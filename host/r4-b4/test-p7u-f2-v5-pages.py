"""Host-only F2 v5 ABI, cross-page binding and adversarial privacy controls."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from p7u_f2_v5_pages import decode_pair,FlightEvidenceRejected

NONCE=bytes([1,2,3,4,5,6,7,8])
def u32(p,off,v):p[off:off+4]=v.to_bytes(4,"little")
def fixture():
    pages=[bytearray(160),bytearray(160)]
    for i,p in enumerate(pages,1):
        p[:4]=b"R4D5";p[4]=5;p[5]=i;p[6]=160
        p[8:16]=NONCE;p[16:24]=bytes(range(1,9))
        u32(p,24,3);u32(p,28,500)
    a,b=pages
    u32(a,32,20);u32(a,36,450)
    u32(a,40,8);u32(a,44,480)
    u32(a,48,8);u32(a,52,490)
    u32(a,56,2);u32(a,60,7);u32(a,64,1)
    u32(a,72,1);u32(a,76,100);u32(a,88,0)
    u32(a,104,3);u32(a,108,2);u32(a,112,10)
    u32(b,32,425);b[36:38]=(0x6400).to_bytes(2,"little");b[38]=3
    u32(b,40,490);b[44:46]=(0x6400).to_bytes(2,"little");b[46]=4
    return a,b

class V5PageTests(unittest.TestCase):
    def test_valid_stable_pair_without_private_ids(self):
        a,b=fixture()
        out=decode_pair(bytes(a),bytes(b),NONCE)
        self.assertEqual(out["counters"]["reserveExhausted"],1)
        self.assertEqual([e["stage"] for e in out["events"]],["MT_ENTER","MT_EXIT"])
        self.assertEqual(out["localization"],"RESERVE_EXHAUSTION_OBSERVED")
        self.assertFalse(out["currentHangProven"])
        self.assertFalse(out["heapFreeBytesKnown"])
        self.assertNotIn("nonce",str(out).lower())
        self.assertNotIn("command",str(out).lower())
    def test_inflight_handler_is_localization_not_hang_proof(self):
        a,b=fixture();u32(a,48,7)
        out=decode_pair(bytes(a),bytes(b),NONCE)
        self.assertEqual(out["localization"],"MT_DISPATCH_IN_FLIGHT_AT_LAST_GOOD_SAMPLE")
        self.assertFalse(out["currentHangProven"])
    def test_cross_page_nonce_seq_tick_and_epoch(self):
        a,b=fixture()
        cases=[
          (lambda x,y:y.__setitem__(9,99)),
          (lambda x,y:u32(y,24,4)),
          (lambda x,y:u32(y,28,501)),
          (lambda x,y:y.__setitem__(17,0)),
          (lambda x,y:y.__setitem__(5,255)),
          (lambda x,y:x.__setitem__(6,248)),
          (lambda x,y:x.__setitem__(150,1)),
          (lambda x,y:u32(x,108,17)),
          (lambda x,y:u32(x,72,4)),
          (lambda x,y:u32(x,112,0)),
          (lambda x,y:y.__setitem__(38,0)),
          (lambda x,y:y.__setitem__(46,255)),
          (lambda x,y:y.__setitem__(48,1)),
          (lambda x,y:u32(x,56,3)),
        ]
        for mut in cases:
            with self.subTest(mut=mut):
                x,y=bytearray(a),bytearray(b)
                mut(x,y)
                with self.assertRaises(FlightEvidenceRejected):
                    decode_pair(bytes(x),bytes(y),NONCE)
    def test_zero_ring_and_invalid_types(self):
        a,b=fixture();u32(a,56,0);u32(a,108,0);b[32:]=bytes(128)
        self.assertEqual(decode_pair(bytes(a),bytes(b),NONCE)["events"],[])
        with self.assertRaises(FlightEvidenceRejected):
            decode_pair(a,bytes(b),NONCE)
        with self.assertRaises(FlightEvidenceRejected):
            decode_pair(bytes(a),bytes(b),b"123")

if __name__=="__main__":
    unittest.main()
