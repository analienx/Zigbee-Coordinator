"""R4 evidence persistence and irreversible transport ambiguity regressions."""
import socket
import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"firmware/slzb-06p7u/r4/release"))
from p7u_r4_startup_transport import FramedZnp, observe_after_srsp, Q2, Q3
from p7u_r4_startup_observer import EvidenceError
sys.path.insert(0,str(ROOT/'tests'))
from test_p7u_r4_startup_observer import evidence,SOURCE,mkframe

class SequenceClock:
    now=0.
    def __call__(self):
        return self.now

class FakeResponses:
    def __init__(self, responses):
        self.responses=list(responses)
        self.clock=SequenceClock()
        self.history=[]
        self.source=None
    def request(self,sub,cmd,payload=b"",*,deadline):
        self.history.append({"operation":payload.hex(),"received_bytes":133,
                             "result":"COMPLETE"})
        reply=self.responses.pop(0)
        if isinstance(reply,Exception):
            raise reply
        return reply

class Socket:
    def __init__(self, data):
        self.data=data
        self.timeout=0.
        self.sent=[]
    def settimeout(self,t):
        self.timeout=t
    def sendall(self,data):
        self.sent.append(data)
    def recv(self,n):
        if self.data is None:
            raise socket.timeout()
        if not self.data:
            return b""
        p=self.data[:min(n,2)]
        self.data=self.data[len(p):]
        return p

class CompletionObserverTests(unittest.TestCase):
    def test_b1e1_ready_survives_b1p1_timeout(self):
        mock=FakeResponses([evidence(),TimeoutError("no B1P1")])
        saved=[]
        result=observe_after_srsp(mock,SOURCE,0,save=lambda name,raw,meta:
                                  saved.append((name,raw,meta)))
        self.assertEqual(result["failure_category"],
                         "READY_OBSERVED_VERIFICATION_INCOMPLETE")
        self.assertTrue(result["ready_observed"])
        self.assertEqual(result["snapshots"],1)
        self.assertEqual(bytes.fromhex(result["frames"]["B1E1"]),evidence())
        self.assertEqual(result["frame_counts"]["B1E1"],1)
        self.assertEqual(len(saved),1)

    def test_running_snapshot_survives_next_poll_timeout(self):
        running=bytearray(evidence());running[6]=3
        mock=FakeResponses([bytes(running),TimeoutError("no next E1")])
        result=observe_after_srsp(mock,SOURCE,0)
        self.assertEqual(result["snapshots"],1)
        self.assertEqual(result["failure_category"],"DEADLINE_NOT_READY")
        self.assertIn("B1E1",result["frames"])
        self.assertNotIn("B1P1",result["frames"])

    def test_firmware_failed_is_not_observer_timeout(self):
        failed=bytearray(evidence());failed[6]=5;failed[40]=0x6c
        result=observe_after_srsp(FakeResponses([bytes(failed)]),SOURCE,0)
        self.assertEqual(result["failure_category"],"FIRMWARE_FAILED")

    def test_fragmented_133byte_frame_and_matching_magic(self):
        sock=Socket(mkframe(evidence()))
        z=FramedZnp(sock,source=SOURCE)
        raw=z.request(1,241,Q3,deadline=z.clock()+5)
        self.assertEqual(raw,evidence())
        self.assertEqual(z.history[-1]["response_length"],128)
        self.assertEqual(z.history[-1]["received_bytes"],133)
        self.assertFalse(z.unusable)

    def test_invalid_matching_evidence_poisoned_forever(self):
        corrupt=bytearray(evidence());corrupt[:4]=b"B9E1"
        z=FramedZnp(Socket(mkframe(bytes(corrupt))),source=SOURCE)
        with self.assertRaisesRegex(EvidenceError,"SHAPE"):
            z.request(1,241,Q3,deadline=z.clock()+5)
        self.assertTrue(z.unusable)
        with self.assertRaisesRegex(EvidenceError,"PERMANENTLY_UNUSABLE"):
            z.request(1,241,Q3,deadline=z.clock()+5)

    def test_timeout_poisoned_even_without_receiving_bytes(self):
        z=FramedZnp(Socket(None),source=SOURCE)
        with self.assertRaises(TimeoutError):
            z.request(1,241,Q2,deadline=z.clock()+.03)
        self.assertTrue(z.unusable)
        self.assertTrue(z.history[-1]["transmission_completed"])
        self.assertEqual(z.history[-1]["received_bytes"],0)
        with self.assertRaisesRegex(EvidenceError,"PERMANENTLY_UNUSABLE"):
            z.request(1,241,Q2,deadline=z.clock()+.03)

if __name__=="__main__":
    unittest.main()
