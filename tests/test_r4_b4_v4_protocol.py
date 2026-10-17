"""No actual hardware is queried by these v4 ABI/correlation tests."""
import secrets
import struct
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "firmware" / "slzb-06p7u" / "r4" / "b4"))
from b4_protocol import frame
from b4_v4_protocol import (InvalidV4, HEADER, COUNTERS, TAIL, V4_RESPONSE_BYTES,
                            decode_frame, decode_payload, request_frame, continuous_epoch)

NONCE = bytes.fromhex("84c095eacf3d1897")

def synthetic_response(nonce=NONCE, *, boot=0x1234, status=1, caps=3, valid=0x3F,
                       seq=5, fp=0x12344556, values=None):
    arr = [0] * 25 if values is None else values
    body = (HEADER.pack(b"R4D4", 4, 0, 160, caps, valid, boot, 0, seq)
            + COUNTERS.pack(*arr)
            + TAIL.pack(nonce, 6, fp, 0, status, 0))
    assert len(body) == V4_RESPONSE_BYTES
    return frame(0x61, 0xF1, body)

class StrictV4(unittest.TestCase):
    def test_nonce_request_has_new_opcode_and_8_bytes(self):
        self.assertEqual(request_frame(NONCE), frame(0x21, 0xF1, NONCE))
        for bad in (b"", bytes(8), b"x", bytearray(NONCE), "string"):
            with self.subTest(bad=bad), self.assertRaises(InvalidV4):
                request_frame(bad)

    def test_epoch_and_nonce_correlation(self):
        r = decode_frame(synthetic_response(), expected_nonce=NONCE)
        self.assertEqual(r.abi, 4)
        self.assertEqual(r.radio_epoch, 0x1234)
        self.assertEqual(r.sequence, 5)
        self.assertTrue(r.boot_epoch_qualified)
        self.assertEqual(r.reset_reason, 6)
        self.assertEqual(r.source_fingerprint, 0x12344556)
        self.assertIsNone(r.counters[7])
        self.assertTrue(continuous_epoch(r, decode_frame(synthetic_response(seq=6), expected_nonce=NONCE),
                                         source_qualified=True))
        self.assertFalse(continuous_epoch(r, decode_frame(synthetic_response(seq=6), expected_nonce=NONCE)))
        self.assertFalse(continuous_epoch(r, decode_frame(synthetic_response(seq=1), expected_nonce=NONCE),
                                          source_qualified=True))

    def test_unavailable_entropy_stays_unknown(self):
        sample = decode_frame(synthetic_response(boot=0, status=0, caps=2), expected_nonce=NONCE)
        self.assertIsNone(sample.radio_epoch)
        self.assertFalse(sample.boot_epoch_qualified)
        self.assertFalse(continuous_epoch(sample, sample, source_qualified=True))

    def test_nonce_mismatch_fail_closed_even_if_valid_fcs(self):
        for bad in (bytes.fromhex("84c095eacf3d1898"), bytes(8)):
            with self.assertRaisesRegex(InvalidV4, "nonce"):
                decode_frame(synthetic_response(nonce=bad), expected_nonce=NONCE)

    def test_source_scope_validity_and_status_negative(self):
        valid = synthetic_response()
        def mutate(start, content):
            t = bytearray(valid)
            t[4 + start:4 + start + len(content)] = content
            return frame(0x61, 0xF1, bytes(t[4:-1]))
        mutants = [
            mutate(0, b"R4D3"), mutate(4, b"\x03"),
            mutate(6, b"\x9f\x00"), mutate(8, b"\x07"),
            mutate(12, b"\xff"), mutate(28, bytes(4)),
            mutate(32 + 6 * 4, b"\x01"), mutate(140, bytes(4)),
            mutate(144, bytes(8)), mutate(152, b"\x01"),
            mutate(154, b"\x02"), mutate(156, b"\x01"),
            mutate(16, bytes(8)),
        ]
        # Reset reason is permitted to be 0; it is metadata, not proof.
        mutants.remove(mutate(140, bytes(4)))
        for bad in mutants:
            with self.subTest(bad=bad[:15]), self.assertRaises(InvalidV4):
                decode_frame(bad, expected_nonce=NONCE)

    def test_legacy_frames_never_decode_as_v4(self):
        with self.assertRaises(InvalidV4):
            decode_frame(frame(0x61, 0xF0, bytes(132)), expected_nonce=NONCE)
        bad = bytearray(synthetic_response())
        bad[-1] ^= 0x20
        with self.assertRaisesRegex(InvalidV4, "FCS"):
            decode_frame(bytes(bad), expected_nonce=NONCE)
        with self.assertRaises(InvalidV4):
            decode_frame(synthetic_response() + b"x", expected_nonce=NONCE)

if __name__ == "__main__":
    unittest.main()
