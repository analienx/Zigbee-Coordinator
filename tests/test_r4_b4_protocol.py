"""B4 strict offline MT oracle tests. No serial, coordinator or Z2M access."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "firmware" / "slzb-06p7u" / "r4" / "b4"))
from b4_protocol import (
    BoundedMtStream, DIAG_ID, SOF, SRSP_SYS, SREQ_SYS, decode_frame,
    fcs, frame,
)

def legacy(values=None, flags=0):
    return struct.pack("<BB25I", 2, flags, *(values if values is not None else [0] * 25))

def proposed(values=None, *, flags=0, caps=0, valid=0, boot_id=0,
             uptime=0, seq=1, magic=b"R4D3", major=3, length=132):
    return struct.pack("<4sBBHIIQII25I", magic, major, flags, length,
                       caps, valid, boot_id, uptime, seq,
                       *(values if values is not None else [0] * 25))

class MTFormat(unittest.TestCase):
    def test_d03_legacy_v2_exact_102_and_max_uint_valid(self):
        values = [0xffffffff] * 25
        wire = frame(SRSP_SYS, DIAG_ID, legacy(values))
        parsed = decode_frame(wire)
        self.assertEqual(len(wire), 107)
        self.assertEqual(parsed["abi"], 2)
        self.assertEqual(len(parsed["counters"]), 25)
        self.assertEqual(set(parsed["counters"].values()), {0xffffffff})
        self.assertFalse(parsed["radio_boot_id_verified"])

    def test_d04_v3_explicit_validity_not_zero_sentinels(self):
        vals = [0xffffffff] * 25
        parsed = decode_frame(frame(SRSP_SYS, DIAG_ID, proposed(vals, valid=1)))
        self.assertEqual(parsed["abi"], 3)
        self.assertEqual(parsed["counters"]["srsp_depth"], 0xffffffff)
        self.assertIsNone(parsed["counters"]["srsp_high_water"])
        self.assertFalse(parsed["radio_boot_id_verified"])

    def test_d05_wrong_size_version_flags_caps_and_magic(self):
        good = frame(SRSP_SYS, DIAG_ID, proposed())
        corrupt = [
            good[:-1], good + b"x", b"", b"\xfe\x00\x61\xf0\x91",
            frame(SRSP_SYS, DIAG_ID, proposed(major=4)),
            frame(SRSP_SYS, DIAG_ID, proposed(length=131)),
            frame(SRSP_SYS, DIAG_ID, proposed(magic=b"FAKE")),
            frame(SRSP_SYS, DIAG_ID, proposed(flags=0x80)),
            frame(SRSP_SYS, DIAG_ID, proposed(caps=2)),
            frame(SRSP_SYS, DIAG_ID, proposed(valid=1 << 25)),
            frame(SRSP_SYS, DIAG_ID, proposed(caps=1, boot_id=0)),
            frame(SRSP_SYS, DIAG_ID, proposed(caps=0, boot_id=99)),
            frame(SRSP_SYS, DIAG_ID, legacy(flags=8)),
            frame(SRSP_SYS, DIAG_ID, b"x" * 133),
        ]
        for bad in corrupt:
            with self.subTest(data=bad[:8]), self.assertRaises(ValueError):
                decode_frame(bad)

    def test_d06_bad_fcs_and_bad_cmd(self):
        raw = bytearray(frame(SRSP_SYS, DIAG_ID, legacy()))
        raw[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "FCS"):
            decode_frame(raw)
        for cmd0, cmd1 in ((SREQ_SYS, DIAG_ID), (SRSP_SYS, 0x01), (0x45, DIAG_ID)):
            with self.assertRaises(ValueError):
                decode_frame(frame(cmd0, cmd1, legacy()))
        self.assertEqual(fcs(frame(SRSP_SYS, DIAG_ID, legacy())[1:]), 0)

    def test_bad_input_types_and_bounds(self):
        for bad in (None, {}, [1], "text"):
            with self.assertRaises(ValueError):
                decode_frame(bad)
        for bad in (-1, 256, True, 1.1):
            with self.assertRaises(ValueError):
                frame(bad, DIAG_ID)
        with self.assertRaises(ValueError):
            frame(SRSP_SYS, DIAG_ID, b"z" * 256)

    def test_d06_incremental_one_byte_chunks_and_resync(self):
        good = frame(SRSP_SYS, DIAG_ID, legacy([42] * 25))
        parser = BoundedMtStream()
        found = []
        for b in b"\x00\xff" + good:
            found.extend(parser.feed(bytes([b])))
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["counters"]["srsp_depth"], 42)
        self.assertEqual(parser.buffered_bytes, 0)

    def test_d06_corrupt_frame_then_good_resynchronizes(self):
        raw = bytearray(frame(SRSP_SYS, DIAG_ID, legacy()))
        raw[-1] ^= 1
        parser = BoundedMtStream()
        found = parser.feed(bytes(raw) + frame(SRSP_SYS, DIAG_ID, proposed()))
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["abi"], 3)
        self.assertGreater(parser.rejected, 0)

    def test_d06_len_smuggling_does_not_trust_embedded_payload(self):
        parser = BoundedMtStream()
        found = parser.feed(bytes((SOF, 0xff, SRSP_SYS, DIAG_ID)) +
                            frame(SRSP_SYS, DIAG_ID, legacy()))
        self.assertEqual(len(found), 1)
        self.assertEqual(parser.buffered_bytes, 0)

    def test_d17_parser_bounded_on_hostile_stream(self):
        parser = BoundedMtStream()
        with self.assertRaises(ValueError):
            parser.feed(b"x" * 4097)
        self.assertEqual(parser.buffered_bytes, 0)
        for _ in range(100):
            parser.feed(bytes((SOF, 255, SRSP_SYS, DIAG_ID)) * 1024)
            self.assertLessEqual(parser.buffered_bytes, 260)

    def test_d11_epoch_identity_not_qualified_by_wire(self):
        p = decode_frame(frame(SRSP_SYS, DIAG_ID,
                               proposed(caps=1, boot_id=33, valid=1)))
        self.assertTrue(p["radio_boot_id_verified"])  # on-wire claim, NOT native qualification
        self.assertEqual(p["radio_boot_id"], 33)

if __name__ == "__main__":
    unittest.main()
