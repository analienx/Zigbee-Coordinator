"""P7U R4 direct-ROM native-to-app-only HEX: synthetic negative controls.

Only synthetic byte patterns. Never loads confidential factory flash.
"""
from __future__ import annotations
import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parents[1] / "firmware/slzb-06p7u/r4"
sys.path.insert(0, str(HERE / "release"))
sys.path.insert(0, str(HERE / "b0/tools"))
spec = importlib.util.spec_from_file_location("r4_direct_app", HERE/"release/r4_make_direct_app_only.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
from b0_image_audit import _parse_intel_hex


def synthetic():
    data = {i: 0x42 for i in range(0x3C)}
    vectors = struct.pack("<II", 0x20023C00, 0x101)
    data.update({i: v for i,v in enumerate(vectors)})
    for base in range(0, m.APP_END, m.SECTOR):
        data[base+0x100] = (base // m.SECTOR) & 255
    data.update({addr: 0xFF for addr in range(0xAFFA8, 0xB0000)})
    return data


class IsolatedNativeTests(unittest.TestCase):
    def test_exact_application_only_roundtrip_and_crc(self):
        native = synthetic()
        blob, receipt = m.isolate(native)
        self.assertEqual(receipt["sectors_to_program"], 23)
        self.assertEqual(len(receipt["sector_crc32_ff_padded"]), 23)
        self.assertTrue(receipt["native_ccfg_is_not_in_payload"])
        self.assertFalse(receipt["flash_authorized"])
        self.assertFalse(receipt["erase_nv"])
        self.assertFalse(receipt["erase_ccfg"])
        self.assertFalse(receipt["bank_or_chip_erase"])
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "image.hex"
            path.write_bytes(blob)
            rebuilt, error = _parse_intel_hex(path)
        self.assertIsNone(error)
        self.assertEqual(rebuilt, {a:v for a,v in native.items() if a < 0xA0000})
        self.assertEqual(min(rebuilt), 0)
        self.assertLess(max(rebuilt), 0x2E000)

    def test_invalid_image_address_guards(self):
        original = synthetic()
        wrong = [
            {**original, 0xAC000: 0},
            {**original, 0xA0000: 0},
            {**original, 0xAE001: 0},
            {k:v for k,v in original.items() if k != 0xAFFEC},
            {k:v for k,v in original.items() if k < 0xA0000 and k >= 0x80},
            {**original, 0: 0xFF, 1: 0xFF, 2: 0xFF, 3: 0xFF},
            {**original, 4: 0, 5: 0, 6: 0, 7: 0},
            {**original, 0x2E000: 0},
        ]
        for i, native in enumerate(wrong):
            with self.subTest(case=i), self.assertRaisesRegex(ValueError, "R4_DIRECT_APP_ONLY_BLOCKED"):
                m.isolate(native)

    def test_serialize_refuses_sparse_missing_or_cross_protected(self):
        native = synthetic()
        native = {a:v for a,v in native.items() if a < 0xA0000}
        for candidate in (
            {},
            {a:v for a,v in native.items() if a < 0x80},
            {**native, 0x2E000: 0xAA},
            {a:v for a,v in native.items() if not 0x2000 <= a < 0x4000},
        ):
            with self.assertRaisesRegex(ValueError, "R4_DIRECT_APP_ONLY_BLOCKED"):
                m.serialize_app(candidate)

    def test_hex_record_checksum_boundaries(self):
        self.assertEqual(m.record(1,0,b""),":00000001FF")
        self.assertEqual(m.record(4,0,b"\x00\x02"),":020000040002F8")


if __name__ == "__main__":
    unittest.main()
