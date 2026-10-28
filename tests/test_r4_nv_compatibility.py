"""No device access. Real-reader tests use explicitly provided pinned TI sources."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import unittest

from tests.test_r4_current_board_profile import capture, profile

MODULE = (Path(__file__).resolve().parents[1] /
          "firmware/slzb-06p7u/r4/qualification/nv_compatibility.py")
spec = importlib.util.spec_from_file_location("nv_clone", MODULE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def formatted_capture(*, corrupt=False, duplicate=False):
    data = bytearray(capture())
    data[0xA0000:0xAC000] = b"\xff" * 0xC000
    region = memoryview(data)[0xA0000:0xA4000]
    for page, state in ((0, 0x7C), (8192, 0xFE)):
        region[page:page + 4] = bytes((state, page // 8192 + 1, 0x0F, 0x96))
        for offset in (7, 11, 15):
            region[page + offset] = 0x96
    cursor = 16
    for item_id in ((2, 2) if duplicate else (2,)):
        payload = b"publicDummyValue"
        length = len(payload)
        header = bytearray((4 | item_id >> 8, item_id & 255, 0,
                            length >> 6, (length & 63) << 2, 0, 0x96))
        crc = 0
        for byte in payload + bytes(header[:5]):
            crc ^= byte
            for _ in range(8):
                crc <<= 1
                if crc > 255:
                    crc ^= 0x197
        header[4] |= crc >> 6
        header[5] = ((crc & 63) << 2) | 2
        region[cursor:cursor + length] = payload
        region[cursor + length:cursor + length + 7] = header
        cursor += length + 7
    if corrupt:
        region[16] ^= 1
    return bytes(data)


class NvCloneBindingTests(unittest.TestCase):
    def test_geometry_never_infers_nv5_nv2_or_uses_boot_sector(self):
        self.assertEqual(m.geometry(0xA0000, 8192, 2)["region_bytes"], 16384)
        for args in ((0xA4000, 8192, 5), (0xAA000, 8192, 2),
                     (0xA0000, 4096, 2), (0xA0001, 8192, 2),
                     (0x80000, 8192, 2), (True, 8192, 2)):
            with self.subTest(args=args), self.assertRaisesRegex(ValueError, "GEOMETRY"):
                m.geometry(*args)

    def test_source_hashes_are_external_and_crc_is_actual_donor(self):
        with self.assertRaisesRegex(ValueError, "NV_SOURCE_PIN_MISMATCH"):
            m.generate_probe(b"changed source", b"crc", expected_nv_source_sha256="0" * 64,
                expected_crc_source_sha256=m.sha256(b"crc"), nvs_base=0xA0000)
        with self.assertRaisesRegex(ValueError, "CRC_NOT_PINNED_TI_DONOR"):
            m.generate_probe(b"source", b"fake crc", expected_nv_source_sha256=m.sha256(b"source"),
                expected_crc_source_sha256=m.sha256(b"fake crc"), nvs_base=0xA0000)

    def test_current_capture_cannot_be_replaced_for_same_profile(self):
        first = formatted_capture()
        board = profile(first)
        with self.assertRaisesRegex(ValueError, "PROFILE_CAPTURE_HASH"):
            m.run_clone(board, formatted_capture(corrupt=True), b"unused", b"unused",
                expected_profile_sha256=board["profile_sha256"],
                expected_nv_source_sha256="0" * 64, expected_crc_source_sha256="0" * 64,
                expected_native_image_sha256="1" * 64, nvs_base=0xA0000)

    def test_native_artifact_pin_required_before_parser(self):
        data = formatted_capture()
        board = profile(data)
        with self.assertRaisesRegex(ValueError, "NATIVE_IMAGE_PIN_REQUIRED"):
            m.run_clone(board, data, b"unused", b"unused",
                expected_profile_sha256=board["profile_sha256"],
                expected_nv_source_sha256="0" * 64, expected_crc_source_sha256="0" * 64,
                expected_native_image_sha256="", nvs_base=0xA0000)


@unittest.skipUnless(os.environ.get("R4_NVOCMP_SOURCE") and os.environ.get("R4_CRC_SOURCE")
                     and shutil.which("gcc"),
                     "real-reader tests require pinned external TI source paths and host gcc")
class RealPinnedReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.nv = Path(os.environ["R4_NVOCMP_SOURCE"]).read_bytes()
        cls.crc = Path(os.environ["R4_CRC_SOURCE"]).read_bytes()
        # These tests run the pristine exact donor, not a regex or a substitute parser.
        if m.sha256(cls.nv) != "d37c7f314696c8669413cfb098900e41ffd2a4d48704481e5dd8c9a8c012d6d6":
            raise ValueError("real-reader test NVOCMP source is not the pinned TI 8.33 donor")

    def run_probe(self, data):
        board = profile(data)
        return m.run_clone(board, data, self.nv, self.crc,
            expected_profile_sha256=board["profile_sha256"],
            expected_nv_source_sha256=m.sha256(self.nv),
            expected_crc_source_sha256=m.sha256(self.crc),
            expected_native_image_sha256="1" * 64, nvs_base=0xA0000)

    def test_real_ti_init_and_active_item_crc_reader_keeps_semantics_blocked(self):
        data = formatted_capture()
        result = self.run_probe(data)
        self.assertEqual(result["gate"], "CLONE_STRUCTURE_ACCEPTED_SEMANTICS_UNPROVEN")
        self.assertEqual(result["result"]["active_items_read"], 1)
        self.assertEqual(result["result"]["write_attempts"], 0)
        self.assertEqual(result["result"]["erase_attempts"], 0)
        self.assertFalse(result["normal_startup_authorized"])
        self.assertFalse(result["network_compatibility_verified"])
        self.assertFalse(result["current_store_location_proven"])
        self.assertNotIn("publicDummyValue", str(result))
        self.assertEqual(data, formatted_capture())

    def test_corrupt_or_blank_clone_never_initializes_or_repairs(self):
        for data in (formatted_capture(corrupt=True), capture()):
            with self.subTest(corrupt=data == formatted_capture(corrupt=True)):
                result = self.run_probe(data)
                self.assertEqual(result["gate"], "CURRENT_CAPTURE_CANDIDATE_NV_PARSER_BLOCKED")
                self.assertEqual(result["result"]["write_attempts"], 0)
                self.assertEqual(result["result"]["erase_attempts"], 0)
                self.assertFalse(result["normal_startup_authorized"])

    def test_real_parser_repair_request_cannot_reach_any_mutating_backend(self):
        result = self.run_probe(formatted_capture(duplicate=True))
        self.assertEqual(result["gate"], "CURRENT_CAPTURE_CANDIDATE_NV_PARSER_BLOCKED")
        self.assertGreater(result["result"]["write_attempts"], 0)
        self.assertFalse(result["capture_modified"])
        self.assertFalse(result["migration_performed"])


if __name__ == "__main__":
    unittest.main()
