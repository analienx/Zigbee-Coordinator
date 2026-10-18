"""Synthetic structural inventory tests; no real NV or credential fixtures."""
import importlib.util
from pathlib import Path
import unittest

from tests.test_r4_current_app_package import current_fixture
import r4_current_board_profile as profiles

PATH = (Path(__file__).resolve().parents[1] /
        "firmware/slzb-06p7u/r4/qualification/nv_sector_inventory.py")
SPEC = importlib.util.spec_from_file_location("nv_sector_inventory", PATH)
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)


def fixture():
    data = bytearray(current_fixture()[0])
    for address, state, version in ((0xA6000, 0x78, 12), (0xA8000, 0x78, 12),
                                    (0xAA000, 0x7C, 15), (0xAC000, 0xFE, 15)):
        data[address:address + 4] = bytes((state, 1, version, 0x96))
    capture = bytes(data)
    identity = {"model": "SLZB-06P7U", "hardware_revision": "1.73", "soc": "CC2652P7",
                "flash_bytes": len(capture), "board_binding_id": "synthetic-inventory-only"}
    profile = profiles.analyze_capture_pair(capture, capture,
        expected_pass1_sha256=profiles.sha256(capture),
        expected_pass2_sha256=profiles.sha256(capture),
        board_identity=identity,
        expected_board_identity_sha256=profiles.board_identity_digest(identity))
    return capture, profile


class InventoryTests(unittest.TestCase):
    def test_multiple_v3_headers_are_not_separate_formats_or_active_nv_proof(self):
        data, profile = fixture()
        report = inventory.inspect(profile, data, expected_profile_sha256=profile["profile_sha256"])
        self.assertEqual(len(report["sectors"]), 7)
        candidates = [s for s in report["sectors"] if s["possible_ti_nvocmp_v3_header"]]
        self.assertEqual([s["start"] for s in candidates],
                         ["0xa6000", "0xa8000", "0xaa000", "0xac000"])
        self.assertEqual([s["candidate_nvocmp_version"] for s in candidates], [3] * 4)
        self.assertEqual([s["candidate_all_active_bits"] for s in candidates], [0, 0, 3, 3])
        self.assertEqual(report["candidate_nv_region_pairs"], "NOT_INFERRED_FROM_PAGE_HEADERS")
        self.assertFalse(report["current_store_identified"])
        self.assertFalse(report["normal_znp_startup_authorized"])
        self.assertFalse(report["raw_nv_or_key_bytes_exported"])
        self.assertFalse(report["flash_authorized"])
        self.assertNotIn("synthetic-inventory-only", str(report))

    def test_bad_capture_pin_or_tampered_profile_denied(self):
        data, profile = fixture()
        with self.assertRaisesRegex(ValueError, "PROFILE_CAPTURE_HASH_MISMATCH"):
            inventory.inspect(profile, data[:-1] + b"\0",
                              expected_profile_sha256=profile["profile_sha256"])
        with self.assertRaisesRegex(ValueError, "EXTERNAL_PROFILE_HASH_MISMATCH"):
            inventory.inspect(profile, data, expected_profile_sha256="0" * 64)


if __name__ == "__main__":
    unittest.main()
