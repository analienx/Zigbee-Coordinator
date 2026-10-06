"""Regression guard for the R5 Trust Center/NVOCMP capacity failure.

R5 configured 400 Trust Center entries while preserving the CC2674P10
5 x 2 KiB NVOCMP region. TI APSME_TCLinkKeyNVEntry_t is 20 bytes in
SDK 8.32 and NVOCMP uses a 7-byte item header, so pre-initializing
400 entries needs at least 10,800 bytes before any other coordinator NV.
That configuration can never fit in 10,240 bytes.

R6 intentionally keeps the vendor-compatible 5-page NVS geometry and uses
a bounded diagnostic Trust Center table instead of moving the NVS base.
"""

import json
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
MANIFEST = HERE / "manifest.json"
APPLY = HERE / "apply_kctrl.py"

NVOCMP_PAGES = 5
FLASH_PAGE_SIZE = 0x800
NV_REGION_BYTES = NVOCMP_PAGES * FLASH_PAGE_SIZE
NVOCMP_ITEM_HEADER_BYTES = 7
TCLK_PAYLOAD_BYTES = 20
TCLK_SLOT_BYTES_MIN = NVOCMP_ITEM_HEADER_BYTES + TCLK_PAYLOAD_BYTES


class NvCapacityContractTests(unittest.TestCase):
    def test_r5_400_slot_configuration_is_mathematically_impossible(self):
        self.assertGreater(400 * TCLK_SLOT_BYTES_MIN, NV_REGION_BYTES)

    def test_r6_tclk_capacity_leaves_majority_of_nv_for_other_items(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        mutation = next(
            item for item in manifest["mutations"]
            if item["id"] == "capacity.tc_devices"
        )
        configured = int(mutation["configured"])
        self.assertEqual(configured, 128)

        minimum_tclk_bytes = configured * TCLK_SLOT_BYTES_MIN
        self.assertLess(minimum_tclk_bytes, NV_REGION_BYTES // 2)
        self.assertEqual(minimum_tclk_bytes, 3456)

    def test_r6_does_not_move_or_expand_p10_nvs_region(self):
        source = APPLY.read_text(encoding="utf-8")
        self.assertNotIn("NVOCMP_NVPAGES=16", source)
        self.assertNotIn("0xF8000", source)
        self.assertNotIn("0x8000", source)
        self.assertIn('"--define=NVOCMP_NVPAGES=2"', source)
        self.assertIn('"--define=NVOCMP_NVPAGES=5"', source)

    def test_manifest_explains_nv_capacity_reason(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        mutation = next(
            item for item in manifest["mutations"]
            if item["id"] == "capacity.tc_devices"
        )
        rationale = mutation["rationale"].lower()
        self.assertIn("10 kib", rationale)
        self.assertIn("128", rationale)
        self.assertIn("vendor-compatible", rationale)


if __name__ == "__main__":
    unittest.main()
