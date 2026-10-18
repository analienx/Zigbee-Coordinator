"""Synthetic five-page NVOCMP forensics tests; no personal network bytes."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


SOURCE = (Path(__file__).resolve().parents[1] /
          "firmware/slzb-06p7u/r4/qualification/nv_five_page_forensics.py")
spec = importlib.util.spec_from_file_location("r4_nv_forensics", SOURCE)
nv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nv)


def sample(*, location=0xA6000, payload=b"synthetic-credential-not-a-key",
           tamper=False) -> bytes:
    image = bytearray(b"\xff" * nv.FLASH_SIZE)
    # Simulated stock application's NVSCC26XX_HWAttrs regionBase/regionSize.
    image[0x3000:0x3008] = (0xA6000).to_bytes(4, "little") + (0x8000).to_bytes(4, "little")
    page = memoryview(image)[location:location + nv.PAGE_SIZE]
    page[:4] = bytes((0x7C, 0x02, 0x0F, 0x96))
    system_id, item_id, sub_id = 3, 17, 2
    count = len(payload)
    header = bytearray(((system_id << 2) | (item_id >> 8), item_id & 255,
                        sub_id >> 2, ((sub_id & 3) << 6) | (count >> 6),
                        (count & 63) << 2))
    check = nv.crc8(payload + header)
    header[4] |= check >> 6
    header.extend((((check & 63) << 2) | 2, 0x96))
    page[16:16 + count + 7] = payload + header
    if tamper:
        page[16] ^= 1
    return bytes(image)


class FivePageForensicsTests(unittest.TestCase):
    def test_five_page_rotation_preserves_items_and_checks_crc(self):
        report = nv.compare(sample(), sample(location=0xAA000))
        self.assertEqual(report["logical_inventory"], {
            "unchanged_records": 1, "changed_records": 0,
            "missing_records": 0, "new_records": 0})
        self.assertEqual([s["active_crc_failed"] for s in report["snapshots"]], [0, 0])
        self.assertEqual(report["changed_candidate_sectors"], ["0xa6000", "0xaa000"])
        self.assertEqual(report["earlier_stock_binary_nvs_hwattrs_word_pairs"], [{
            "app_data_offset": "0x03000", "region_base": "0xa6000",
            "region_size": "0x08000", "nvs_pages_if_hwattrs": 4}])
        self.assertEqual(report["snapshots"][0]["active_system_id_counts"], {3: 1})
        self.assertFalse(report["safe_to_initialize_zigbee_nv"])
        self.assertFalse(report["active_stock_partition_proven"])
        self.assertNotIn("synthetic-credential", str(report))
        self.assertNotIn("payload_hash", str(report))

    def test_payload_corruption_fails_crc_and_changes_record(self):
        report = nv.compare(sample(), sample(tamper=True))
        self.assertEqual(report["logical_inventory"]["changed_records"], 1)
        self.assertEqual(report["snapshots"][1]["active_crc_failed"], 1)

    def test_page_header_or_item_bounds_rejected(self):
        bad = bytearray(sample())
        bad[0xA6000 + 3] = 0x00
        with self.assertRaisesRegex(ValueError, "PAGE_HEADER"):
            nv.inspect_capture(bytes(bad))
        bad = bytearray(sample())
        last_item_byte = max(i for i in range(0xA6000, 0xA8000)
                             if bad[i] != 0xFF)
        bad[last_item_byte] = 0x00
        with self.assertRaisesRegex(ValueError, "ITEM_SIGNATURE"):
            nv.inspect_capture(bytes(bad))

    def test_image_size_is_mandatory(self):
        with self.assertRaisesRegex(ValueError, "CAPTURE_SIZE"):
            nv.inspect_capture(b"\xff" * 8192)


if __name__ == "__main__":
    unittest.main()
