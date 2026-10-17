"""B0 negative-only sector policy; source-analysis is NOT flashing authority."""
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1] /
                    "firmware/slzb-06p7u/r4/b0/tools"))
from b0_sector_dryrun import classify_payload, CCFG_BEGIN

class SectorDeny(unittest.TestCase):
    def valid(self):
        return {0x000100:0xC3,0x020100:0x11,CCFG_BEGIN:0x5A}

    def test_ccfg_final_sector_held_despite_hex_records(self):
        r=classify_payload(self.valid())
        self.assertEqual(r["status"],"NO_SAFE_FULL_IMAGE_SECTOR_PLAN")
        self.assertFalse(r["flash_authorized"])
        self.assertIsNone(r["programmer_commands"])
        self.assertIn("0xae000",r["blocked_record_sector_starts"])
        self.assertIn("0xae000",r["all_excluded_sector_starts"])
        self.assertIn("0x0",r["app_candidate_sector_starts"])

    def test_all_candidate_nv_union_addresses_rejected(self):
        for addr in (0xA4000,0xAA000,0xADFFF):
            with self.subTest(addr=addr),self.assertRaisesRegex(ValueError,"NV5_NV2"):
                classify_payload({**self.valid(),addr:0})

    def test_unverified_ccfg_sector_data_never_allowlisted(self):
        r=classify_payload({**self.valid(),0xAE010:0xAB})
        self.assertIn("0xae000",r["blocked_record_sector_starts"])
        self.assertNotIn("0xae000",r["app_candidate_sector_starts"])

    def test_missing_ccfg_or_application_never_forms_plan(self):
        for d in ({0x100:1},{CCFG_BEGIN:0x5A},{}):
            with self.subTest(records=d),self.assertRaises(ValueError):
                classify_payload(d)

    def test_invalid_bytes_address_and_type(self):
        for addr,value in ((0xB0000,1),(-1,1),(0,256),("100",1)):
            with self.subTest(addr=addr,value=value),self.assertRaises(ValueError):
                classify_payload({**self.valid(),addr:value})

    def test_no_positive_execution_metadata_can_appear(self):
        receipt=classify_payload(self.valid())
        self.assertFalse(receipt["production_release_authorized"])
        self.assertFalse(receipt["hardware_erase_geometry_verified"])
        self.assertTrue(receipt["future_required"])
        self.assertFalse(receipt["parent_flash_authorized"] if
                         "parent_flash_authorized" in receipt else False)

if __name__=="__main__": unittest.main()
