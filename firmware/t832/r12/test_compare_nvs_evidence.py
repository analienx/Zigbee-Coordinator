"""Fail-closed static NV contract comparator tests; no radio operations."""
import copy
import unittest
from pathlib import Path
from unittest.mock import patch
import compare_nvs_evidence as target

def fixture(rev: int) -> dict:
    return {
      "nv_contract":{"nvs_base":target.BASE,"nvs_bytes":target.BYTES,
                     "nvs_pages":15,"sector_bytes":2048},
      "ccfg_fields":{"BL_CONFIG":"0xc5fe0fc5","ERASE_CONF":"0xffffffff"},
      "ccfg_other":{"bootloader_enabled":True},
      "ccfg_reset_vector":"0x0002b195" if rev==8320062 else "0x0002b311",
      "image_revision":rev,
      "image_sha256":str(rev).zfill(64),"image_bytes":207132 if rev==8320062 else 207508,
      "sdk_commit":"6499c3f53fc5fb5806213be695450a7b43fbaf3d",
      "vendor_nvs_base":target.BASE,"vendor_nvs_bytes":target.BYTES,
    }

class ContractTests(unittest.TestCase):
    def run_pair(self,a,b):
        with patch.object(target,"check_bundle",side_effect=[a,b]):
            return target.audit(Path("old"),Path("new"))
    def test_identical_static_layout_does_not_claim_physical_preservation(self):
        report=self.run_pair(fixture(8320062),fixture(8320063))
        self.assertTrue(report["nv_contract_identical"])
        self.assertFalse(report["physical_erasure_determined"])
        self.assertFalse(report["nvocmp_init_erasure_determined"])
        self.assertEqual(report["status"],"STATIC_NVS_LAYOUT_EQUAL_PHYSICAL_NVS_UNPROVEN")
    def test_page_base_drift_denied(self):
        a,b=fixture(8320062),fixture(8320063)
        b["nv_contract"]["nvs_base"]-=2048
        with self.assertRaisesRegex(ValueError,"contract drift"):self.run_pair(a,b)
    def test_security_ccfg_drift_denied(self):
        a,b=fixture(8320062),fixture(8320063)
        b["ccfg_fields"]["ERASE_CONF"]="0x0"
        with self.assertRaisesRegex(ValueError,"CCFG fields"):self.run_pair(a,b)
    def test_other_ccfg_changes_denied(self):
        a,b=fixture(8320062),fixture(8320063)
        b["ccfg_other"]["bootloader_enabled"]=False
        with self.assertRaisesRegex(ValueError,"CCFG non-reset"):self.run_pair(a,b)
    def test_wrong_revision_denied(self):
        a,b=fixture(8320062),fixture(8320063)
        b["image_revision"]=8320064
        with self.assertRaisesRegex(ValueError,"revisions"):self.run_pair(a,b)
    def test_reference_geometry_drift_denied(self):
        a,b=fixture(8320062),fixture(8320063)
        b["vendor_nvs_bytes"]-=2048
        with self.assertRaisesRegex(ValueError,"reference geometry"):self.run_pair(a,b)

if __name__=="__main__":
    unittest.main()
