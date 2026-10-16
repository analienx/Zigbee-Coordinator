import tempfile
import unittest
from pathlib import Path

from tools.b2_compose import compose, apply, ComposeError, PROFILES

class B2ComposeTests(unittest.TestCase):
    def test_p0_byte_identical(self):
        source="-DFREQ_2_4G\n"
        result, overrides=compose(source,"P0")
        self.assertEqual(source,result)
        self.assertFalse(overrides)
    def test_p1_only_owned_routing_macros(self):
        result,defines=compose("-DNPI\n","P1")
        self.assertEqual(defines,{"MAX_RTG_SRC_ENTRIES":192,
                                  "MAX_NEIGHBOR_ENTRIES":64,
                                  "MAX_RTG_ENTRIES":128})
        for k,v in defines.items():self.assertIn(f"-D{k}={v}",result)
        for not_allowed in ("NVOCMP_NVPAGES","NWK_MAX_DEVICE_LIST",
                            "CONCENTRATOR_ENABLE","APSC_MAX_FRAME_RETRIES"):
            self.assertNotIn(not_allowed,result)
    def test_reject_duplicate_macro(self):
        with self.assertRaisesRegex(ComposeError,"existing project definition"):
            compose("-DMAX_RTG_SRC_ENTRIES=12","P1")
    def test_reject_duplicate_2nd_pass(self):
        result,_=compose("-DNPI\n","P1")
        with self.assertRaisesRegex(ComposeError,"already applied"):
            compose(result,"P1")
    def test_reject_unapproved_profile(self):
        with self.assertRaisesRegex(ComposeError,"not approved"):
            compose("-DNPI\n","P2")
    def test_reject_bad_path(self):
        with tempfile.TemporaryDirectory() as d:
            opts=Path(d)/"production.opts"
            opts.write_text("-DNPI\n")
            with self.assertRaisesRegex(ComposeError,"only imported"):
                apply(opts,"P1",Path(d)/"receipt.json")
    def test_receipt_reproducible_and_p0_unchanged(self):
        with tempfile.TemporaryDirectory() as d:
            opts=Path(d)/"Stack"/"Config"/"znp_cnf.opts"
            opts.parent.mkdir(parents=True)
            opts.write_text("-DNPI\n")
            original=opts.read_bytes()
            result=apply(opts,"P0",Path(d)/"p0.json")
            self.assertEqual(result["status"],"B0_UNCHANGED")
            self.assertEqual(opts.read_bytes(),original)
            result=apply(opts,"P1",Path(d)/"p1.json")
            self.assertEqual(result["status"],"SOURCE_OVERLAY_APPLIED")
            self.assertNotEqual(opts.read_bytes(),original)

if __name__=="__main__":unittest.main()
