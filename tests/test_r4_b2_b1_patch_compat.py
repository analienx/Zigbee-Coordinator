import unittest
from tools.b2_b1_patch_compat import check_paths,CompatibilityError,B1_REQUIRED
class B1B2PatchCompatibility(unittest.TestCase):
    def test_known_b1_b2_source_paths_disjoint(self):
        evidence=check_paths(B1_REQUIRED | {".github/workflows/test-r4-b1-direct-native.yml"},
                             {"tools/b2_compose.py",".github/workflows/test-r4-b0-native.yml"})
        self.assertEqual(evidence["overlap_paths"],[])
        self.assertFalse(evidence["B1_B2_INTEGRATED_READY"])
        self.assertEqual(evidence["RF_HOLD_NV_SECURITY_GATE"],"NOT_TESTED")
    def test_actual_path_collision_blocks(self):
        with self.assertRaisesRegex(CompatibilityError,"overlapping"):
            check_paths(B1_REQUIRED | {"tools/shared.py"},{"tools/shared.py"})
    def test_missing_b1_hold_source_blocks(self):
        with self.assertRaisesRegex(CompatibilityError,"hold/admission"):
            check_paths({".github/workflows/test-r4-b1-direct-native.yml"},set())
if __name__=="__main__":unittest.main()
