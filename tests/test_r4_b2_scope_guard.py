import unittest
from tools.b2_scope_guard import evaluate, ScopeError

class B2ScopeGuard(unittest.TestCase):
    def test_known_b2_files_pass(self):
        data=evaluate([("A","tools/b2_scope_guard.py"),
                       ("M",".github/workflows/test-r4-b0-native.yml"),
                       ("A","docs/r4/b2/TEST_MATRIX.md"),
                       ("A","firmware/slzb-06p7u/r4/b2/B2_PROFILE_MATRIX.json")])
        self.assertEqual(data["status"],"B2_SCOPE_ACCEPTED")
        self.assertFalse(data["B2_SOURCE_READY"])
        self.assertEqual(data["independent_human_or_model_reviews"],"NOT_ATTESTED")
    def test_protected_security_rejected(self):
        data=evaluate([("M","source/ti/zstack/stack/sec/zd_sec_mgr.c")])
        self.assertEqual(data["status"],"B2_SCOPE_REJECTED")
    def test_ccfg_rejected(self):
        data=evaluate([("M","firmware/slzb-06p7u/r4/b0/ccfg.c")])
        self.assertEqual(data["status"],"B2_SCOPE_REJECTED")
    def test_unsafe_binary_rejected(self):
        data=evaluate([("A","firmware/slzb-06p7u/r4/b2/release.bin")])
        self.assertEqual(data["status"],"B2_SCOPE_REJECTED")
    def test_outside_script_rejected(self):
        data=evaluate([("M","tools/b0_provision.py")])
        self.assertEqual(data["status"],"B2_SCOPE_REJECTED")
    def test_delete_and_rename_rejected(self):
        data=evaluate([("D","docs/r4/b2/B2_ADR.md")])
        self.assertEqual(data["status"],"B2_SCOPE_REJECTED")
        data=evaluate([("R100","tools/b2_compose.py")])
        self.assertEqual(data["status"],"B2_SCOPE_REJECTED")
    def test_path_traversal_rejected(self):
        data=evaluate([("A","docs/r4/b2/../../secrets/key.pem")])
        self.assertEqual(data["status"],"B2_SCOPE_REJECTED")
    def test_empty_branch_rejected(self):
        with self.assertRaisesRegex(ScopeError,"no branch changes"):
            evaluate([])

if __name__=="__main__":unittest.main()
