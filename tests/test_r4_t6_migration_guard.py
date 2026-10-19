"""R4-T6 300-TC legacy migration must be compile-time denied, never run."""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "tools" / "r4_t6_migration_guard.py"
PROFILE = ROOT / "firmware/slzb-06p7u/r4/profiles/p7u-r4-full-nv4.json"
spec = importlib.util.spec_from_file_location("t6_guard", SRC)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

UPSTREAM = b"""/* synthetic exact-structure pinned TI candidate */
#ifdef ZSTACK_5_30_NV_MIGRATION
static void zgMigrateTo530SDK( void );
#endif
#ifdef ZSTACK_5_30_NV_MIGRATION
static void zgMigrateTo530SDK( void )
{
    uint8_t i = 0;
    for( i = 0; i < gZDSECMGR_TC_DEVICE_MAX; i++ )
    {
        osal_nv_delete_ex(ZCD_NV_EX_TCLK_TABLE, i, 1);
    }
}
#endif
"""


class T6LegacyMigrationGuard(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="r4-t6-", dir="/tmp")
        self.root = Path(self.directory.name)
        self.sdk = self.root / "sdk"
        self.source = self.sdk / guard.REL
        self.source.parent.mkdir(parents=True)
        self.source.write_bytes(UPSTREAM)
        self.profile = self.root / "profile.json"
        self.profile.write_text(PROFILE.read_text())
        self.receipt = self.root / "evidence.json"

    def tearDown(self):
        self.directory.cleanup()

    def git(self, args):
        if args[-2:] == ["rev-parse", "HEAD"]:
            return (guard.PIN + "\n").encode()
        if args[-2:] == ["show", guard.PIN + ":" + guard.REL]:
            return UPSTREAM
        raise AssertionError(args)

    def test_positive_pin_and_actual_full_nv4_profile_guarded(self):
        with patch.object(guard.subprocess, "check_output", side_effect=self.git):
            proof = guard.stage(self.sdk, self.profile, self.receipt)
        self.assertEqual(proof["legacy_migration_if_enabled"], "COMPILE_TIME_ERROR")
        self.assertFalse(proof["actual_tc300_linked_capacity_proven"])
        self.assertFalse(proof["installed_or_flash_authorized"])
        self.assertTrue(self.source.read_bytes().startswith(guard.GUARD.encode()))
        self.assertTrue(self.receipt.is_file())
        with patch.object(guard.subprocess, "check_output", side_effect=self.git), self.assertRaises(ValueError):
            guard.stage(self.sdk, self.profile, self.root / "second.json")

    def test_wrong_capacities_and_authorization_fail_before_source_change(self):
        original = json.loads(self.profile.read_text())
        mutants = []
        for cap in (255, 256, 301):
            m = copy.deepcopy(original)
            m["capacities"]["trust_center_devices"] = cap
            mutants.append(m)
        for field in ("auto_nv_format", "auto_flash", "physical_flash_authorized",
                      "network_forming_by_default", "full_b0_b4_sealed"):
            m = copy.deepcopy(original)
            m["policies"][field] = True
            mutants.append(m)
        for data in mutants:
            with self.subTest(data=data["capacities"], field=data["policies"]), self.assertRaises(ValueError):
                self.profile.write_text(json.dumps(data))
                guard.stage(self.sdk, self.profile, self.receipt)
            self.assertEqual(self.source.read_bytes(), UPSTREAM)

    def test_source_drift_and_wrong_sdk_commit_fail_closed(self):
        with patch.object(guard.subprocess, "check_output", side_effect=lambda args:
                b"0"*40 if args[-2:] == ["rev-parse", "HEAD"] else UPSTREAM):
            with self.assertRaisesRegex(ValueError, "SDK commit"):
                guard.stage(self.sdk, self.profile, self.receipt)
        self.source.write_bytes(UPSTREAM + b"// mutated")
        with patch.object(guard.subprocess, "check_output", side_effect=self.git):
            with self.assertRaisesRegex(ValueError, "modified"):
                guard.stage(self.sdk, self.profile, self.receipt)

    def test_wrong_index_and_destructive_order_not_patched_silently(self):
        for mutant in (UPSTREAM.replace(b"uint8_t i = 0", b"uint16_t i = 0"),
                       UPSTREAM.replace(b"osal_nv_delete_ex", b"osal_nv_write_ex")):
            with self.subTest(mutant=mutant[:30]):
                with self.assertRaisesRegex(ValueError, "unsafe migration source drift"):
                    guard.guarded(mutant)

    def test_parent_symlink_refuses_write_outside_sdk(self):
        outside = self.root / "external"
        outside.mkdir()
        srcdir = self.source.parent
        # Only this disposable fixture is removed.
        shutil.rmtree(srcdir)
        (outside / "zglobals.c").write_bytes(UPSTREAM)
        srcdir.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            guard.stage(self.sdk, self.profile, self.receipt)
        self.assertEqual((outside / "zglobals.c").read_bytes(), UPSTREAM)

    def test_full_native_workflow_guards_the_disposable_sdk_before_make(self):
        workflow = (ROOT / ".github/workflows/test-r4-final-composite-native.yml").read_text()
        build_scope = 'python "$GITHUB_WORKSPACE/firmware/slzb-06p7u/r4/b0/tools/b0_sdk_build_scope.py"'
        guard_call = 'python "$GITHUB_WORKSPACE/tools/r4_t6_migration_guard.py"'
        build = '(cd "$sdk" && make -j2)'
        self.assertEqual(workflow.count(build_scope), 1)
        self.assertEqual(workflow.count(guard_call), 1)
        self.assertEqual(workflow.count(build), 1)
        self.assertLess(workflow.index(build_scope), workflow.index(guard_call))
        self.assertLess(workflow.index(guard_call), workflow.index(build))
        self.assertIn("tests.test_r4_t6_migration_guard", workflow)

    @unittest.skipUnless(shutil.which("gcc"), "host C compiler required")
    def test_preprocessor_explicitly_refuses_legacy_migration_macro(self):
        content = (guard.GUARD + "int main(void) {return 0;}\n").encode()
        positive = subprocess.run(["gcc", "-x", "c", "-fsyntax-only", "-"],
                                  input=content, capture_output=True)
        negative = subprocess.run(["gcc", "-DZSTACK_5_30_NV_MIGRATION",
                                   "-x", "c", "-fsyntax-only", "-"],
                                  input=content, capture_output=True)
        self.assertEqual(positive.returncode, 0, positive.stderr)
        self.assertNotEqual(negative.returncode, 0)
        self.assertIn(b"R4_TC300_LEGACY_MIGRATION_FORBIDDEN", negative.stderr)


if __name__ == "__main__":
    unittest.main()
