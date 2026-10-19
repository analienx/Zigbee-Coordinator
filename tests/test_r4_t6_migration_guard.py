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
#endif // ZSTACK_5_30_NV_MIGRATION
"""
OVERLAID = b"/* B1+B3 checked source overlay */\n" + UPSTREAM


class T6LegacyMigrationGuard(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="r4-t6-", dir="/tmp")
        self.root = Path(self.directory.name)
        self.sdk = self.root / "sdk"
        self.source = self.sdk / guard.REL
        self.source.parent.mkdir(parents=True)
        self.source.write_bytes(OVERLAID)
        self.profile = self.root / "profile.json"
        self.profile.write_text(PROFILE.read_text())
        self.receipt = self.root / "evidence.json"
        self.b1_receipt = self.root / "b1-overlay.json"
        self.b1_receipt.write_text(json.dumps({
            "schema": "r4-b1-admission-overlay-v2",
            "upstream_zglobals_blob": guard.git_blob(UPSTREAM),
            "post_b1_security_fusion": "B1_PLUS_SELECTED_B3_IMMUTABLE_INPUTS",
            "b3_source_commit": "b481e0beabf1966900644f69d7f5d024708ebf73",
            "modified_zglobals_sha256": guard.digest(OVERLAID),
        }))

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
            proof = guard.stage(self.sdk, self.profile, self.receipt, self.b1_receipt)
        self.assertEqual(proof["legacy_migration_if_enabled"], "COMPILE_TIME_ERROR")
        self.assertFalse(proof["actual_tc300_linked_capacity_proven"])
        self.assertFalse(proof["installed_or_flash_authorized"])
        self.assertTrue(self.source.read_bytes().startswith(guard.GUARD.encode()))
        self.assertTrue(self.receipt.is_file())
        b1 = json.loads(self.b1_receipt.read_text())
        self.assertEqual(b1["modified_zglobals_sha256"], guard.digest(self.source.read_bytes()))
        self.assertEqual(b1["t6_legacy_migration_denial"]["full_role_sealed"], False)
        with patch.object(guard.subprocess, "check_output", side_effect=self.git), self.assertRaises(ValueError):
            guard.stage(self.sdk, self.profile, self.root / "second.json", self.b1_receipt)

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
                guard.stage(self.sdk, self.profile, self.receipt, self.b1_receipt)
            self.assertEqual(self.source.read_bytes(), OVERLAID)

    def test_source_drift_and_wrong_sdk_commit_fail_closed(self):
        with patch.object(guard.subprocess, "check_output", side_effect=lambda args:
                b"0"*40 if args[-2:] == ["rev-parse", "HEAD"] else UPSTREAM):
            with self.assertRaisesRegex(ValueError, "SDK commit"):
                guard.stage(self.sdk, self.profile, self.receipt, self.b1_receipt)
        self.source.write_bytes(OVERLAID + b"// mutated")
        with patch.object(guard.subprocess, "check_output", side_effect=self.git):
            with self.assertRaisesRegex(ValueError, "modified"):
                guard.stage(self.sdk, self.profile, self.receipt, self.b1_receipt)

    def test_mutated_migration_body_or_stale_b1_receipt_fails_closed(self):
        self.source.write_bytes(OVERLAID.replace(b"osal_nv_delete_ex",
                                                 b"osal_nv_write_ex"))
        with patch.object(guard.subprocess, "check_output", side_effect=self.git):
            with self.assertRaisesRegex(ValueError, "receipt drift"):
                guard.stage(self.sdk, self.profile, self.receipt, self.b1_receipt)
        self.assertFalse(self.receipt.exists())
        self.source.write_bytes(OVERLAID)
        bound = json.loads(self.b1_receipt.read_text())
        bound["modified_zglobals_sha256"] = guard.digest(OVERLAID + b"bad")
        self.b1_receipt.write_text(json.dumps(bound))
        with patch.object(guard.subprocess, "check_output", side_effect=self.git):
            with self.assertRaisesRegex(ValueError, "receipt drift"):
                guard.stage(self.sdk, self.profile, self.receipt, self.b1_receipt)
        self.assertEqual(self.source.read_bytes(), OVERLAID)

    def test_function_body_mutation_rejected_even_with_matching_receipt(self):
        changed = OVERLAID.replace(b"TCLK_TABLE, i, 1", b"TCLK_TABLE, i, 2")
        self.source.write_bytes(changed)
        bound = json.loads(self.b1_receipt.read_text())
        bound["modified_zglobals_sha256"] = guard.digest(changed)
        self.b1_receipt.write_text(json.dumps(bound))
        with patch.object(guard.subprocess, "check_output", side_effect=self.git):
            with self.assertRaisesRegex(ValueError, "unsafe migration source drift"):
                guard.stage(self.sdk, self.profile, self.receipt, self.b1_receipt)
        self.assertFalse(self.receipt.exists())

    def test_wrong_index_and_destructive_order_not_patched_silently(self):
        for mutant in (UPSTREAM.replace(b"uint8_t i = 0", b"uint16_t i = 0"),
                       UPSTREAM.replace(b"osal_nv_delete_ex", b"osal_nv_write_ex")):
            with self.subTest(mutant=mutant[:30]):
                with self.assertRaisesRegex(ValueError, "unsafe migration source drift"):
                    guard.guarded(mutant, UPSTREAM)

    def test_parent_symlink_refuses_write_outside_sdk(self):
        outside = self.root / "external"
        outside.mkdir()
        srcdir = self.source.parent
        # Only this disposable fixture is removed.
        shutil.rmtree(srcdir)
        (outside / "zglobals.c").write_bytes(OVERLAID)
        srcdir.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            guard.stage(self.sdk, self.profile, self.receipt, self.b1_receipt)
        self.assertEqual((outside / "zglobals.c").read_bytes(), UPSTREAM)

    def test_full_native_workflow_guards_after_all_overlays_before_ccs_import(self):
        workflow = (ROOT / ".github/workflows/test-r4-final-composite-native.yml").read_text()
        markers = (
            '(cd "$sdk" && make -j2)',
            'python "$GITHUB_WORKSPACE/firmware/slzb-06p7u/r4/b1/tools/apply_b1.py"',
            'python "$GITHUB_WORKSPACE/tools/r4_b1_b3_security_fuse.py"',
            'python "$GITHUB_WORKSPACE/tools/r4_b0_b4_composite_stage.py"',
            'python "$GITHUB_WORKSPACE/firmware/slzb-06p7u/r4/qualification/nv4_b1_bridge.py"',
            'python "$GITHUB_WORKSPACE/tools/r4_t6_migration_guard.py"',
            'echo "importing and building the pinned ZNP projectspec"',
        )
        for marker in markers:
            self.assertEqual(workflow.count(marker), 1, marker)
        offsets = [workflow.index(marker) for marker in markers]
        self.assertEqual(offsets, sorted(offsets))
        self.assertIn("--b1-overlay-receipt /tmp/b0out/b1-overlay.json", workflow)
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
