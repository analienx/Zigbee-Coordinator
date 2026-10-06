"""Unit tests for the T832 R8 NV recovery fix module.

Self-contained: no SDK checkout is needed. These tests prove the patch
strings are self-consistent (each old block matches once, the result
carries the fingerprint and refuses double-patching). Applying the patch
to the real pinned TI file, compiling it and proving recovery is a
hosted-CI matter (run_nv_lab pins the SDK commit and file hash,
audit_source fingerprints the patched firmware sources).
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from apply_diag import Exact
from nv_recovery_fix import (apply_fix, verify_fixed, FIX_ID,
                             PRISTINE_ALGO_SHA256, P1_OLD, P1_NEW, P3_OLD,
                             P3_NEW, HELPER_ANCHOR_OLD, HELPER_ANCHOR_NEW,
                             CASE_OLD, CASE_NEW, HELPER)


def synthetic_pristine():
    return '\n'.join(('header', P1_OLD, 'middle', P3_OLD, 'more',
                       HELPER_ANCHOR_OLD, 'tail', CASE_OLD, 'end')) + '\n'


class RecoveryFixTests(unittest.TestCase):
    def test_identity_constants(self):
        self.assertEqual(FIX_ID, 't832-r8-nv-recovery-02')
        self.assertEqual(len(PRISTINE_ALGO_SHA256), 64)
        int(PRISTINE_ALGO_SHA256, 16)

    def test_patch_strings_are_lf_and_distinct(self):
        for block in (P1_OLD, P1_NEW, P3_OLD, P3_NEW, HELPER_ANCHOR_OLD,
                      HELPER_ANCHOR_NEW, CASE_OLD, CASE_NEW, HELPER):
            self.assertNotIn('\r', block)
        for old, new in ((P1_OLD, P1_NEW), (P3_OLD, P3_NEW),
                         (HELPER_ANCHOR_OLD, HELPER_ANCHOR_NEW),
                         (CASE_OLD, CASE_NEW)):
            self.assertNotEqual(old, new)

    def test_exact_mechanics_and_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'nvocmp.c'
            target.write_text(synthetic_pristine(), encoding='utf-8')
            ex = Exact()
            ex.replace(target, P1_OLD, P1_NEW, 'p1')
            ex.replace(target, P3_OLD, P3_NEW, 'p3')
            ex.replace(target, HELPER_ANCHOR_OLD, HELPER_ANCHOR_NEW, 'helper')
            ex.replace(target, CASE_OLD, CASE_NEW, 'case')
            result = target.read_text(encoding='utf-8')
            self.assertNotIn(P1_OLD, result)
            self.assertNotIn(P3_OLD, result)
            fp = verify_fixed(result)
            self.assertEqual(fp['fix_id'], FIX_ID)
            # Double-patching must fail closed.
            with self.assertRaises(SystemExit):
                ex.replace(target, P1_OLD, P1_NEW, 'p1-again')

    def test_verify_rejects_unpatched_text(self):
        with self.assertRaises(ValueError):
            verify_fixed(synthetic_pristine())

    def test_verify_rejects_marker_only_text(self):
        with self.assertRaises(ValueError):
            verify_fixed('no markers here\n')

    def test_apply_refuses_non_pristine_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'nvocmp.c'
            target.write_text(synthetic_pristine(), encoding='utf-8')
            with self.assertRaises(ValueError):
                apply_fix(target)


if __name__ == '__main__':
    unittest.main()
