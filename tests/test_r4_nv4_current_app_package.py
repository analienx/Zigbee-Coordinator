"""Offline-only packaging denies unbound native evidence before private reads."""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'firmware/slzb-06p7u/r4/qualification'))
import nv4_current_app_package as mod


class Nv4CurrentAppTests(unittest.TestCase):
    def test_missing_manifest_refused(self):
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaisesRegex(ValueError, 'NATIVE_MANIFEST_UNBOUND'):
                mod.from_artifacts(Path(t), {}, b'',
                                   expected_profile_sha256='0'*64,
                                   expected_manifest_sha256='1'*64)

    def test_wrong_manifest_digest_refused_before_binary(self):
        with tempfile.TemporaryDirectory() as t:
            (Path(t)/'manifest.json').write_text('{}')
            with self.assertRaisesRegex(ValueError, 'NATIVE_MANIFEST_UNBOUND'):
                mod.from_artifacts(Path(t), {}, b'',
                                   expected_profile_sha256='0'*64,
                                   expected_manifest_sha256='1'*64)

    def test_fitted_application_limit_remains_stricter_than_nv4(self):
        from r4_current_board_profile import APP_LIMIT
        self.assertEqual(APP_LIMIT, 0xA0000)
        self.assertLess(APP_LIMIT, mod.audit_nv4.__globals__['APP_END'])


if __name__ == '__main__':
    unittest.main()
