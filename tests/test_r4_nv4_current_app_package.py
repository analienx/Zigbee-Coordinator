"""Offline native packaging freezes all evidence before private binding."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'firmware/slzb-06p7u/r4/qualification'))
import nv4_current_app_package as mod


def native_fixture(root: Path):
    raw_files = {
        'elf': ('native.out', b'\x7fELF' + b'elf-fixture'),
        'hex': ('native.hex', b':00000001FF\n'),
        'bin': ('native.bin', b'binary-fixture'),
        'xml': ('native.xml', b'<link_info></link_info>'),
    }
    manifest = {'schema': 'r4-b0-artifact-manifest-v1', 'files': {}}
    for kind, (name, raw) in raw_files.items():
        (root / name).write_bytes(raw)
        manifest['files'][kind] = {'file': name, 'sha256': mod.sha(raw)}
    manifest_bytes = (json.dumps(manifest, sort_keys=True) + '\n').encode()
    (root / 'manifest.json').write_bytes(manifest_bytes)
    (root / 'build.log').write_bytes(b'fixture - not a real native build')
    return manifest, mod.sha(manifest_bytes)


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

    def test_manifest_hex_substitution_after_freeze_cannot_reach_binder(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            manifest, pinned = native_fixture(root)
            bound = []
            def audit(frozen):
                self.assertNotEqual(frozen.resolve(), root.resolve())
                self.assertEqual((frozen/'native.hex').read_bytes(), b':00000001FF\n')
                # An attacker can change original inputs after the snapshot;
                # neither audited bytes nor the payload binder can see them.
                (root/'native.hex').write_bytes(b'malicious bytes')
                (root/'manifest.json').write_text('{}')
                return {
                    'status': 'REAL_LINKED_ADDRESS_ENVELOPE_ACCEPTED_NO_FLASH',
                    'linked_ccfg_exact_stock_20240716': True,
                    'flash_authorized': False,
                    'manifest_digests': {k: v['sha256'] for k, v in manifest['files'].items()},
                }
            def parse(path):
                self.assertEqual(path.read_bytes(), b':00000001FF\n')
                bound.append(path.read_bytes())
                return {0: 1}, None
            def bind(linked, profile, snapshot, evidence, *, expected_profile_sha256):
                self.assertEqual(linked, {0: 1})
                self.assertEqual(evidence['manifest_sha256'], pinned)
                self.assertEqual(evidence['hex_sha256'], manifest['files']['hex']['sha256'])
                return SimpleNamespace(sectors={0: b'fixture'}, manifest={'package_sha256': 'f'*64})
            with (patch.object(mod, 'audit_nv4', side_effect=audit),
                  patch.object(mod, '_parse_intel_hex', side_effect=parse),
                  patch.object(mod.current, '_bind_payload', side_effect=bind)):
                pkg = mod.from_artifacts(root, {}, b'', expected_profile_sha256='0'*64,
                                         expected_manifest_sha256=pinned)
            self.assertEqual(pkg.sectors, {0: b'fixture'})
            self.assertEqual(bound, [b':00000001FF\n'])

    def test_pre_audit_file_mutation_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            _, pinned = native_fixture(root)
            (root/'native.hex').write_bytes(b'tampered before freezing')
            with self.assertRaisesRegex(ValueError, 'NATIVE_ARTIFACT_CHANGED_HEX'):
                mod.from_artifacts(root, {}, b'', expected_profile_sha256='0'*64,
                                   expected_manifest_sha256=pinned)

    def test_ambiguous_duplicate_artifact_basename_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            manifest, _ = native_fixture(root)
            manifest['files']['xml'] = manifest['files']['hex'].copy()
            updated = (json.dumps(manifest, sort_keys=True)+'\n').encode()
            (root/'manifest.json').write_bytes(updated)
            with self.assertRaisesRegex(ValueError, 'NATIVE_ARTIFACT_NAMES_COLLIDE'):
                mod.from_artifacts(root, {}, b'', expected_profile_sha256='0'*64,
                                   expected_manifest_sha256=mod.sha(updated))

    def test_auditor_manifest_digest_divergence_denied(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            _, pinned = native_fixture(root)
            fake_audit = {
                'status': 'REAL_LINKED_ADDRESS_ENVELOPE_ACCEPTED_NO_FLASH',
                'linked_ccfg_exact_stock_20240716': True,
                'flash_authorized': False,
                'manifest_digests': {},
            }
            with (patch.object(mod, 'audit_nv4', return_value=fake_audit),
                  patch.object(mod, '_parse_intel_hex', return_value=({0: 1}, None))):
                with self.assertRaisesRegex(ValueError, 'AUDITOR_MANIFEST_BINDING_MISMATCH'):
                    mod.from_artifacts(root, {}, b'', expected_profile_sha256='0'*64,
                                       expected_manifest_sha256=pinned)


if __name__ == '__main__':
    unittest.main()
