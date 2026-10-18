"""Offline-only packaging denies unbound native evidence before private reads."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'firmware/slzb-06p7u/r4/qualification'))
import nv4_current_app_package as mod


def write_bundle(root: Path, payload: dict[int, int]) -> bytes:
    files = {
        'elf': ('znp.out', b'\x7fELF\x02native-test'),
        'hex': ('znp.hex', mod.current.serialize(payload)),
        'bin': ('znp.bin', b'\x01\x02native-test'),
        'xml': ('znp_linkInfo.xml', b'<linkInfo/>'),
    }
    manifest = {
        'schema': 'r4-b0-artifact-manifest-v1',
        'build_log': 'build.log',
        'files': {kind: {'file': name, 'sha256': mod.current.sha(contents)}
                  for kind, (name, contents) in files.items()},
    }
    for name, contents in files.values():
        (root / name).write_bytes(contents)
    (root / 'build.log').write_text('native build evidence\n')
    raw = (json.dumps(manifest, sort_keys=True) + '\n').encode()
    (root / 'manifest.json').write_bytes(raw)
    return raw


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

    def test_coherent_source_swap_during_audit_cannot_change_package(self):
        original = {0: 0x12, 1: 0x34, 0x100: 0xAA}
        replacement = {0: 0x99, 1: 0x88, 0x100: 0xBB}
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            pinned = write_bundle(source, original)
            original_hex = (source / 'znp.hex').read_bytes()
            def swap_after_capture(frozen):
                self.assertNotEqual(frozen, source)
                self.assertEqual((frozen / 'manifest.json').read_bytes(), pinned)
                self.assertEqual((frozen / 'znp.hex').read_bytes(), original_hex)
                updated = write_bundle(source, replacement)
                self.assertNotEqual(mod.current.sha(updated), mod.current.sha(pinned))
                return {'status': 'REAL_LINKED_ADDRESS_ENVELOPE_ACCEPTED_NO_FLASH',
                        'linked_ccfg_exact_stock_20240716': True,
                        'flash_authorized': False}

            package = SimpleNamespace(sectors={0: b'captured'})
            with mock.patch.object(mod, 'audit_nv4', side_effect=swap_after_capture), \
                 mock.patch.object(mod.current, '_bind_payload', return_value=package) as bind:
                result = mod.from_artifacts(source, {}, b'',
                    expected_profile_sha256='0' * 64,
                    expected_manifest_sha256=mod.current.sha(pinned))
            self.assertIs(result, package)
            self.assertEqual(bind.call_args.args[0], original)
            self.assertEqual(bind.call_args.args[3]['hex_sha256'], mod.current.sha(original_hex))
            self.assertEqual(bind.call_args.args[3]['manifest_sha256'], mod.current.sha(pinned))

    def test_changed_member_and_symlink_member_denied_before_audit(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            pinned = write_bundle(source, {0: 1})
            (source / 'znp.hex').write_bytes(mod.current.serialize({0: 2}))
            with mock.patch.object(mod, 'audit_nv4') as audit:
                with self.assertRaisesRegex(ValueError, 'NATIVE_HEX_DIGEST_MISMATCH'):
                    mod.from_artifacts(source, {}, b'',
                        expected_profile_sha256='0' * 64,
                        expected_manifest_sha256=mod.current.sha(pinned))
                audit.assert_not_called()
            (source / 'znp.hex').unlink()
            (source / 'znp.hex').symlink_to(source / 'znp.out')
            with mock.patch.object(mod, 'audit_nv4') as audit:
                with self.assertRaisesRegex(ValueError, 'NATIVE_HEX_NOT_REGULAR'):
                    mod.from_artifacts(source, {}, b'',
                        expected_profile_sha256='0' * 64,
                        expected_manifest_sha256=mod.current.sha(pinned))
                audit.assert_not_called()

    def test_manifest_cannot_alias_snapshot_metadata_or_traverse(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            pinned = write_bundle(source, {0: 1})
            data = json.loads(pinned)
            for name in ('../external.hex', 'build.log', 'manifest.json'):
                with self.subTest(name=name):
                    data['files']['hex']['file'] = name
                    raw = json.dumps(data).encode()
                    (source / 'manifest.json').write_bytes(raw)
                    with self.assertRaisesRegex(ValueError, 'NATIVE_HEX_BASENAME'):
                        mod.from_artifacts(source, {}, b'',
                            expected_profile_sha256='0' * 64,
                            expected_manifest_sha256=mod.current.sha(raw))


if __name__ == '__main__':
    unittest.main()
