"""Offline boundaries for the Windows/local launcher; no real SSH or device."""
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'host/flash' / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


local = load('p7u_v6_recover_local')
recovery = load('p7u_v6_rom_recovery')


class LocalBoundary(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def package(self, source=local.V6):
        name = 'source/host/flash/p7u_v6_rom_recovery.py'
        path = self.root / name
        path.parent.mkdir(parents=True)
        path.write_bytes(b'qualified fixture')
        meta = {'firmware_source_sha': source, 'paired_host_source_sha': source,
                'paired_host_image': local.IMAGE, 'f2_wire_contract': local.WIRE,
                'operator_source_sha': 'a' * 40, 'files': {name: local.sha(path.read_bytes())}}
        raw = local.canonical(meta)
        (self.root / 'PACKAGE.json').write_bytes(raw)
        return local.sha(raw), path

    def test_wrong_firmware_pair_rejected_before_ssh(self):
        pin, _ = self.package('e3a0f3b7726adf1f6c182973f135665a5c3857e0')
        with patch.object(local.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'PACKAGE_NOT_INSTALLED_V6_PAIR'):
                local.checked_package(self.root, pin)
            run.assert_not_called()

    def test_changed_sealed_file_rejected(self):
        pin, path = self.package()
        local.checked_package(self.root, pin)
        path.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'PACKAGE_FILE_HASH'):
            local.checked_package(self.root, pin)

    def test_uncertain_ssh_is_consumed_and_cannot_be_replayed(self):
        with patch.object(local.subprocess, 'run', side_effect=subprocess.TimeoutExpired('ssh', 420)) as run:
            with self.assertRaises(subprocess.TimeoutExpired):
                local.dispatch(self.root, 'execute', ['python3', '-B', '/fixed/operator.py'])
            with self.assertRaises(FileExistsError):
                local.dispatch(self.root, 'execute', ['python3', '-B', '/fixed/operator.py'])
            self.assertEqual(run.call_count, 1)
        self.assertTrue(json.loads((self.root / 'execute-dispatch.json').read_bytes())['consumed_before_send'])

    def test_remote_hold_is_not_success_or_retry(self):
        response = subprocess.CompletedProcess([], 1, b'{"status":"HOLD"}\n', b'')
        with patch.object(local.subprocess, 'run', return_value=response) as run:
            with self.assertRaisesRegex(ValueError, 'SSH_PHASE_FAILED'):
                local.dispatch(self.root, 'execute', ['/fixed/operator.py'])
            with self.assertRaises(FileExistsError):
                local.dispatch(self.root, 'execute', ['/fixed/operator.py'])
            self.assertEqual(run.call_count, 1)
        self.assertFalse((self.root / 'execute-result.json').exists())


class ControlBinding(unittest.TestCase):
    @staticmethod
    def need(ok, reason):
        if not ok:
            raise ValueError(reason)

    def source(self, os_version='v3.4.3.dev1', data=b'qualified opcode source'):
        replies = [io.BytesIO(json.dumps({'Info': {'sw_version': os_version}}).encode()), io.BytesIO(data)]
        opener = unittest.mock.MagicMock()
        opener.open.side_effect = replies
        return opener

    def test_exact_decompressed_control_source(self):
        raw = b'qualified opcode source'
        expected = hashlib.sha256(raw).hexdigest()
        for wire in (raw, gzip.compress(raw)):
            with patch.object(recovery.urllib.request, 'build_opener', return_value=self.source(data=wire)):
                with patch.object(recovery, 'CONTROL_SOURCE_SHA256', expected):
                    self.assertEqual(recovery.control_source(self.need), expected)

    def test_changed_os_or_control_source_is_held(self):
        with patch.object(recovery.urllib.request, 'build_opener', return_value=self.source(os_version='other')):
            with self.assertRaisesRegex(ValueError, 'RECOVERY_CONTROL_OS'):
                recovery.control_source(self.need)
        with patch.object(recovery.urllib.request, 'build_opener', return_value=self.source(data=b'changed')):
            with self.assertRaisesRegex(ValueError, 'RECOVERY_CONTROL_SOURCE'):
                recovery.control_source(self.need)


if __name__ == '__main__':
    unittest.main()
