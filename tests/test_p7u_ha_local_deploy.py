"""HA operator fault tests: no actual HA, serial, management or private records."""
import asyncio
from dataclasses import dataclass
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, Mock, patch

SOURCE = Path(__file__).resolve().parents[1]/'host/flash/p7u_pr154_ha.py'
spec = importlib.util.spec_from_file_location('ha_deploy', SOURCE)
op = importlib.util.module_from_spec(spec); spec.loader.exec_module(op)


class Containment(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.root.chmod(0o700)

    def seal(self, files):
        raw = op.canonical({'files': files}); (self.root/'INPUT.json').write_bytes(raw)
        return op.sha(raw)

    def test_changed_file_rejected(self):
        (self.root/'x').write_bytes(b'old'); pin = self.seal({'x': op.sha(b'old')})
        op.sealed_tree(self.root, 'INPUT.json', pin)
        (self.root/'x').write_bytes(b'new')
        with self.assertRaisesRegex(op.Hold, 'FILE_PIN'): op.sealed_tree(self.root, 'INPUT.json', pin)

    def test_manifest_pin(self):
        pin = self.seal({'x': 'a'*64})
        with self.assertRaisesRegex(op.Hold, 'MANIFEST_PIN'): op.sealed_tree(self.root, 'INPUT.json', 'b'*64)

    def test_paths_and_symlinks(self):
        for name in ('../x', '/etc/passwd', 'x\\y'):
            with self.subTest(name=name):
                pin = self.seal({name: 'a'*64})
                with self.assertRaisesRegex(op.Hold, 'PATH_ESCAPE'): op.sealed_tree(self.root, 'INPUT.json', pin)
        (self.root/'link').symlink_to('/etc/passwd'); pin = self.seal({'link': 'a'*64})
        with self.assertRaisesRegex(op.Hold, 'SYMLINK'): op.sealed_tree(self.root, 'INPUT.json', pin)

    def test_private_root_permissions(self):
        self.root.chmod(0o755)
        with self.assertRaisesRegex(op.Hold, 'PRIVATE_ROOT'): op.private_root(self.root)

    def test_receipt_is_immutable(self):
        op.durable(self.root, 'intent.json', {'one': 1})
        with self.assertRaises(FileExistsError): op.durable(self.root, 'intent.json', {'two': 2})

    def test_supervisor_write_scope_cannot_expand(self):
        ha = op.HA()
        for url, payload in [('http://supervisor/core/api/services/button/press', {'entity_id': 'button.other'}),
                             ('http://supervisor/addons/45df7312_zigbee2mqtt/start', {}),
                             ('http://supervisor/core/api/services/homeassistant/restart', {})]:
            with self.subTest(url=url), self.assertRaisesRegex(op.Hold, 'API_SCOPE'): ha.request(url, payload)


@dataclass
class Receipt:
    status: str = 'SPARSE_ROM_CRC_WITH_FRESH_NV_READ_ONLY_NOT_FLASH_ADMISSION'


class Execution(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.private = self.root/'private'; self.private.mkdir(mode=0o700)
        self.data = self.root/'data'; self.data.mkdir(); (self.data/'coordinator_backup.json').write_text('{}')
        self.candidate = self.root/'candidate'; self.candidate.mkdir()
        for name in ('security-native-abi.json', 'handoff-receipt.json'): (self.candidate/name).write_text('{}')
        for name in ('P7U-STOCK20260311-APP-ONLY.hex', 'P7U-STOCK20260311-AC000-HANDOFF.bin'):
            (self.candidate/name).write_bytes(b'public')
        self.package = self.root/'package'; self.package.mkdir(); (self.package/'security-reader-aarch64').write_bytes(b'reader')
        self.inputs = self.root/'input'; self.inputs.mkdir()
        for name in ('installed-app.hex', 'installed-handoff.bin'): (self.inputs/name).write_bytes(b'oldpublic')
        (self.inputs/'historical-backup.json').write_text('{}')
        self.ha = Mock(); self.owner = {'image': op.IMAGE, 'id': 'one', 'running': True}
        self.ha.inspect.return_value = self.owner; self.ha.management.return_value = 'm'
        self.p = {'created_at': time.time(), 'owner': self.owner, 'management_sha256': 'm',
                  'prior_verified_image_sha256': op.sha(b'expected'), 'installed_result_sha256': op.sha(op.canonical({}))}
        self.t = Mock(); self.sec = Mock(); self.sec.abi_tool.canonical = op.canonical
        self.sec.preflight.return_value = {'status': 'HOLD'}
        self.rom = Mock(); self.rom.reader.read = AsyncMock(side_effect=asyncio.TimeoutError)
        self.rom.open = AsyncMock(); self.rom.close = AsyncMock(); self.rom.synchronize = AsyncMock(return_value=True)
        self.rom.identity_sha256 = AsyncMock(return_value=op.ROM_ID)
        self.rom.enable_fast_reads = AsyncMock(); self.rom.assert_read_status = AsyncMock()
        self.factory = Mock(return_value=self.rom)
        self.capture = AsyncMock(return_value=SimpleNamespace(receipt=Receipt(), snapshot=b'current'))
        self.reconcile = Mock()
        self.old = SimpleNamespace(snapshot=b'old', manifest={'plan_sha256': 'oldpin', 'candidate_sha256': 'oldcandidate'})
        patches = {'PRIVATE': self.private, 'DATA': self.data, 'CANDIDATE': self.candidate, 'INPUT': self.inputs}
        for k, v in patches.items():
            p = patch.object(op, k, v); p.start(); self.addCleanup(p.stop)
        for name, value in [('check_plan', Mock(return_value=self.p)),
                            ('installed', Mock(return_value=(self.old, {}, {}, b'expected'))),
                            ('candidate', Mock(return_value={'profile_sha256': 'profile', 'native_manifest_sha256': 'manifest'})),
                            ('modules', Mock(return_value=(self.t, self.sec, self.reconcile, self.factory, self.capture)))]:
            p = patch.object(op, name, value); p.start(); self.addCleanup(p.stop)
        p = patch.object(op.asyncio, 'sleep', AsyncMock()); p.start(); self.addCleanup(p.stop)

    async def test_consumed_execution_never_stops(self):
        op.durable(self.private, 'execute-intent.json', {})
        with self.assertRaisesRegex(op.Hold, 'EXECUTION_CONSUMED'): await op.deploy(self.package, 'pin', self.ha)
        self.ha.owner_action.assert_not_called(); self.factory.assert_not_called()

    async def test_expired_plan_never_stops(self):
        self.p['created_at'] -= 1801
        with self.assertRaisesRegex(op.Hold, 'PLAN_EXPIRED'): await op.deploy(self.package, 'pin', self.ha)
        self.ha.owner_action.assert_not_called()

    async def test_changed_owner_never_stops(self):
        self.ha.inspect.return_value = {'different': True}
        with self.assertRaisesRegex(op.Hold, 'OWNER_CHANGED'): await op.deploy(self.package, 'pin', self.ha)
        self.ha.owner_action.assert_not_called()

    async def test_policy_hold_never_stops(self):
        self.ha.policy.side_effect = op.Hold('policy')
        with self.assertRaises(op.Hold): await op.deploy(self.package, 'pin', self.ha)
        self.ha.owner_action.assert_not_called()

    async def test_stop_ack_unknown_is_consumed_without_bsl_or_replay(self):
        self.ha.owner_action.side_effect = TimeoutError()
        with self.assertRaises(TimeoutError): await op.deploy(self.package, 'pin', self.ha)
        self.assertTrue((self.private/'execute-intent.json').exists())
        self.assertTrue((self.private/'hold.json').exists()); self.factory.assert_not_called()
        with self.assertRaisesRegex(op.Hold, 'EXECUTION_CONSUMED'): await op.deploy(self.package, 'pin', self.ha)
        self.ha.owner_action.assert_called_once_with('stop')

    async def test_security_hold_never_erases_or_boots(self):
        with self.assertRaisesRegex(op.Hold, 'NATIVE_SECURITY'): await op.deploy(self.package, 'pin', self.ha)
        self.t.execute.assert_not_called(); self.ha.restart_radio.assert_not_called()
        self.ha.owner_action.assert_called_once_with('stop'); self.rom.close.assert_awaited_once()
        self.assertTrue((self.private/'hold.json').exists())

    async def test_bsl_ack_unknown_never_syncs_or_retries(self):
        self.ha.enter_bsl.side_effect = TimeoutError()
        with self.assertRaises(TimeoutError): await op.deploy(self.package, 'pin', self.ha)
        self.rom.synchronize.assert_not_awaited(); self.t.execute.assert_not_called()
        self.ha.enter_bsl.assert_called_once(); self.rom.close.assert_awaited_once()

    async def test_wrong_silicon_never_captures_or_writes(self):
        self.rom.identity_sha256.return_value = 'other'
        with self.assertRaisesRegex(op.Hold, 'ROM_IDENTITY'): await op.deploy(self.package, 'pin', self.ha)
        self.capture.assert_not_awaited(); self.t.execute.assert_not_called()

    def ready(self):
        (self.candidate/'security-native-abi.json').write_text('{"structs":{"nwkIB_t":{"size":1}}}')
        self.sec.preflight.return_value = {'status': 'PASS_RETAINED_SECURITY_OFFLINE_ONLY'}
        self.sec.read_private.return_value = ({(1, 7, 0): b'counter'}, {})
        self.sec.get.return_value = b'nib'; self.sec.field.return_value = b'pan'; self.sec.number.return_value = 123
        self.reconcile.return_value = {'status': 'PASS_CURRENT_OWNER_OFFLINE_ONLY'}
        self.frozen = SimpleNamespace(manifest={'plan_sha256': 'frozenpin'},
            sectors={a: bytes(8192) for a in (*range(0, 0x30000, 8192), 0xAC000)})
        self.t.prepare_upgrade.return_value = self.frozen; self.t.bind_sparse_plan.return_value = self.frozen
        self.t.admit_sparse = AsyncMock(return_value={'admission_sha256': 'admitpin'})
        async def writer(*args, **kwargs):
            await kwargs['journal']({'event': 'SECTOR_VERIFIED', 'address': 0, 'sha256': 'digest'})
            return {'status': 'APP_AND_AC000_CRC_VERIFIED_STILL_IN_BSL'}
        self.t.execute = AsyncMock(side_effect=writer)

    async def test_current_owner_security_hold_never_writes(self):
        self.ready(); self.reconcile.return_value = {'status': 'HOLD'}
        with self.assertRaisesRegex(op.Hold, 'CURRENT_OWNER_SECURITY'): await op.deploy(self.package, 'pin', self.ha)
        self.t.execute.assert_not_awaited(); self.ha.restart_radio.assert_not_called()

    async def test_nv_sector_cannot_enter_execution(self):
        self.ready(); self.frozen.sectors[0xA4000] = bytes(8192)
        with self.assertRaisesRegex(op.Hold, 'SECTOR_SCOPE'): await op.deploy(self.package, 'pin', self.ha)
        self.t.admit_sparse.assert_not_awaited(); self.t.execute.assert_not_awaited()

    async def test_uncertain_writer_never_boots_or_replays(self):
        self.ready(); self.t.execute.side_effect = TimeoutError()
        with self.assertRaises(TimeoutError): await op.deploy(self.package, 'pin', self.ha)
        self.assertFalse((self.private/'verified-write.json').exists())
        self.assertTrue((self.private/'hold.json').exists()); self.ha.restart_radio.assert_not_called()
        with self.assertRaisesRegex(op.Hold, 'EXECUTION_CONSUMED'): await op.deploy(self.package, 'pin', self.ha)
        self.t.execute.assert_awaited_once()

    async def test_success_stays_in_bsl_with_bound_receipt(self):
        self.ready(); result = await op.deploy(self.package, 'pin', self.ha)
        envelope = op.load(self.private/'verified-write.json')
        self.assertEqual(envelope['result'], result); self.assertEqual(envelope['operation_plan_sha256'], 'pin')
        self.assertTrue(self.t.execute.await_args.kwargs['same_session_sparse'])
        self.ha.owner_action.assert_called_once_with('stop'); self.ha.restart_radio.assert_not_called()
        self.rom.close.assert_awaited_once()


if __name__ == '__main__': unittest.main()
