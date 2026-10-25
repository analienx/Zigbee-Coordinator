"""HA operator fault tests: no actual HA, serial, management or private records."""
import asyncio
from dataclasses import dataclass
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, Mock, patch

SOURCE = Path(__file__).resolve().parents[1]/'host/flash/p7u_pr154_ha.py'
spec = importlib.util.spec_from_file_location('ha_deploy', SOURCE)
op = importlib.util.module_from_spec(spec); spec.loader.exec_module(op)
spec = importlib.util.spec_from_file_location('ha_stage', SOURCE.with_name('p7u_pr154_stage.py'))
stage = importlib.util.module_from_spec(spec); spec.loader.exec_module(stage)


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

    def test_only_read_timeouts_are_retried(self):
        ha = op.HA(); response = Mock()
        response.__enter__ = Mock(return_value=response); response.__exit__ = Mock(return_value=False)
        response.read.return_value = b'{"result":"ok"}'
        with patch.dict(os.environ, {'SUPERVISOR_TOKEN': 'test-only'}), \
             patch.object(op.time, 'sleep'), \
             patch.object(op.urllib.request, 'urlopen', side_effect=[TimeoutError(), response]) as http:
            self.assertEqual(ha.request('http://supervisor/addons/'+op.OWNER+'/info'), {'result': 'ok'})
            self.assertEqual(http.call_count, 2)
        with patch.dict(os.environ, {'SUPERVISOR_TOKEN': 'test-only'}), \
             patch.object(op.urllib.request, 'urlopen', side_effect=TimeoutError()) as http:
            with self.assertRaises(TimeoutError): ha.owner_action('start')
            self.assertEqual(http.call_count, 1)

    def test_exhausted_read_names_fixed_endpoint(self):
        with patch.dict(os.environ, {'SUPERVISOR_TOKEN': 'test-only'}), \
             patch.object(op.time, 'sleep'), \
             patch.object(op.urllib.request, 'urlopen', side_effect=TimeoutError()) as http:
            with self.assertRaisesRegex(op.Hold, 'READ_TIMEOUT_addons/local_p7u_r4_native_host/info'):
                op.HA().info(op.OWNER)
            self.assertEqual(http.call_count, 2)

    def test_stage_cannot_escape_or_use_links_or_duplicate_roots(self):
        for name in ('package/../x', '/share/x', 'input/C:\\Windows', 'package//x', 'third/x'):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'MEMBER_PATH'): stage.safe_name(name)
        with patch.object(stage, 'SHARE', self.root), patch.object(stage, 'INPUT', self.root/'input-final'):
            first = stage.prepare('a'*64)
            self.assertTrue(Path(first['path']).is_dir())
            with self.assertRaisesRegex(ValueError, 'EXISTS'): stage.prepare('a'*64)

    def test_stage_rejects_archive_tamper_before_extract(self):
        with patch.object(stage, 'SHARE', self.root), patch.object(stage, 'INPUT', self.root/'input-final'):
            root = Path(stage.prepare('a'*64)['path']); (root/'payload.tar').write_bytes(b'tampered')
            with self.assertRaisesRegex(ValueError, 'ARCHIVE_HASH'): stage.install('a'*64, 'b'*64, 'c'*64)
            self.assertFalse((root/'install-intent.json').exists())


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

    async def test_qualified_quiescent_continuation_never_repeats_stop(self):
        self.ready(); self.p['quiescent_provenance_sha256'] = 'proof'
        with patch.object(op, 'quiescent_provenance', return_value='proof'):
            await op.deploy(self.package, 'pin', self.ha)
        self.ha.owner_action.assert_not_called(); self.t.execute.assert_awaited_once()

    async def test_changed_quiescent_provenance_never_enters_bsl(self):
        self.p['quiescent_provenance_sha256'] = 'proof'
        with patch.object(op, 'quiescent_provenance', return_value='changed'):
            with self.assertRaisesRegex(op.Hold, 'QUIESCENT_CHANGED'):
                await op.deploy(self.package, 'pin', self.ha)
        self.ha.owner_action.assert_not_called(); self.factory.assert_not_called()

    async def test_rom_reattach_never_repeats_bsl_or_stop(self):
        self.ready(); self.p['quiescent_provenance_sha256'] = 'q'
        self.p['rom_continuation_sha256'] = 'r'
        held = self.root/'held'; held.mkdir(); (held/'fresh-sparse-snapshot.bin').write_bytes(b'current')
        with patch.object(op, 'quiescent_provenance', return_value='q'), \
             patch.object(op, 'rom_hold_provenance', return_value='r'), patch.object(op, 'HELD_ROM', held):
            await op.deploy(self.package, 'pin', self.ha)
        self.ha.enter_bsl.assert_not_called(); self.ha.owner_action.assert_not_called()
        self.assertTrue((self.private/'rom-reattach-intent.json').exists())
        self.t.execute.assert_awaited_once()
        self.assertTrue(self.sec.preflight.call_args.kwargs['runtime_upgrade'])

    async def test_changed_rom_image_never_admits_or_writes(self):
        self.ready(); self.p['quiescent_provenance_sha256'] = 'q'
        self.p['rom_continuation_sha256'] = 'r'
        held = self.root/'held'; held.mkdir(); (held/'fresh-sparse-snapshot.bin').write_bytes(b'different')
        with patch.object(op, 'quiescent_provenance', return_value='q'), \
             patch.object(op, 'rom_hold_provenance', return_value='r'), patch.object(op, 'HELD_ROM', held):
            with self.assertRaisesRegex(op.Hold, 'ROM_IMAGE_CHANGED'):
                await op.deploy(self.package, 'pin', self.ha)
        self.ha.enter_bsl.assert_not_called(); self.t.execute.assert_not_awaited()

    async def test_changed_rom_hold_never_opens_serial(self):
        self.p['rom_continuation_sha256'] = 'r'
        with patch.object(op, 'rom_hold_provenance', return_value='changed'):
            with self.assertRaisesRegex(op.Hold, 'ROM_HOLD_CHANGED'):
                await op.deploy(self.package, 'pin', self.ha)
        self.factory.assert_not_called(); self.ha.enter_bsl.assert_not_called()

    async def test_bounded_fresh_session_enters_bsl_exactly_once(self):
        self.ready(); self.p['quiescent_provenance_sha256'] = 'q'; self.p['bounded_reentry_sha256'] = 'r'
        with patch.object(op, 'quiescent_provenance', return_value='q'), \
             patch.object(op, 'bounded_reentry_provenance', return_value='r'):
            await op.deploy(self.package, 'pin', self.ha)
        self.ha.enter_bsl.assert_called_once(); self.ha.owner_action.assert_not_called()
        self.t.execute.assert_awaited_once()

    async def test_changed_bounded_reentry_proof_never_opens_serial(self):
        self.p['bounded_reentry_sha256'] = 'r'
        with patch.object(op, 'bounded_reentry_provenance', return_value='changed'):
            with self.assertRaisesRegex(op.Hold, 'REENTRY_CHANGED'):
                await op.deploy(self.package, 'pin', self.ha)
        self.factory.assert_not_called(); self.ha.enter_bsl.assert_not_called()


class Boot(Execution):
    def evidence(self):
        snapshot = bytes(0xB0000)
        frozen = {'source_sha': op.SOURCE, 'capture_sha256': op.sha(snapshot), 'program_order': [0, 0xAC000],
                  'sector_sha256': {'0': op.sha(b'a'*8192), str(0xAC000): op.sha(b'b'*8192)}}
        digest = op.sha(op.canonical(frozen)); frozen['plan_sha256'] = digest
        op.durable(self.private, 'frozen-plan.json', frozen)
        op.durable(self.private, 'fresh-sparse-snapshot.bin', snapshot)
        events = [{'event': 'SECTOR_VERIFIED', 'address': a, 'sha256': frozen['sector_sha256'][str(a)]}
                  for a in frozen['program_order']]
        (self.private/'mutation-journal.jsonl').write_bytes(b''.join(op.canonical(v)+b'\n' for v in events))
        result = {'status': 'APP_AND_AC000_CRC_VERIFIED_STILL_IN_BSL',
                  'verification_scope': 'WRITTEN_SHA_PLUS_ALL88_ROM_CRC', 'written_sectors': [0, 0xAC000],
                  'nv_touched': False, 'ccfg_touched': False, 'reset_issued': False, 'automatic_rollback': False}
        op.durable(self.private, 'verified-write.json', {'operation_plan_sha256': 'pin',
            'frozen_plan_sha256': digest, 'journal_sha256': op.sha(op.read(self.private/'mutation-journal.jsonl')),
            'result': result})
        self.ha.boot_binding.return_value = 'button.slzb_06p7u_zigbee_restart'
        self.ha.inspect.return_value = {'id': 'two', 'image': op.IMAGE, 'running': True}
        p = patch.object(op.time, 'sleep', Mock()); p.start(); self.addCleanup(p.stop)
        p = patch.object(Path, 'is_char_device', Mock(return_value=True)); p.start(); self.addCleanup(p.stop)

    def test_no_result_never_boots(self):
        with self.assertRaisesRegex(op.Hold, 'INPUT_FILE'): op.boot(self.package, 'pin', self.ha)
        self.ha.restart_radio.assert_not_called()

    def test_changed_journal_never_boots(self):
        self.evidence(); (self.private/'mutation-journal.jsonl').write_bytes(b'{}\n')
        with self.assertRaisesRegex(op.Hold, 'WRITE_RECEIPT_PIN'): op.boot(self.package, 'pin', self.ha)
        self.ha.restart_radio.assert_not_called()

    def test_hold_after_write_never_boots(self):
        self.evidence(); op.durable(self.private, 'hold.json', {})
        with self.assertRaisesRegex(op.Hold, 'WRITE_NOT_VERIFIED'): op.boot(self.package, 'pin', self.ha)
        self.ha.restart_radio.assert_not_called()

    def test_unknown_boot_ack_is_never_repeated(self):
        self.evidence(); self.ha.restart_radio.side_effect = TimeoutError()
        with self.assertRaises(TimeoutError): op.boot(self.package, 'pin', self.ha)
        self.ha.owner_action.assert_not_called(); self.assertTrue((self.private/'boot-intent.json').exists())
        with self.assertRaisesRegex(op.Hold, 'BOOT_CONSUMED'): op.boot(self.package, 'pin', self.ha)
        self.ha.restart_radio.assert_called_once()

    def test_unknown_start_ack_is_never_repeated(self):
        self.evidence(); self.ha.owner_action.side_effect = TimeoutError()
        with self.assertRaises(TimeoutError): op.boot(self.package, 'pin', self.ha)
        self.assertTrue((self.private/'start-intent.json').exists())
        with self.assertRaisesRegex(op.Hold, 'BOOT_CONSUMED'): op.boot(self.package, 'pin', self.ha)
        self.ha.owner_action.assert_called_once_with('start')

    def test_verified_boot_starts_only_pinned_owner_once(self):
        self.evidence(); result = op.boot(self.package, 'pin', self.ha)
        self.assertEqual(result['status'], 'FLASH_VERIFIED_HOST_STARTED_PENDING_SERVING')
        self.ha.restart_radio.assert_called_once(); self.ha.owner_action.assert_called_once_with('start')
        self.assertTrue((self.private/'started-pending-serving.json').exists())


class PreBslRestore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.root.chmod(0o700)
        self.data = self.root/'data'; self.data.mkdir()
        for n in ('database.db', 'coordinator_backup.json'): (self.data/n).write_bytes(b'unchanged')
        self.failed = self.root/'failed'; self.failed.mkdir(mode=0o700)
        self.plan = {'source': op.SOURCE, 'installed': op.INSTALLED, 'package_pin': op.FAILED_PACKAGE_PIN,
                     'candidate_pin': op.CANDIDATE_PIN, 'input_pin': 'input', 'management_sha256': 'board',
                     'scope': 'CHANGED_APP_AND_PAIRED_AC000_PRESERVE_NV_CCFG', 'owner': {'id': 'old'}}
        self.pin = op.sha(op.canonical(self.plan))
        for n, v in {'plan.json': self.plan, 'reader-baseline-check.json': {},
                     'owner-backup-before-stop.json': {}, 'execute-intent.json': {'plan_sha256': self.pin},
                     'hold.json': {'error_type': 'TimeoutError', 'automatic_retry': False,
                                   'automatic_boot': False, 'plan_sha256': self.pin}}.items():
            op.durable(self.failed, n, v)
        self.ha = Mock(); self.ha.management.return_value = 'board'
        self.ha.info.return_value = {'state': 'error', 'version': '0.2.1-068ae05e9f9a', 'build': False}
        self.ha.inspect.return_value = {'id': 'new', 'image': op.IMAGE, 'running': True}
        for name, v in [('FAILED_PRIVATE', self.failed), ('DATA', self.data),
                        ('sealed_tree', Mock()), ('candidate', Mock()),
                        ('run', Mock(return_value=op.canonical([{'Id': op.IMAGE}])) )]:
            p = patch.object(op, name, v); p.start(); self.addCleanup(p.stop)

    def restore(self): return op.restore_pre_bsl(self.root, 'new-package', self.pin, self.ha)

    def test_only_unchanged_host_started_without_reset_or_stop(self):
        self.assertEqual(self.restore()['source'], op.INSTALLED)
        self.ha.owner_action.assert_called_once_with('start'); self.ha.restart_radio.assert_not_called()
        self.assertTrue((self.failed/'hold.json').exists())
        with self.assertRaisesRegex(op.Hold, 'RESTORE_CONSUMED'): self.restore()
        self.ha.owner_action.assert_called_once()

    def test_any_bsl_or_unknown_file_rejects(self):
        op.durable(self.failed, 'bsl-entry-intent.json', {})
        with self.assertRaisesRegex(op.Hold, 'RESTORE_NOT_PRE_BSL'): self.restore()
        self.ha.owner_action.assert_not_called()

    def test_wrong_plan_rejects(self):
        self.pin = 'wrong'
        with self.assertRaisesRegex(op.Hold, 'RESTORE_PROVENANCE'): self.restore()
        self.ha.owner_action.assert_not_called()

    def test_competing_holder_rejects(self):
        self.ha.proof.side_effect = op.Hold('not-quiescent')
        with self.assertRaises(op.Hold): self.restore()
        self.ha.owner_action.assert_not_called()

    def test_changed_image_rejects(self):
        op.run.return_value = op.canonical([{'Id': 'foreign'}])
        with self.assertRaisesRegex(op.Hold, 'RESTORE_IMAGE'): self.restore()
        self.ha.owner_action.assert_not_called()

    def test_unknown_start_response_cannot_replay(self):
        self.ha.owner_action.side_effect = TimeoutError()
        with self.assertRaises(TimeoutError): self.restore()
        with self.assertRaisesRegex(op.Hold, 'RESTORE_CONSUMED'): self.restore()
        self.ha.owner_action.assert_called_once_with('start')

    def quiescent(self):
        self.ha.owner_action.side_effect = TimeoutError()
        with self.assertRaises(TimeoutError): self.restore()
        r = op.load(self.failed/'restore-intent.json')
        r['package_pin'] = 'f9f6b06e08579f0532c6be9524ab5c8263cb13ee470188d2fb951c3a685fe16a'
        (self.failed/'restore-intent.json').write_bytes(op.canonical(r))
        return {'id': 'new', 'image': op.IMAGE, 'running': False,
                'started_at': op.datetime.datetime.now(op.datetime.timezone.utc).isoformat()}

    def test_quiescent_provenance_is_bound_and_requires_stopped_owner(self):
        owner = self.quiescent()
        self.assertEqual(len(op.quiescent_provenance(self.ha, owner)), 64)
        with self.assertRaisesRegex(op.Hold, 'QUIESCENT_OWNER'):
            op.quiescent_provenance(self.ha, dict(owner, running=True))

    def test_quiescent_provenance_rejects_any_bsl_artifact(self):
        owner = self.quiescent(); op.durable(self.failed, 'bsl-entry-intent.json', {})
        with self.assertRaisesRegex(op.Hold, 'QUIESCENT_NOT_PRE_BSL'):
            op.quiescent_provenance(self.ha, owner)


if __name__ == '__main__': unittest.main()
