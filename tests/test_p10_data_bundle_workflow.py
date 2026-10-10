"""Synthetic fixtures only: private household records must never enter Git."""
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'deploy'))
import p10_data_bundle as bundle
import p10_migration_workflow as workflow

CONFIG = b'serial:\n  port: /dev/serial/by-id/usb-SONOFF-fake\n  adapter: ember\n  baudrate: 115200\n  rtscts: false\nchannel: 11\n'
OPTIONS = {'serial': {'port': '/dev/serial/by-id/usb-SONOFF-fake', 'adapter': 'ember',
                      'baudrate': 115200, 'rtscts': False},
           'socat': {'enabled': False}, 'mqtt': {'password': 'PRIVATE_TEST_FAKE'}}
DB = '\n'.join(json.dumps({'type': role, 'ieeeAddr': f'0x{index:016x}', 'lastSeen': 1})
               for index, role in enumerate(('Coordinator', 'Router', 'EndDevice'))).encode()
BACKUP = json.dumps({'coordinator_ieee': '0000000000000000', 'channel': 11,
                     'network_key': {'frame_counter': 8, 'key': 'PRIVATE_FAKE'},
                     'metadata': {'format': 'zigpy/open-coordinator-backup', 'version': 1},
                     'stack_specific': {'ezsp': {}}, 'pan_id': 1,
                     'extended_pan_id': 'fake', 'devices': []}).encode()


def make_bundle(path, mode='hot', corrupt=False):
    payloads = {'data/configuration.yaml': CONFIG, 'data/database.db': DB,
                'data/coordinator_backup.json': BACKUP,
                'data/external_converters/custom.js': b'// synthetic converter',
                'meta/addon_options.private.json': json.dumps({'addon_slug': bundle.ADDON,
                                                               'options': OPTIONS}).encode()}
    records = {name: {'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}
               for name, payload in payloads.items()}
    with zipfile.ZipFile(path, 'w') as archive:
        for name, raw in payloads.items():
            archive.writestr(name, raw + (b'bad' if corrupt and name.endswith('custom.js') else b''))
        archive.writestr(bundle.MANIFEST_NAME, json.dumps({'format':'p10-z2m-data-bundle-v1',
                                                           'mode':mode, 'app_stopped_throughout_capture':mode=='cold', 'files':records}))


class BundleTests(unittest.TestCase):
    def test_full_archive_verification_and_hot_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'data.zip'
            make_bundle(path)
            with patch.object(bundle, 'private_target', lambda p: Path(p)):
                outcome = bundle.verify(path)
            self.assertTrue(outcome['integrity_pass'])
            self.assertFalse(outcome['cold_consistent'])
            self.assertEqual(outcome['application_file_count'], 4)
            self.assertTrue(outcome['addon_options_included'])

    def test_corruption_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'data.zip'
            make_bundle(path, corrupt=True)
            with patch.object(bundle, 'private_target', lambda p: Path(p)):
                with self.assertRaises(ValueError): bundle.verify(path)

    def test_duplicate_archive_member_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'data.zip'
            make_bundle(path)
            with zipfile.ZipFile(path, 'a') as archive:
                archive.writestr('data/database.db', DB)
            with patch.object(bundle, 'private_target', lambda p: Path(p)):
                with self.assertRaises(ValueError): bundle.verify(path)

    def test_cold_capture_refuses_started_addon(self):
        fake = type('HA', (), {'close': lambda self: None})()
        with patch.object(bundle, 'private_target', lambda p: Path(p)), \
             patch.object(bundle, 'load_ha', return_value=fake), \
             patch.object(bundle, 'addon_info', return_value={'state':'started'}):
            with tempfile.TemporaryDirectory() as tmp:
                with self.assertRaisesRegex(RuntimeError, 'not stopped or error'):
                    bundle.capture(Path(tmp)/'fresh.zip', 'cold')

    def test_log_folder_does_not_exclude_nonlog_custom_data(self):
        self.assertIn('log', bundle.SKIP_TOPLEVEL)
        self.assertNotIn('external_converters', bundle.SKIP_TOPLEVEL)


class WorkflowTests(unittest.TestCase):
    def test_matching_live_two_layer_serial(self):
        import yaml
        summary = workflow.inspect_effective_serial(yaml.safe_load(CONFIG), OPTIONS)
        self.assertTrue(summary['addon_serial_matches_yaml'])
        new = workflow.render_addon_options(OPTIONS, '192.168.50.22', 7638)
        self.assertEqual(new['serial']['adapter'], 'zstack')
        self.assertEqual(new['serial']['port'], 'tcp://192.168.50.22:7638')
        self.assertEqual(new['mqtt'], OPTIONS['mqtt'])
        self.assertEqual(OPTIONS['serial']['adapter'], 'ember')

    def test_conflicting_override_and_socat_refused(self):
        import yaml
        other = json.loads(json.dumps(OPTIONS))
        other['serial']['port'] = 'tcp://192.168.1.2:1234'
        with self.assertRaisesRegex(ValueError,'disagreement'):
            workflow.inspect_effective_serial(yaml.safe_load(CONFIG), other)
        other = json.loads(json.dumps(OPTIONS)); other['socat']['enabled'] = True
        with self.assertRaisesRegex(ValueError,'socat'):
            workflow.inspect_effective_serial(yaml.safe_load(CONFIG), other)

    def test_coordinator_ieee_matches_direct_or_reversed(self):
        import yaml
        observed = workflow.identity_checks(DB, BACKUP, yaml.safe_load(CONFIG))
        self.assertTrue(observed['source_ieee_records_agree'])
        self.assertEqual(observed['source_device_count'], 3)
        edited = json.loads(BACKUP); edited['coordinator_ieee'] = '0011223344556677'
        with self.assertRaisesRegex(ValueError,'IEEE mismatch'):
            workflow.identity_checks(DB, json.dumps(edited).encode(), yaml.safe_load(CONFIG))

    def test_source_only_stage_without_full_ha_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); archive = root/'src.zip'; output = root/'stage'
            make_bundle(archive, mode='cold')
            with patch.object(bundle, 'private_target', lambda p: Path(p)), \
                 patch.object(workflow, 'private_target', lambda p: Path(p)):
                result = workflow.stage(archive, output)
                self.assertEqual(result['status'], 'SOURCE_RECOVERY_STAGED')
                self.assertEqual((output/'rollback_configuration.yaml').read_bytes(), CONFIG)
                self.assertEqual(result['source']['source_device_count'], 3)
                self.assertFalse((output/'target_configuration.yaml').exists())
                with self.assertRaises(FileExistsError): workflow.stage(archive, output)

    def test_post_assessment_does_not_invent_functional_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); archive = root/'post.zip'; make_bundle(archive)
            baseline = root/'baseline.json'; baseline.write_text(json.dumps({'baseline':
                workflow.parse_database(DB)}))
            with patch.object(bundle, 'private_target',lambda p:Path(p)), \
                 patch.object(workflow, 'private_target',lambda p:Path(p)):
                outcome = workflow.assess(baseline, archive, '2026-09-24T09:00:00+02:00')
            self.assertEqual(outcome['summary']['functional_acceptance'],'NOT_PROVEN')
            self.assertFalse(outcome['summary']['outbound_command_delivery_tested'])


if __name__ == '__main__':
    unittest.main()
