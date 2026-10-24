"""Hosted-only adversarial controls; no live HA, registry or radio operations."""
import base64
from contextlib import nullcontext
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,ROOT/'host/recovery'/file)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod
m=load('guard_deploy','deploy_native_guard_024.py')
r=load('guard_install','native_guard_install.py')


def payload():
    sha='a'*40;version='0.2.4-'+sha[:12]
    config=('version: '+version+'\nimage: localhost:50146/p7u-native-guard\n').encode()
    return {'mode':'plan','expected_plan_hash':'','config_b64':base64.b64encode(config).decode(),
            'release':{'schema':'p7u-native-guard-release-v1','source_sha':sha,'version':version,
                       'image_reference':'localhost:50146/p7u-native-guard:'+version,'image_id':'sha256:'+'b'*64,
                       'files':{'config.yaml':hashlib.sha256(config).hexdigest()},'physical_action':False,'installed':False}}


class Tests(unittest.TestCase):
    def setUp(self):
        p=patch.object(r,'deployment_lock',side_effect=lambda:nullcontext())
        p.start();self.addCleanup(p.stop)

    def test_only_known_guard_mutations_accepted_before_any_http(self):
        for target in ['/addons/45df7312_zigbee2mqtt/start','/addons/local_p7u_r4_native_host/start',
                       '/core/api/services/button/press','/addons/local_p7u_recovery/security','/api2']:
            with self.subTest(target=target),patch.object(r,'urlopen') as http:
                with self.assertRaisesRegex(RuntimeError,'UNAPPROVED_MUTATION_TARGET'):r.api(target,{})
                http.assert_not_called()

    def test_registry_reference_and_version_are_source_bound(self):
        for field,value in [('image_reference','evil/image:latest'),('source_sha','../arbitrary'),('version','latest')]:
            p=payload();p['release'][field]=value
            with self.subTest(field=field),self.assertRaises(AssertionError):r.validate_payload(p)

    def test_changed_configuration_is_rejected(self):
        p=payload();p['config_b64']=base64.b64encode(b'full_access: true').decode()
        with self.assertRaises(AssertionError):r.validate_payload(p)

    def test_readonly_plan_has_no_copy_import_lifecycle_or_receipt_write(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(r,'ROOT',Path(directory)), \
             patch.object(r,'snapshot',return_value={'guard':'pinned','options_hash':'c'*64}), \
             patch.object(r,'command') as command,patch.object(r,'unique') as write,patch.object(r,'api') as api:
            result=r.install(payload())
        self.assertEqual(result['status'],'GUARD_ONLY_PLAN')
        self.assertEqual(len(result['plan_hash']),64)
        command.assert_not_called();write.assert_not_called();api.assert_not_called()

    def test_changed_plan_is_rejected_before_any_mutation(self):
        p=payload();p.update(mode='apply',expected_plan_hash='f'*64)
        with tempfile.TemporaryDirectory() as directory,patch.object(r,'ROOT',Path(directory)), \
             patch.object(r,'snapshot',return_value={'guard':'pinned'}), \
             patch.object(r,'command') as command,patch.object(r,'unique') as write:
            with self.assertRaisesRegex(RuntimeError,'STALE_PLAN_HASH'):r.install(p)
        command.assert_not_called();write.assert_not_called()

    def test_global_prior_intent_blocks_a_new_source_directory(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(r,'ROOT',Path(directory)), \
             patch.object(r,'snapshot') as snapshot:
            (Path(directory)/'active-deployment.json').write_text('{}')
            with self.assertRaises(AssertionError):r.install(payload())
        snapshot.assert_not_called()

    def test_snapshot_reports_hashes_instead_of_private_options(self):
        policy={'enabled':False,'dry_run':True,'serial_owner_approved':False,'allow_private_http_fallback':False,
                'notify_on_confirmed_hang':True,'esp_restart_entity':m.EXPECTED_CORE,'zigbee_restart_entity':m.EXPECTED_RADIO,
                'password':'never disclose this'}
        def api(path):
            if r.GUARD in path:return {'state':'started','version':'0.2.3','boot':'manual','watchdog':False,'options':policy}
            return {'state':'error','version':'2.14.0-1','boot':'manual','watchdog':False,'options':{'password':'never disclose this'}}
        with patch.object(r,'api',side_effect=api),patch.object(r,'inspect',return_value={'id':'pinned','running':True}):
            result=r.snapshot()
        self.assertNotIn('never disclose this',json.dumps(result))
        self.assertEqual(result['options_hash'],r.digest(policy))

    def test_tampered_image_bytes_fail_release_verification(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary)/'release';directory.mkdir()
            p=payload()['release'];p['runtime_files']={name:'c'*64 for name in m.MODULES}
            values={'IMAGE_ID.txt':b'sha256:'+b'b'*64,'image.docker.tar':b'hosted image',
                    'config.yaml':b'manual configuration','deploy_native_guard_024.py':Path(m.__file__).read_bytes(),
                    'native_guard_install.py':Path(r.__file__).read_bytes()}
            for name,data in values.items():(directory/name).write_bytes(data)
            p['files']={name:hashlib.sha256(data).hexdigest() for name,data in values.items()}
            (directory/'RELEASE.json').write_text(json.dumps(p))
            checks={'check_runs':[{'name':name,'conclusion':'success'} for name in ['Policy and one-shot journal regressions','unittest','release']]}
            with patch.object(m,'ARTIFACT_ROOT',Path(temporary)),patch.object(m.subprocess,'check_output',return_value=json.dumps(checks)):
                self.assertEqual(m.verify_release(directory)[1]['source_sha'],'a'*40)
                (directory/'image.docker.tar').write_bytes(b'tampered')
                with self.assertRaisesRegex(RuntimeError,'ARTIFACT_HASH_CHANGED'):m.verify_release(directory)

    def previous(self, directory):
        previous=directory/r.PREVIOUS_SOURCE;previous.mkdir()
        intent={'plan_hash':r.PREVIOUS_PLAN,'plan':{'source_sha':r.PREVIOUS_SOURCE,'image_id':r.PREVIOUS_IMAGE}}
        result={'status':'GUARD_PREBUILT_DEPLOYED_UNARMED','source_sha':r.PREVIOUS_SOURCE,
            'image_id':r.PREVIOUS_IMAGE,'version':'0.2.4-'+r.PREVIOUS_SOURCE[:12],'plan_hash':r.PREVIOUS_PLAN,
            'options_preserved':True,'ledger_preserved':True,'zigbee_hosts_unchanged':True,'resets_enabled':False,
            'container_id':'qualified-old-container'}
        (directory/'active-deployment.json').write_text(json.dumps(intent))
        (previous/'receipt.json').write_text(json.dumps(result))
        return previous

    def test_only_exact_completed_predecessor_is_admitted(self):
        with tempfile.TemporaryDirectory() as temporary,patch.object(r,'ROOT',Path(temporary)):
            path=self.previous(Path(temporary))
            result=r.verified_previous()
            self.assertEqual(result['guard_container_id'],'qualified-old-container')
            p=path/'receipt.json';d=json.loads(p.read_text());d['status']='HOLD';p.write_text(json.dumps(d))
            with self.assertRaises(AssertionError):r.verified_previous()

    def test_explicit_upgrade_keeps_old_intent_and_hash_binds_its_receipt(self):
        with tempfile.TemporaryDirectory() as temporary,patch.object(r,'ROOT',Path(temporary)), \
             patch.object(r,'snapshot',return_value={'guard':'known-current','options_hash':'c'*64}), \
             patch.object(r,'command') as command,patch.object(r,'unique') as write:
            path=self.previous(Path(temporary));old=(Path(temporary)/'active-deployment.json').read_bytes()
            p=payload();p['reconcile_previous']=r.PREVIOUS_SOURCE
            result=r.install(p)
            self.assertEqual(result['plan']['reconciled_previous']['source_sha'],r.PREVIOUS_SOURCE)
            self.assertEqual((Path(temporary)/'active-deployment.json').read_bytes(),old)
            (Path(temporary)/('active-upgrade-from-'+r.PREVIOUS_SOURCE[:12]+'.json')).write_text('{}')
            with self.assertRaises(AssertionError):r.install(p)
            command.assert_not_called();write.assert_not_called()

    def test_unknown_predecessor_or_wrong_running_image_is_not_an_upgrade(self):
        p=payload();p['reconcile_previous']='f'*40
        with self.assertRaises(AssertionError):r.validate_payload(p)
        p['reconcile_previous']=r.PREVIOUS_SOURCE
        with tempfile.TemporaryDirectory() as temporary,patch.object(r,'ROOT',Path(temporary)):
            self.previous(Path(temporary));q=Path(temporary)/r.PREVIOUS_SOURCE/'receipt.json'
            d=json.loads(q.read_text());d['image_id']='sha256:'+'0'*64;q.write_text(json.dumps(d))
            with self.assertRaises(AssertionError):r.verified_previous()


if __name__=='__main__':unittest.main()
