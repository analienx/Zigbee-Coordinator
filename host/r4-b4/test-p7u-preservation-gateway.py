"""Hosted-only gateway mutation boundaries; no HA or physical UART access."""
import base64
from contextlib import nullcontext
import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('preservation_gateway',Path(__file__).with_name('p7u_preservation_gateway.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def payload(mode='plan'):
    source='a'*40;config=b'synthetic pinned configuration'
    return {'mode':mode,'expected_plan_hash':'','config_b64':base64.b64encode(config).decode(),
        'release':{'schema':'p7u-preservation-release-v1','source_sha':source,'version':'0.1.0-'+source[:12],
        'image_reference':'localhost:50148/p7u-preservation:0.1.0-'+source[:12],'image_id':'sha256:'+'b'*64,
        'entrypoint':m.ENTRY,'config_sha256':m.sha(config),'archive_sha256':'c'*64,'audited_filesystem_matches':True,'stty_arm64_verified':True,'radio_reset':False,'network_startup':False,'nv_write':False}}


class Tests(unittest.TestCase):
    def test_original_lifecycle_buttons_flash_and_arbitrary_posts_are_rejected(self):
        for path in ['/addons/45df7312_zigbee2mqtt/start','/addons/local_p7u_r4_native_host/start','/core/api/services/button/press',
                     '/addons/'+m.SLUG+'/security','/addons/foreign/start']:
            with self.subTest(path=path),patch.object(m,'build_opener') as http:
                with self.assertRaisesRegex(RuntimeError,'UNAPPROVED_HTTP_MUTATION'):m.api(path,{})
                http.assert_not_called()

    def test_unqualified_role_or_source_is_refused(self):
        for field,value in [('entrypoint',['/docker-entrypoint.sh']),('image_reference','foreign/image:latest'),('source_sha','../x'),('network_startup',True)]:
            p=payload();p['release'][field]=value
            with self.subTest(field=field),self.assertRaises(RuntimeError):m.validate(p['release'],base64.b64decode(p['config_b64']))

    def test_plan_has_no_mutations_or_receipt_write(self):
        with TemporaryDirectory() as d,patch.object(m,'ROOT',Path(d)/'absent'),patch.object(m,'lock',side_effect=lambda:nullcontext()), \
             patch.object(m,'snapshot',return_value={'database_sha256':'d'*64}),patch.object(m,'unique') as write,patch.object(m,'command') as command:
            result=m.remote(payload())
            self.assertEqual(result['status'],'PRESERVATION_PLAN');self.assertEqual(len(result['plan_hash']),64)
            write.assert_not_called();command.assert_not_called()

    def test_staging_consumed_once_and_changed_plan_never_creates_authority(self):
        with TemporaryDirectory() as d,patch.object(m,'ROOT',Path(d)/'stage'),patch.object(m,'lock',side_effect=lambda:nullcontext()), \
             patch.object(m,'snapshot',return_value={'database_sha256':'d'*64}):
            p=payload();plan=m.remote(p);p.update(mode='stage',expected_plan_hash=plan['plan_hash'])
            self.assertEqual(m.remote(p)['status'],'STAGED_NO_DEVICE_ACTION')
            self.assertFalse((m.ROOT/'authority.intent.json').exists())
            with self.assertRaisesRegex(RuntimeError,'DIRECTORY_EXISTS_NO_REPLAY'):m.remote(p)

    def test_bad_stage_hash_is_rejected_before_directory_creation(self):
        with TemporaryDirectory() as d,patch.object(m,'ROOT',Path(d)/'stage'),patch.object(m,'lock',side_effect=lambda:nullcontext()), \
             patch.object(m,'snapshot',return_value={}):
            p=payload('stage');p['expected_plan_hash']='f'*64
            with self.assertRaisesRegex(RuntimeError,'STALE_PLAN'):m.remote(p)
            self.assertFalse(m.ROOT.exists())

    def test_existing_probe_root_is_never_overwritten_or_new_incident_created(self):
        with TemporaryDirectory() as d,patch.object(m,'ROOT',Path(d)),patch.object(m,'lock',side_effect=lambda:nullcontext()), \
             patch.object(m,'snapshot') as read:
            (m.ROOT/'sentinel').write_text('unchanged')
            with self.assertRaisesRegex(RuntimeError,'DIRECTORY_EXISTS_NO_REPLAY'):m.remote(payload())
            read.assert_not_called();self.assertEqual((m.ROOT/'sentinel').read_text(),'unchanged')


if __name__=='__main__':unittest.main()
