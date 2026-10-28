"""Hosted activation boundaries. No Supervisor/device access or radio client."""
import importlib.util,io,json,os,sys,unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).parent))
import p7u_post_web_activation as m

class Tests(unittest.TestCase):
 def test_unknown_routes_and_other_owners_cannot_be_started(self):
  for route in ['/addons/'+m.t.ORIGINAL+'/start','/addons/local_p7u_r4_fallback/start','/addons/'+m.TARGET+'/restart','/addons/'+m.TARGET+'/security','/core/api/services/button/press','/api2?action=6','https://foreign/']:
   for body in [None,{}]:
    with self.subTest(route=route,body=body),patch.object(m.t,'build_opener') as http:
     with self.assertRaises(RuntimeError):m.api(route,body)
     http.assert_not_called()
 def test_even_known_routes_reject_unexpected_mutation_bodies(self):
  with patch.object(m.t,'build_opener') as http:
   for body in [{'protected':False},{'options':{}},{'image':'other'}]:
    with self.assertRaises(RuntimeError):m.api('/addons/'+m.TARGET+'/start',body)
   http.assert_not_called()
 def test_config_transform_accepts_only_exact_pinned_config_and_one_sidecar_change(self):
  raw=b'boot: manual_only\nenvironment:\n P7U_B4_COLLECTOR: 1\n P7U_APPROVED_DB_MANIFEST: /config/zigbee2mqtt/.p7u-approved.json\nimage: localhost:50144/p7u-r4-diagnostic\n'
  with patch.object(m,'CONFIG_SHA',m.sha(raw)):
   new=m.transformed_config(raw)
   self.assertEqual(new.replace(str(m.MANIFEST).encode(),b'/config/zigbee2mqtt/.p7u-approved.json'),raw)
   for changed in [raw+b' ',raw.replace(b'manual_only',b'auto'),raw.replace(b'diagnostic',b'fallback')]:
    with self.assertRaises(RuntimeError):m.transformed_config(changed)
 def test_stale_plan_cannot_create_root_transfer_image_or_start_service(self):
  with TemporaryDirectory() as d,patch.object(m,'ROOT',Path(d)/'new'),patch.object(m,'preflight',return_value={'current':'value'}),patch.object(m,'receive_archive') as transfer,patch.object(m,'api') as api:
   with self.assertRaisesRegex(RuntimeError,'STALE_ACTIVATION_PLAN'):m.activate('0'*64,b'config',io.BytesIO())
   self.assertFalse(m.ROOT.exists());transfer.assert_not_called();api.assert_not_called()
 def test_consumed_operation_or_approval_denies_replay_before_other_reads(self):
  for consumed in ['root','sidecar']:
   with TemporaryDirectory() as d,patch.object(m,'ROOT',Path(d)/'root'),patch.object(m,'MANIFEST',Path(d)/'manifest'),patch.object(m,'regular') as read:
    if consumed=='root':m.ROOT.mkdir()
    else:m.MANIFEST.write_text('{}')
    with self.assertRaisesRegex(RuntimeError,'ALREADY_CONSUMED'):m.preflight(b'config')
    read.assert_not_called()
 def test_archive_integrity_failure_has_no_docker_or_service_side_effect(self):
  with TemporaryDirectory() as d,patch.object(m,'ROOT',Path(d)),patch.object(m,'event'),patch.object(m.t,'command') as command,patch.object(m,'api') as api:
   with self.assertRaisesRegex(RuntimeError,'ARCHIVE_INTEGRITY'):m.receive_archive(io.BytesIO(b'wrong image'))
   command.assert_not_called();api.assert_not_called()
 def test_archive_write_is_exclusive_and_cannot_overwrite_prior_transfer(self):
  with TemporaryDirectory() as d,patch.object(m,'ROOT',Path(d)),patch.object(m,'event'):
   p=m.ROOT/'image.docker.tar';p.write_bytes(b'prior')
   with self.assertRaises(FileExistsError):m.receive_archive(io.BytesIO(b'new'))
   self.assertEqual(p.read_bytes(),b'prior')
 def test_consumed_start_intent_cannot_be_overwritten(self):
  with TemporaryDirectory() as d,patch.object(m,'ROOT',Path(d)):
   m.event('start-debug-once',{'image_id':m.IMAGE})
   before=(m.ROOT/'start-debug-once.intent.json').read_bytes()
   with self.assertRaises(FileExistsError):m.event('start-debug-once')
   self.assertEqual((m.ROOT/'start-debug-once.intent.json').read_bytes(),before)
 def test_registry_rejects_privilege_mounts_and_external_bind(self):
  good={'Id':'old','Image':'sha256:fixed','Config':{'Labels':{'p7u.issue':'144'},'Image':'registry@sha256:'+'a'*64},'State':{'Running':False},'HostConfig':{'PortBindings':{'5000/tcp':[{'HostIp':'127.0.0.1','HostPort':'50144'}]},'Privileged':False,'Binds':None,'Devices':[],'RestartPolicy':{'Name':'no'}}}
  for field,value in [('Privileged',True),('Binds',['/:/host']),('Devices',[{'PathOnHost':'/dev/ttyACM0'}]),('PortBindings',{'5000/tcp':[{'HostIp':'0.0.0.0','HostPort':'50144'}]})]:
   c=json.loads(json.dumps(good));c['HostConfig'][field]=value
   with patch.object(m,'inspect',return_value=c):
    with self.assertRaisesRegex(RuntimeError,'REGISTRY_POLICY'):m.registry()

if __name__=='__main__':unittest.main()
