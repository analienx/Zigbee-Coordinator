"""Hosted control-plane boundary tests. No device, MQTT or Supervisor access."""
import importlib.util,os,unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('trial',Path(__file__).with_name('p7u_web_flash_trial.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Tests(unittest.TestCase):
 def test_arbitrary_slzb_resets_modes_nvm_writes_and_flash_parameters_are_denied(self):
  for route in ['/api2?action=4&cmd=9','/api2?action=4&cmd=2','/api2?action=6&eraseNVM=1',m.FLASH_ROUTE+'&zbChipIdx=1','/esp32update','https://foreign/']:
   for method in ['GET','POST']:
    with self.subTest(route=route,method=method),patch.object(m,'build_opener') as http:
     with self.assertRaises(RuntimeError):m.request('slzb',route,method=method)
     http.assert_not_called()
 def test_normal_hosts_can_never_be_started_and_guard_security_cannot_be_changed(self):
  for route in ['/addons/'+m.ORIGINAL+'/start','/addons/local_p7u_r4_native_host/start','/addons/'+m.GUARD+'/security','/core/api/services/button/press']:
   with self.subTest(route=route),patch.object(m,'build_opener') as http:
    with self.assertRaises(RuntimeError):m.request('ha',route,method='POST',data=b'{}')
    http.assert_not_called()
 def test_get_cannot_disguise_unknown_supervisor_mutations(self):
  with patch.object(m,'build_opener') as http:
   with self.assertRaises(RuntimeError):m.request('ha','/addons/'+m.ORIGINAL+'/start')
   http.assert_not_called()
 def test_invalid_image_and_legacy_flat_bin_fail_before_any_live_snapshot(self):
  with patch.object(m,'snapshot') as read:
   for blob in [b'',b'\xff'*720896,b'\x01\x02SLZB'+b'\0'*204824]:
    with self.assertRaises(RuntimeError):m.apply('a'*64,blob)
   read.assert_not_called()
 def test_stale_plan_has_no_writes_or_http_mutations(self):
  with TemporaryDirectory() as d,patch.object(m,'ROOT',Path(d)/'absent'),patch.object(m,'image'),patch.object(m,'snapshot',return_value={'inventory':'fresh'}),patch.object(m,'unique') as write,patch.object(m,'api') as api:
   with self.assertRaisesRegex(RuntimeError,'STALE_PLAN'):m.apply('0'*64,b'image')
   write.assert_not_called();api.assert_not_called();self.assertFalse(m.ROOT.exists())
 def test_consumed_trial_is_not_replayed(self):
  with TemporaryDirectory() as d,patch.object(m,'ROOT',Path(d)),patch.object(m,'image'),patch.object(m,'snapshot') as read:
   with self.assertRaisesRegex(RuntimeError,'ALREADY_EXISTS_NO_REPLAY'):m.apply('a'*64,b'image')
   read.assert_not_called()
 def test_redirects_are_never_followed(self):
  with self.assertRaisesRegex(RuntimeError,'REDIRECT_DENIED'):m.NoRedirect().redirect_request(None,None,None,None,None,None)
 def test_continuation_rejects_any_previous_stop_upload_flash_or_consumed_continuation(self):
  for name in ['stop-original.intent.json','upload.intent.json','flash.intent.json','continue.intent.json','continuation.result.json']:
   with TemporaryDirectory() as d,patch.object(m,'ROOT',Path(d)),patch.object(m,'snapshot') as read:
    (Path(d)/name).write_text('{}')
    with self.assertRaisesRegex(RuntimeError,'PHYSICAL_PHASE_OR_CONTINUATION_ALREADY_CONSUMED'):m.continuation_plan()
    read.assert_not_called()
 def test_stale_continuation_plan_has_no_side_effects_or_backup_reissue(self):
  with patch.object(m,'image'),patch.object(m,'continuation_plan',return_value={'fresh_backup':'a'*64}),patch.object(m,'intent') as act,patch.object(m,'after_backup') as flash,patch.object(m,'fresh_backup') as backup:
   with self.assertRaisesRegex(RuntimeError,'STALE_CONTINUATION_PLAN'):m.continue_trial('0'*64,b'image')
   act.assert_not_called();flash.assert_not_called();backup.assert_not_called()
 def test_stopped_reconciliation_never_allows_a_second_upload_or_flash(self):
  for name in ['upload.intent.json','flash.intent.json','stop-reconcile.intent.json','stop-reconcile.result.json']:
   with TemporaryDirectory() as d,patch.object(m,'ROOT',Path(d)),patch.object(m,'board') as read:
    (Path(d)/name).write_text('{}')
    with self.assertRaisesRegex(RuntimeError,'UPLOAD_OR_FLASH_ALREADY_ATTEMPTED'):m.stopped_plan()
    read.assert_not_called()
 def test_changed_stop_plan_cannot_repeat_a_stop_or_reach_upload(self):
  with patch.object(m,'image'),patch.object(m,'stopped_plan',return_value={'stop':'done'}),patch.object(m,'intent') as write,patch.object(m,'api') as api,patch.object(m,'after_stop') as flash:
   with self.assertRaisesRegex(RuntimeError,'STALE_STOP_RECONCILIATION'):m.reconcile_stop('0'*64,b'image')
   write.assert_not_called();api.assert_not_called();flash.assert_not_called()

if __name__=='__main__':unittest.main()
