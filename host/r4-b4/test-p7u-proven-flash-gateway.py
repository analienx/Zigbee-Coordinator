"""Hosted fixed-target gateway checks; no device or Supervisor access."""
import io,sys,unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).parent))
import p7u_proven_flash_gateway as m
class Tests(unittest.TestCase):
 def test_unknown_controls_never_reach_http(self):
  with patch.object(m.t,'build_opener') as http:
   for action in ['reset','factory','stock','flash','wifi','../boot']:
    with self.assertRaises(RuntimeError):m.fixed_vendor(action)
   for path,body in [('/addons/'+m.t.ORIGINAL+'/start',{}),('/addons/'+m.TARGET+'/restart',{}),('/addons/'+m.TARGET+'/start',{'image':'other'})]:
    with self.assertRaises(RuntimeError):m.control(path,body)
   http.assert_not_called()
 def test_stale_quiesce_plan_cannot_write_stop_or_request_backup(self):
  with TemporaryDirectory() as d,patch.object(m,'ROOT',Path(d)/'new'),patch.object(m,'preflight',return_value={'current':True}),patch.object(m.t,'fresh_backup') as backup,patch.object(m.t,'api') as api:
   with self.assertRaisesRegex(RuntimeError,'STALE_PROVEN_PLAN'):m.quiesce('0'*64)
   self.assertFalse(m.ROOT.exists());backup.assert_not_called();api.assert_not_called()
 def test_existing_operation_cannot_be_replayed(self):
  with TemporaryDirectory() as d,patch.object(m,'ROOT',Path(d)),patch.object(m.t,'snapshot') as snapshot:
   with self.assertRaisesRegex(RuntimeError,'OPERATION_ALREADY_EXISTS'):m.preflight()
   snapshot.assert_not_called()
 def test_stale_mode_plan_has_no_control_or_inspector_action(self):
  with patch.object(m,'phase_plan',return_value={'action':'ethernet'}),patch.object(m,'fixed_vendor') as change,patch.object(m.t,'zero_holders') as proof,patch.object(m.t,'intent') as intent:
   with self.assertRaisesRegex(RuntimeError,'STALE_PHASE_PLAN'):m.phase('ethernet','0'*64)
   change.assert_not_called();proof.assert_not_called();intent.assert_not_called()
 def test_failed_mode_change_is_consumed_without_retry(self):
  with TemporaryDirectory() as d,patch.object(m,'ROOT',Path(d)),patch.object(m,'phase_plan',return_value={'action':'ethernet'}),patch.object(m,'fixed_vendor',side_effect=TimeoutError) as change,patch.object(m.t,'zero_holders',return_value=[]),patch.object(m.t,'ROOT',Path(d)):
   result=m.phase('ethernet',m.sha(m.canonical({'action':'ethernet'})))
   self.assertEqual(result['status'],'AMBIGUOUS_NO_RETRY');self.assertEqual(change.call_count,1)
   self.assertTrue((Path(d)/'ethernet.intent.json').is_file())
 def test_mode_payload_preserves_hardware_usb_web_and_never_selects_wifi(self):
  class Response:
   def __enter__(self):return self
   def __exit__(self,*a):pass
   def read(self,n):return b'{}'
  for action,mode in [('ethernet','0'),('usb','2')]:
   with patch.object(m.t,'build_opener') as opener:
    opener.return_value.open.return_value=Response();m.fixed_vendor(action)
    request=opener.return_value.open.call_args.args[0]
    self.assertEqual(request.full_url,'http://192.168.50.59/settings/saveParams')
    self.assertEqual(request.data,('pageId=1&coordMode='+mode+'&keepWeb=on&oUsbMod=0').encode())
if __name__=='__main__':unittest.main()
