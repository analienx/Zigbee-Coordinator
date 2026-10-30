"""Offline negative gates for a distinct, no-write instrumented ROM operation."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import time
import types
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

FILE=Path(__file__).resolve().parents[1]/"host/flash/p7u_v6_instrumented_rom_once.py"
import sys
sys.path.insert(0,str(FILE.parent))
spec=importlib.util.spec_from_file_location("p7u_v6_instrumented_rom_once",FILE)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class Hold(Exception):pass

class Tests(unittest.TestCase):
 def setUp(self):
  tmp=tempfile.TemporaryDirectory()
  self.addCleanup(tmp.cleanup)
  self.root=Path(tmp.name)
  self.ha=MagicMock()
  self.old={"source":module.V6,"host":module.HOST,"image":module.IMAGE,
   "scope":"ONE_USB_OPEN_FIRST_ROM_READONLY_SECURITY_APP_BOOT_AND_HOST_ONCE",
   "flash_writes":0,"nv_writes":0,"ccfg_writes":0,
   "host_starts":1,"radio_boots":1,"rom_entries":1,
   "crc32":{"0":0,"704512":0,"712704":0}}
  self.ns={"PRIVATE":self.root,
           "need":lambda condition,why:condition or self.hold(why),
           "canonical":lambda x:json.dumps(x,sort_keys=True,separators=(',',':')).encode(),
           "sha":lambda b:hashlib.sha256(b).hexdigest(),
           "load":lambda p:json.loads(p.read_bytes()),
           "durable":self.durable,"private_root":lambda p:p.is_dir() or self.hold("PRIVATE_ROOT")}
  self.mk=patch.object(module,"evidence",return_value=(self.old,object(),()))
  self.mk.start();self.addCleanup(self.mk.stop)
 @staticmethod
 def hold(why):raise Hold(why)
 def durable(self,root,name,value):
  with (root/name).open("xb") as f:
   f.write(value if isinstance(value,bytes) else self.ns["canonical"](value))
 def planned(self):
  p=module.plan(self.ns,self.root,"new-package","write-pin",self.ha)
  self.assertEqual(p["status"],"INSTRUMENTED_ROM_PLAN_READY_NO_LIVE_EFFECTS")
  return p["pin"]
 def test_plan_cannot_reset(self):
  self.planned();self.ha.restart_radio.assert_not_called()
  self.ha.enter_bsl.assert_not_called()
 def test_second_plan_is_rejected(self):
  self.planned()
  with self.assertRaisesRegex(Hold,"FRESH_ROM_PREVIOUS_PLAN"):
   module.plan(self.ns,self.root,"new-package","write-pin",self.ha)
 def test_wrong_pin_halts_before_rom(self):
  self.planned()
  with self.assertRaisesRegex(Hold,"INSTRUMENTED_ROM_PLAN_PIN_TTL"):
   module.execute(self.ns,self.root,"new-package","write-pin","0"*64,self.ha)
  self.ha.enter_bsl.assert_not_called()
 def test_drift_halts_before_rom(self):
  pin=self.planned()
  self.old["image"]="sha256:unexpected"
  with self.assertRaisesRegex(Hold,"INSTRUMENTED_ROM_DRIFT"):
   module.execute(self.ns,self.root,"new-package","write-pin",pin,self.ha)
 def test_consumed_intent_cannot_replay(self):
  pin=self.planned()
  self.durable(self.root/module.ROOT,"execute-intent.json",{"consumed":True})
  with self.assertRaisesRegex(Hold,"INSTRUMENTED_ROM_ALREADY_CONSUMED"):
   module.execute(self.ns,self.root,"new-package","write-pin",pin,self.ha)
 def test_rom_failure_does_not_boot_or_start_host(self):
  pin=self.planned()
  with patch.object(module.rom,"_rom_observe",side_effect=RuntimeError("radio silent")) as f:
   with self.assertRaises(RuntimeError):
    module.execute(self.ns,self.root,"new-package","write-pin",pin,self.ha)
  self.assertEqual(f.call_count,1)
  self.ha.restart_radio.assert_not_called()
  self.ha.owner_action.assert_not_called()
  self.assertTrue((self.root/module.ROOT/"failure.json").is_file())
  with self.assertRaisesRegex(Hold,"INSTRUMENTED_ROM_ALREADY_CONSUMED"):
   module.execute(self.ns,self.root,"new-package","write-pin",pin,self.ha)
 def test_native_state9_failure_blocks_supervisor_start(self):
  pin=self.planned()
  self.old["board_sha256"]="expected-board"
  self.ha.management.return_value="expected-board"
  with patch.object(module.rom,"_rom_observe",new=AsyncMock()) as observe:
   with patch.object(module,"boot_and_verify_native_state9",
                     side_effect=Hold("STATE9_NOT_PROVEN")):
    with self.assertRaisesRegex(Hold,"STATE9_NOT_PROVEN"):
     module.execute(self.ns,self.root,"new-package","write-pin",pin,self.ha)
  observe.assert_awaited_once()
  self.ha.owner_action.assert_not_called()
  self.assertFalse((self.root/module.ROOT/"host-start-intent.json").exists())
  self.assertTrue((self.root/module.ROOT/"failure.json").exists())

 def test_boot_observer_requires_state9_and_closes_exclusive_port(self):
  radio=MagicMock()
  znp=MagicMock()
  znp._next.return_value=(0x41,0x80,bytes(6))
  def make_journal(path,source):
   path.write_bytes(b"")
   return MagicMock()
  transport=types.SimpleNamespace(FramedZnp=lambda port,source:znp,
                 PrivateEvidenceJournal=make_journal)
  self.ns.update({"StartupSerial":lambda:radio,
      "resume_pristine":lambda *args,**kwargs:{"status":"FAILED_STOP_NO_RETRY"}})
  with patch.dict("sys.modules",{"p7u_r4_startup_transport":transport}):
   with self.assertRaisesRegex(Hold,"INSTRUMENTED_ROM_NATIVE_STATE9_NOT_PROVEN"):
    module.boot_and_verify_native_state9(self.ns,self.root,self.ha)
  radio.close.assert_called_once()
  self.ha.restart_radio.assert_called_once()
  self.ha.owner_action.assert_not_called()
  self.assertFalse((self.root/"state9-accepted.json").exists())
  self.assertTrue((self.root/"app-boot-intent.json").exists())

 def test_state9_acceptance_is_written_before_host_can_start(self):
  radio=MagicMock()
  znp=MagicMock()
  znp._next.return_value=(0x41,0x80,bytes(6))
  def make_journal(path,source):
   path.write_bytes(b"")
   return MagicMock()
  def verify(znp,root,backup,evidence,source):
   self.assertEqual(source,module.V6)
   self.durable(root,"startup-result.json",{"status":"COORDINATOR_STATE9_MARKER_PASS"})
   return {"status":"COORDINATOR_STATE9_MARKER_PASS"}
  (self.root/"owner-backup-before-stop.json").write_bytes(b"{}")
  self.ns.update({"StartupSerial":lambda:radio,
      "resume_pristine":verify,
      "file_sha":lambda p:hashlib.sha256(p.read_bytes()).hexdigest()})
  transport=types.SimpleNamespace(FramedZnp=lambda port,source:znp,
                 PrivateEvidenceJournal=make_journal)
  with patch.dict("sys.modules",{"p7u_r4_startup_transport":transport}):
   result=module.boot_and_verify_native_state9(self.ns,self.root,self.ha)
  self.assertEqual(result["status"],"COORDINATOR_STATE9_MARKER_PASS")
  self.assertTrue(self.ns["load"](self.root/"state9-accepted.json")["state9"])
  radio.close.assert_called_once()
  self.ha.restart_radio.assert_called_once()

 def test_no_write_or_restore_primitives_in_module(self):
  text=FILE.read_text()
  self.assertNotIn("rom.erase",text)
  self.assertNotIn("rom.write",text)
  self.assertNotIn("restore_backup",text)
  self.assertIn("boot_and_verify_native_state9",text)
  self.assertIn("COORDINATOR_STATE9_MARKER_PASS",text)
  self.assertNotIn("rom._boot_observe_reset(ns,root,ha)",text)
  self.assertIn("rom._rom_observe",text)

if __name__=="__main__":unittest.main()
