"""Negative, fully offline acceptance for the single-use V6 ROM recovery gates."""
import hashlib
import importlib.util
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/"host"/"flash"/"p7u_v6_rom_recovery.py"
spec=importlib.util.spec_from_file_location("p7u_v6_rom_recovery",SOURCE)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Hold(Exception):
    pass


class Cases(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home=Path(self.temp.name)
        self.owner={"id":"original","image":"sha256:qualified","running":False}
        self.evidence={"source":module.V6_SOURCE,"image":"sha256:qualified",
                       "owner":self.owner,"management_sha256":"device",
                       "write_plan_sha256":"sealed","failed_boot_sha256":"failed",
                       "written_receipt_sha256":"write","expected_crc32":{"0":1},
                       "scope":"USB_OPEN_FIRST_ROM_READONLY_APP_BOOT_PROTECTED_HOST_ONCE",
                       "firmware_writes":0,"nv_writes":0,"ccfg_writes":0,
                       "external_startup_requests":0}
        self.deps=(object(),object(),object(),object(),bytes(720896))
        self.ha=MagicMock()
        self.ha.inspect.return_value={"id":"new","image":"sha256:qualified","running":True}
        self.ns={"PRIVATE":self.home,"SOURCE":module.V6_SOURCE,
                 "IMAGE":"sha256:qualified","SERIAL":"/never/open/real/serial",
                 "Path":Path,
                 "need":lambda predicate,name: predicate or self.fail_hold(name),
                 "sealed_tree":lambda *args:None,
                 "canonical":lambda x:json.dumps(x,sort_keys=True,separators=(',',':')).encode(),
                 "sha":lambda b:hashlib.sha256(b).hexdigest(),
                 "durable":self.durable,
                 "load":lambda p:json.loads(p.read_text()),
                 "private_root":lambda p:p.is_dir() or self.fail_hold("PRIVATE_ROOT")}
        self.patcher=patch.object(module,"_checked",return_value=(self.home,self.owner,self.evidence,self.deps))
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    @staticmethod
    def fail_hold(name):
        raise Hold(name)

    def durable(self,root,name,value):
        with (root/name).open("xb") as out:
            out.write(value if isinstance(value,bytes) else self.ns["canonical"](value))

    def planned(self):
        r=module.plan(self.ns,self.home,"pin","sealed",self.ha)
        self.assertEqual(r["status"],"V6_ROM_RECOVERY_PLAN_READY")
        self.assertEqual(list((self.home/module.ROOT_NAME).glob("*"))[0].name,"plan.json")
        return r["recovery_plan_sha256"]

    def test_no_side_effects_in_plan(self):
        self.planned()
        self.ha.restart_radio.assert_not_called()
        self.ha.enter_bsl.assert_not_called()
        self.ha.owner_action.assert_not_called()

    def test_second_plan_fails_closed(self):
        self.planned()
        with self.assertRaises(Hold):
            module.plan(self.ns,self.home,"pin","sealed",self.ha)

    def test_wrong_pin_consumes_no_intent(self):
        self.planned()
        with self.assertRaisesRegex(Hold,"RECOVERY_PLAN_EXPIRED_OR_DRIFTED"):
            module.execute(self.ns,self.home,"pin","sealed","0"*64,self.ha)
        self.assertFalse((self.home/module.ROOT_NAME/"execute-intent.json").exists())

    def test_expired_plan_consumes_no_intent(self):
        pin=self.planned()
        with patch.object(module.time,"time",return_value=time.time()+module.MAX_PLAN_AGE_SECONDS+1):
            with self.assertRaisesRegex(Hold,"RECOVERY_PLAN_EXPIRED_OR_DRIFTED"):
                module.execute(self.ns,self.home,"pin","sealed",pin,self.ha)
        self.assertFalse((self.home/module.ROOT_NAME/"execute-intent.json").exists())

    def test_pending_intent_refuses_replay(self):
        pin=self.planned()
        self.durable(self.home/module.ROOT_NAME,"execute-intent.json",{"already":True})
        with self.assertRaisesRegex(Hold,"RECOVERY_PHASE_ALREADY_CONSUMED"):
            module.execute(self.ns,self.home,"pin","sealed",pin,self.ha)
        self.ha.enter_bsl.assert_not_called()

    def test_failed_rom_never_restarts_or_starts_host(self):
        pin=self.planned()
        with patch.object(module,"_rom_observe",new=AsyncMock(side_effect=TimeoutError("ROM unreachable"))):
            with self.assertRaises(TimeoutError):
                module.execute(self.ns,self.home,"pin","sealed",pin,self.ha)
        self.assertTrue((self.home/module.ROOT_NAME/"failure.json").exists())
        self.ha.restart_radio.assert_not_called()
        self.ha.owner_action.assert_not_called()

    def test_success_only_ever_starts_one_owner(self):
        pin=self.planned()
        with patch.object(module,"_rom_observe",new=AsyncMock()) as rom:
            with patch.object(module.time,"sleep"):
                result=module.execute(self.ns,self.home,"pin","sealed",pin,self.ha)
        self.assertEqual(result["status"],"V6_ROM_ROUNDTRIP_HOST_RUNNING_PENDING_SERVING")
        rom.assert_awaited_once()
        self.ha.restart_radio.assert_called_once()
        self.ha.owner_action.assert_called_once_with("start")
        self.assertTrue((self.home/module.ROOT_NAME/"result.json").exists())
        with self.assertRaises(Hold):
            module.execute(self.ns,self.home,"pin","sealed",pin,self.ha)


if __name__=="__main__":
    unittest.main()
