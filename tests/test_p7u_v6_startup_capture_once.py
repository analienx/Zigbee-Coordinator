"""Offline fail-closed unit coverage of single-use V6 instrumented startup."""
import importlib.util
from pathlib import Path
import hashlib
import json
import tempfile
import unittest
from unittest.mock import patch, MagicMock

source=Path(__file__).resolve().parents[1]/"host/flash/p7u_v6_startup_capture_once.py"
spec=importlib.util.spec_from_file_location("startup_capture",source)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class Hold(Exception): pass

class Tests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.private=Path(self.temp.name)
        self.state={"source":module.V6,"host":module.HOST,"image":module.IMAGE,
            "prior_publish_sha256":"prior","write_plan_sha256":"plan","radio_resets":0}
        self.ns={"PRIVATE":self.private,"SOURCE":module.V6,"IMAGE":module.IMAGE,
            "PAIRED_HOST_VERSION":"0.2.1-"+module.HOST[:12],
            "need":lambda test,name:test or self.raise_hold(name),
            "sealed_tree":lambda *args:None,
            "canonical":lambda x:json.dumps(x,sort_keys=True,separators=(',',':')).encode(),
            "sha":lambda x:hashlib.sha256(x).hexdigest(),
            "load":lambda p:json.loads(p.read_bytes()),
            "durable":self.durable,"private_root":lambda p:p.is_dir() or self.raise_hold("NOT_PRIVATE")}
        self.ha=MagicMock()
        self.mock=patch.object(module,"_get_current",return_value=self.state)
        self.mock.start();self.addCleanup(self.mock.stop)
    @staticmethod
    def raise_hold(name):raise Hold(name)
    def durable(self,root,name,value):
        with (root/name).open("xb") as f:
            f.write(value if isinstance(value,bytes) else self.ns["canonical"](value))
    def planned(self):
        out=module.plan(self.ns,self.private,"package","write-plan",self.ha)
        self.assertEqual(out["status"],"START_CAPTURE_ONE_SHOT_PLAN_READY")
        return out["pin"]

    def test_plan_is_non_mutating(self):
        self.planned()
        self.ha.owner_action.assert_not_called()
        self.assertEqual([p.name for p in (self.private/module.START_ROOT).iterdir()],["plan.json"])

    def test_second_plan_rejected(self):
        self.planned()
        with self.assertRaisesRegex(Hold,"START_CAPTURE_ALREADY_PLANNED"):
            module.plan(self.ns,self.private,"package","write-plan",self.ha)

    def test_invalid_pin_blocks_before_host(self):
        self.planned()
        with self.assertRaisesRegex(Hold,"START_CAPTURE_PLAN_PIN_OR_TTL"):
            module.execute(self.ns,self.private,"package","write-plan","0"*64,self.ha)
        self.ha.owner_action.assert_not_called()

    def test_drift_blocks_before_host(self):
        pin=self.planned()
        self.state["image"]="sha256:drift"
        with self.assertRaisesRegex(Hold,"START_CAPTURE_PRESTART_DRIFT"):
            module.execute(self.ns,self.private,"package","write-plan",pin,self.ha)
        self.ha.owner_action.assert_not_called()

    def test_prior_consumed_intent_blocks_duplicate(self):
        pin=self.planned()
        self.durable(self.private/module.START_ROOT,"start-intent.json",{"consumed":True})
        with self.assertRaisesRegex(Hold,"START_CAPTURE_ACTION_ALREADY_CONSUMED"):
            module.execute(self.ns,self.private,"package","write-plan",pin,self.ha)
        self.ha.owner_action.assert_not_called()

    def test_successful_once_only_and_private_log(self):
        pin=self.planned()
        self.ns["OWNER"]="local_p7u_r4_native_host"
        new_id="a"*64
        container={"Id":new_id,"Image":module.IMAGE,
                   "State":{"Running":False,"ExitCode":1}}
        self.ns["run"]=lambda argv,*args: (
            json.dumps([container]).encode() if argv[:2]==["docker","inspect"]
            else b"P7U startup trace private")
        with patch.object(module.time,"sleep"):
            result=module.execute(self.ns,self.private,"package","write-plan",pin,self.ha)
        self.assertEqual(result["status"],"STARTUP_FAILED_HELD_NO_RETRY")
        self.ha.owner_action.assert_called_once_with("start")
        self.assertTrue((self.private/module.START_ROOT/"first-startup.log").is_file())
        with self.assertRaisesRegex(Hold,"START_CAPTURE_ACTION_ALREADY_CONSUMED"):
            module.execute(self.ns,self.private,"package","write-plan",pin,self.ha)

    def test_ambiguous_owner_ack_never_retried(self):
        pin=self.planned()
        self.ns["OWNER"]="local_p7u_r4_native_host"
        self.ha.owner_action.side_effect=TimeoutError("Supervisor unknown")
        container={"Id":"a"*64,"Image":module.IMAGE,
                   "State":{"Running":False,"ExitCode":1}}
        self.ns["run"]=lambda argv,*args:(
            json.dumps([container]).encode() if argv[:2]==["docker","inspect"]
            else b"captured")
        with patch.object(module.time,"sleep"):
            result=module.execute(self.ns,self.private,"package","write-plan",pin,self.ha)
        self.assertFalse(result["host_start_ack"])
        self.ha.owner_action.assert_called_once()

if __name__=="__main__": unittest.main()
