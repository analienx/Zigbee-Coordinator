"""Offline, fail-closed tests of the stopped-only startup-capture host operator."""
import hashlib
import importlib.util
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT=Path(__file__).resolve().parents[1]
FILE=ROOT/"host"/"flash"/"p7u_v6_startup_host_install.py"
spec=importlib.util.spec_from_file_location("p7u_v6_startup_host_install",FILE)
import sys
sys.path.insert(0,str(FILE.parent))
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class Hold(Exception):pass


class Tests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.owner={"running":False,"image":mod.OLD_IMAGE,"started_at":"2026-10-30T06:34:11Z"}
        self.payload={
            "firmware_source":mod.FW,"host_source":mod.HOST,
            "new_image":mod.NEW_IMAGE,"old_owner":self.owner,
            "old_version":mod.config.OLD_VERSION,
            "old_config_sha256":mod.config.OLD_SHA256,
            "new_config_sha256":"test-config",
            "release_sha256":"test-manifest","archive_sha256":mod.ARCHIVE_SHA,
            "write_plan_pin":"write-plan","write_receipt_sha256":"verified-write",
            "database_sha256":"database","board_sha256":"board",
            "package_pin":"package-pin","scope":"PUBLISH_PREBUILT_INSTALL_STOPPED_ONLY",
            "radio_actions":0,"host_starts":0
        }
        self.ns={
            "PRIVATE":self.root,"SOURCE":mod.FW,
            "need":lambda test,why:test or self.hold(why),
            "canonical":lambda p:json.dumps(p,sort_keys=True,separators=(',',':')).encode(),
            "sha":lambda b:hashlib.sha256(b).hexdigest(),
            "durable":self.durable,
            "private_root":lambda p:p.is_dir() or self.hold("PRIVATE_ROOT"),
            "load":lambda p:json.loads(p.read_bytes()),
        }
        self.ha=MagicMock()
        self.preflight=patch.object(mod,"preflight",return_value=(self.payload,b"new-config"))
        self.preflight.start()
        self.addCleanup(self.preflight.stop)

    @staticmethod
    def hold(why):raise Hold(why)
    def durable(self,root,name,data):
        with (root/name).open("xb") as f:
            f.write(self.ns["canonical"](data) if not isinstance(data,bytes) else data)

    def planned(self):
        p=mod.plan(self.ns,self.root,"package-pin","write-plan",self.ha)
        self.assertEqual(p["status"],"HOST_STARTUP_CAPTURE_INSTALL_PLAN_READY")
        return p["plan_pin"]

    def test_plan_no_side_effects(self):
        self.planned()
        self.ha.owner_action.assert_not_called()
        self.ha.restart_radio.assert_not_called()
        self.assertEqual({p.name for p in (self.root/mod.OP_ROOT).iterdir()},{"plan.json"})

    def test_duplicate_plan_denied(self):
        self.planned()
        with self.assertRaisesRegex(Hold,"HOST_INSTALL_PLAN_ALREADY_EXISTS"):
            mod.plan(self.ns,self.root,"package-pin","write-plan",self.ha)

    def test_wrong_publish_pin_denied_before_docker(self):
        self.planned()
        with patch.object(mod,"_run",side_effect=AssertionError("no docker should run")):
            with self.assertRaisesRegex(Hold,"HOST_INSTALL_PLAN_EXPIRED_OR_DRIFTED"):
                mod.publish(self.ns,self.root,"package-pin","write-plan","0"*64,self.ha)
        self.assertFalse((self.root/mod.OP_ROOT/"publish-intent.json").exists())

    def test_expired_plan_denied(self):
        pin=self.planned()
        now=time.time()
        with patch.object(mod.time,"time",return_value=now+mod.MAX_AGE+5):
            with self.assertRaisesRegex(Hold,"HOST_INSTALL_PLAN_EXPIRED_OR_DRIFTED"):
                mod.publish(self.ns,self.root,"package-pin","write-plan",pin,self.ha)

    def test_consumed_publish_cannot_replay(self):
        pin=self.planned()
        self.durable(self.root/mod.OP_ROOT,"publish-intent.json",{"attempts":1})
        with self.assertRaisesRegex(Hold,"HOST_INSTALL_PHASE_ALREADY_CONSUMED"):
            mod.publish(self.ns,self.root,"package-pin","write-plan",pin,self.ha)

    def test_install_never_precedes_verified_publication(self):
        pin=self.planned()
        with self.assertRaisesRegex(Hold,"HOST_INSTALL_PHASE_ALREADY_CONSUMED"):
            mod.install_stopped(self.ns,self.root,"package-pin","write-plan",pin,self.ha)

    def test_resume_must_prove_premutation_receipts(self):
        pin=self.planned()
        with self.assertRaisesRegex(Hold,"HOST_INSTALL_CONTINUATION_PREMUTATION_ONLY"):
            mod.continue_pre_mutation(self.ns,self.root,"package-pin",
                                      "write-plan",pin,self.ha)

    def test_fresh_continuation_is_not_a_replay(self):
        pin=self.planned()
        previous=self.root/mod.OP_ROOT
        self.durable(previous,"publish-intent.json",{"pin":pin})
        self.durable(previous,"publish-result.json",{"pin":pin})
        self.durable(previous,"prior-host.log",b"prior private failure")
        self.durable(previous,"backup-database-db.bin",b"unchanged")
        data=self.root/"data"
        data.mkdir()
        (data/"database.db").write_bytes(b"unchanged")
        self.ns["DATA"]=data
        self.ns["file_sha"]=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
        with patch.object(mod,"_install_body",return_value={"status":"PRE_MUTATION_TEST_ONLY"}) as run:
            result=mod.continue_pre_mutation(self.ns,self.root,"package-pin",
                                             "write-plan",pin,self.ha)
        self.assertEqual(result["status"],"PRE_MUTATION_TEST_ONLY")
        run.assert_called_once()
        self.assertEqual(run.call_args.kwargs["published_root"], previous)
        continuation=self.root/(mod.OP_ROOT+"-continuation")
        intent=self.ns["load"](continuation/"continuation-intent.json")
        self.assertTrue(intent["consumed_before_send"])
        self.assertEqual(intent["previous_mutation_attempts"],0)
        self.assertEqual(intent["radio_actions"],0)
        with self.assertRaisesRegex(Hold,"HOST_INSTALL_CONTINUATION_ALREADY_CONSUMED"):
            mod.continue_pre_mutation(self.ns,self.root,"package-pin",
                                      "write-plan",pin,self.ha)

    def test_continuation_rejects_any_previous_install_intent(self):
        pin=self.planned()
        previous=self.root/mod.OP_ROOT
        self.durable(previous,"install-intent.json",{"consumed":True})
        with self.assertRaisesRegex(Hold,"HOST_INSTALL_CONTINUATION_PREMUTATION_ONLY"):
            mod.continue_pre_mutation(self.ns,self.root,"package-pin",
                                      "write-plan",pin,self.ha)

    def test_schema_scope_exposes_no_automatic_start(self):
        pin=self.planned()
        plan=self.ns["load"](self.root/mod.OP_ROOT/"plan.json")
        self.assertEqual(plan["host_starts"],0)
        self.assertEqual(plan["radio_actions"],0)
        self.assertEqual(plan["scope"],"PUBLISH_PREBUILT_INSTALL_STOPPED_ONLY")
        self.assertEqual(pin,self.ns["sha"](self.ns["canonical"](plan)))


if __name__=="__main__":unittest.main()
