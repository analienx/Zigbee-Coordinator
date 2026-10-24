"""No hardware: durable, bounded first-error and incident forensic tests."""
from pathlib import Path
import json
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"host"/"recovery"))
from forensics import PassiveForensics, MAX_ROWS, committed_native_summary
from policy import Observation, State


class FakeSupervisor:
    def __init__(self): self.calls=0
    def log_window(self,slug):
        self.calls+=1
        return ("boot marker","2026 SRSP TIMEOUT device 0x00124b000abc1234\nnormal healthy line")


class Tests(unittest.TestCase):
    def test_first_af_error_freeze_and_dedupe(self):
        with TemporaryDirectory() as tmp:
            s=FakeSupervisor()
            f=PassiveForensics(Path(tmp),s,"z2m")
            base={"utc":1800000000,"epoch_id":"unit-test-epoch",
                  "srsp_120s":0,"rx_valid":True}
            f.record(base)
            f.record({**base,"utc":1800000020,"srsp_120s":1})
            f.record({**base,"utc":1800000040,"srsp_120s":2})
            self.assertEqual(s.calls,1)
            result=json.loads((f.root/"first-error-1800000020.json").read_text())
            self.assertEqual(result["summary"]["srsp_120s"],1)
            self.assertNotIn("00124b000abc1234",json.dumps(result))
            self.assertTrue((f.root/"first-error-1800000020.intent.json").exists())

    def test_shadow_evidence_exactly_once_after_restart(self):
        with TemporaryDirectory() as tmp:
            s=FakeSupervisor()
            f=PassiveForensics(Path(tmp),s,"z2m")
            state=State(phase="CAPTURE_PENDING",incident_id="a"*32,
                incident_since=1800000000,stage_since=1800000000)
            obs=Observation(utc=1800000000,addon="error",srsp_120s=5)
            self.assertTrue(f.incident(state,obs))
            fresh=PassiveForensics(Path(tmp),s,"z2m")
            self.assertFalse(fresh.incident(state,obs))
            self.assertEqual(s.calls,1)
            self.assertTrue((f.root/("shadow-"+"a"*32+".json")).exists())

    def test_intent_without_result_is_not_replayed(self):
        with TemporaryDirectory() as tmp:
            s=FakeSupervisor()
            f=PassiveForensics(Path(tmp),s,"z2m")
            (f.root/("shadow-"+"b"*32+".intent.json")).write_text("{}")
            state=State(phase="CAPTURE_PENDING",incident_id="b"*32,
                incident_since=1800000000,stage_since=1800000000)
            self.assertFalse(f.incident(state,Observation(utc=1800000020,addon="error")))
            self.assertEqual(s.calls,0)

    def test_bounded_history_and_invalid_data_fail_closed(self):
        with TemporaryDirectory() as tmp:
            f=PassiveForensics(Path(tmp),FakeSupervisor(),"z2m")
            base={"epoch_id":"one","srsp_120s":0}
            with patch("forensics.MAX_ROWS",5):
                for i in range(7):
                    f.record({**base,"utc":1800000000+i})
            doc=json.loads(f.history.read_text())
            self.assertEqual(len(doc["rows"]),5)
            f.history.write_text("{}")
            with self.assertRaises(ValueError):
                f.record({**base,"utc":1800009999})
            self.assertEqual(f.history.read_text(),"{}")

    def test_not_using_serial_or_actuator(self):
        from pathlib import Path
        content=(Path(__file__).resolve().parents[1]/"host"/"recovery"/"forensics.py").read_text()
        self.assertNotIn("ttyACM",content)
        self.assertNotIn("private_restart(",content)
        self.assertNotIn("serial.Serial(",content)


class WorkerV2Freeze(unittest.TestCase):
    NOW = 1800000000

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def seed(self, rows, pointed=True):
        import hashlib
        target = self.root
        if pointed:
            name = "generation-8e2cdca6-17b6-4a4c-a951-a78742ad89e1"
            target = self.root / name
            target.mkdir()
            (self.root / "current-v2.json").write_text(json.dumps({"schema":"p7u-f2-pointer-v1", "active":name, "previous":None}))
        previous = "0" * 64
        frames = []
        for number, data in enumerate(rows, 1):
            frame = {"seq":number,"previous":previous,"data":data}
            previous = hashlib.sha256(json.dumps(frame,ensure_ascii=False,separators=(",",":")).encode()).hexdigest()
            frames.append(json.dumps({**frame,"sha":previous},ensure_ascii=False,separators=(",",":")) + "\n")
        raw = "".join(frames).encode()
        (target / "events-v2.jsonl").write_bytes(raw)
        last = next((i for i in range(len(rows),0,-1) if rows[i-1]["kind"]=="VALID"),None)
        (target / "manifest-v2.json").write_text(json.dumps({"schema":"p7u-f2-worker-v2", "committedBytes":len(raw),
            "sequence":len(rows),"head":previous,"lastValidSeq":last,"lastValidHostRun":rows[last-1]["hostRunId"] if last else None}))
        return target

    def valid(self):
        return {"kind":"VALID","abi":4,"sequence":1,"validityMask":0x2c,"utc":self.NOW*1000-1000,
            "hostRunId":"a"*36,"ownerGeneration":"b"*36,"srspDepth":999,"srspHighWater":999,
            "asyncDepth":2,"asyncHighWater":4,"srspEnqueued":123,"uartTxFinishedEvents":50,
            "private_token":"synthetic-secret"}

    def read(self):
        return committed_native_summary(self.root,{"epoch_start_utc":self.NOW-60},self.NOW)

    def test_retired_v1_last_good_never_becomes_evidence(self):
        (self.root / "last-good.json").write_text(json.dumps(self.valid()))
        result = self.read()
        self.assertEqual(result["status"],"UNAVAILABLE")
        self.assertNotIn("synthetic-secret",json.dumps(result))

    def test_committed_pointer_freezes_real_validity_and_host_failure(self):
        failed = {"kind":"FAILED","utc":self.NOW*1000,"hostRunId":"a"*36,"ownerGeneration":"b"*36,
            "hostTimeoutKind":"AF_SREQ_TIMEOUT","hostTimeoutAtMs":200,"hostTimeoutDropped":0}
        self.seed([self.valid(),failed])
        result = self.read()
        self.assertEqual(result["status"],"VERIFIED_COMMITTED_HISTORY")
        self.assertEqual(result["last_good"]["asyncDepth"],2)
        self.assertIsNone(result["last_good"]["srspDepth"])
        self.assertIsNone(result["last_good"]["srspEnqueued"])
        self.assertTrue(result["last_good"]["matches_observed_process_start"])
        self.assertEqual(result["host_timeouts"][0]["hostTimeoutKind"],"AF_SREQ_TIMEOUT")
        self.assertNotIn("synthetic-secret",json.dumps(result))
        self.assertEqual(result["radio_epoch"],"UNKNOWN")

    def test_torn_append_unavailable_not_repaired(self):
        target=self.seed([self.valid()])
        path=target/"events-v2.jsonl";raw=path.read_bytes()+b"partial"
        path.write_bytes(raw)
        self.assertEqual(self.read()["status"],"UNAVAILABLE")
        self.assertEqual(path.read_bytes(),raw)

    def test_tampered_hash_unavailable(self):
        target=self.seed([self.valid()])
        p=target/"events-v2.jsonl";raw=p.read_bytes().replace(b'"asyncDepth":2',b'"asyncDepth":9');p.write_bytes(raw)
        self.assertEqual(self.read()["status"],"UNAVAILABLE")

    def test_pending_pointer_never_promotes_orphan(self):
        self.seed([self.valid()]);(self.root/".current-v2.pending").write_text("pending")
        self.assertEqual(self.read()["status"],"UNAVAILABLE")

    def test_selected_symlink_or_escape_is_unavailable(self):
        target=self.seed([self.valid()]);target.rename(self.root/"elsewhere");target.symlink_to(self.root/"elsewhere",target_is_directory=True)
        self.assertEqual(self.read()["status"],"UNAVAILABLE")
        pointer=self.root/"current-v2.json";d=json.loads(pointer.read_text());d["active"]="../elsewhere";pointer.write_text(json.dumps(d))
        self.assertEqual(self.read()["status"],"UNAVAILABLE")

    def test_old_owner_valid_sample_not_used_for_new_owner_failure(self):
        self.seed([self.valid(),{"kind":"FAILED","hostRunId":"c"*36,"ownerGeneration":"d"*36,"utc":self.NOW*1000}])
        self.assertIsNone(self.read()["last_good"])

    def test_age_and_missing_epoch_are_explicit(self):
        self.seed([self.valid()],pointed=False)
        result=committed_native_summary(self.root,{},self.NOW)
        self.assertIsNone(result["last_good"]["matches_observed_process_start"])
        self.assertEqual(result["last_good"]["age_ms"],1000)
        self.assertIsNone(committed_native_summary(self.root,{},self.NOW+90000)["last_good"])

    def test_manifest_changes_while_reading_do_not_freeze_mixed_state(self):
        import forensics
        self.seed([self.valid()])
        original=forensics._native_bytes
        calls=0
        def racing(path,limit):
            nonlocal calls
            raw=original(path,limit)
            if path.name=="manifest-v2.json":
                calls+=1
                if calls==2:return raw+b" "
            return raw
        with patch.object(forensics,"_native_bytes",side_effect=racing):
            self.assertEqual(self.read()["status"],"UNAVAILABLE")

    def test_actual_freeze_records_v2_and_marks_v1_retired(self):
        self.seed([self.valid()])
        with TemporaryDirectory() as temp, patch("forensics.NATIVE_ROOT",self.root), patch("forensics.time.time",return_value=self.NOW):
            f=PassiveForensics(Path(temp),FakeSupervisor(),"z2m")
            f.freeze("first-error-1800000000",{"utc":self.NOW,"epoch_start_utc":self.NOW-60})
            d=json.loads((f.root/"first-error-1800000000.json").read_text())
            self.assertIsNone(d["native_last_good_advisory"])
            self.assertEqual(d["native_worker_v2_advisory"]["status"],"VERIFIED_COMMITTED_HISTORY")

if __name__=="__main__":
    unittest.main()
