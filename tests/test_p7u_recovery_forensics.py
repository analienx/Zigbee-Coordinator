"""No hardware: durable, bounded first-error and incident forensic tests."""
from pathlib import Path
import json
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"host"/"recovery"))
from forensics import PassiveForensics, MAX_ROWS
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


if __name__=="__main__":
    unittest.main()
