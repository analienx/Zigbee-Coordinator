"""B4 adversarial persistence checks against the #87 passive recorder.

Strictly offline and only synthetic inputs; never opens a ZNP transport.
"""
from pathlib import Path
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "firmware" / "slzb-06p7u" / "r4" / "tools"))
from r4_passive_recorder import PassiveR4Recorder

def event(kind, at, waiter=None):
    item = {"kind":kind, "at_ms":at}
    if waiter is not None:
        item["waiter_id"] = waiter
    return item

class RecorderHostiles(unittest.TestCase):
    def test_d07_d30_allowlist_rejects_raw_fields(self):
        r = PassiveR4Recorder(process_generation=9)
        for field in ("ieee", "pan_id", "network_key", "raw_payload",
                      "serial_path", "logs", "auth_token", "mt_frame"):
            bad = event("AF_SREQ_TIMEOUT", 1, 3)
            bad[field] = "SECRET-CANARY"
            with self.subTest(field=field), self.assertRaises(ValueError):
                r.offer(bad)
        self.assertEqual(len(r.pending), 0)

    def test_d25_earlier_snapshot_survives_pre_rename_failure(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "last-good.json"
            r = PassiveR4Recorder(process_generation=1)
            r.offer(event("AF_SREQ_TIMEOUT", 5, 1))
            r.drain()
            r.persist(path)
            original = path.read_bytes()
            r.offer(event("ZDO_SREQ_TIMEOUT", 10, 2))
            r.drain()
            with patch("r4_passive_recorder.os.replace", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    r.persist(path)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(PassiveR4Recorder.read_last_good(path)["last_at_ms"], 5)

    def test_d26_fsync_failure_is_not_reported_as_success(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "last-good.json"
            r = PassiveR4Recorder(process_generation=2)
            r.offer(event("OTA_START", 1))
            r.drain()
            with patch("r4_passive_recorder.os.fsync", side_effect=OSError("IO error")):
                with self.assertRaises(OSError):
                    r.persist(path)

    def test_d25_d30_oversized_and_bad_history_refused(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "last-good.json"
            r = PassiveR4Recorder(process_generation=1)
            r.offer(event("OTA_START", 100))
            r.offer(event("OTA_STOP", 200))
            r.drain()
            r.persist(path)
            valid = json.loads(path.read_text())
            cases = []
            p = dict(valid)
            p["recent_events"] = [{"kind": "OTA_START", "at_ms": 201}]
            cases.append(p)
            p = dict(valid)
            p["recent_events"] = [{"kind": "OTA_START", "at_ms": 201},
                                  {"kind": "OTA_STOP", "at_ms": 100}]
            cases.append(p)
            p = dict(valid)
            p["signals"] = ["NO_MATCHING_HOST_SYMPTOM"] * 2
            cases.append(p)
            p = dict(valid)
            p["recent_events"] = [{"kind": "OTA_START", "at_ms": 2**70}]
            cases.append(p)
            for hostile in cases:
                with self.subTest(hostile=hostile["recent_events"][:1]):
                    path.write_text(json.dumps(hostile))
                    with self.assertRaises(ValueError):
                        PassiveR4Recorder.read_last_good(path)
            path.write_bytes(b"x" * 1_048_577)
            with self.assertRaisesRegex(ValueError, "exceeds"):
                PassiveR4Recorder.read_last_good(path)

    def test_d27_event_history_bounded_and_drop_accounted(self):
        r = PassiveR4Recorder(process_generation=3, max_pending=2, max_history=3)
        for i in range(10):
            r.offer(event("ZCL_TIMEOUT", i))
        self.assertEqual(len(r.pending), 2)
        self.assertEqual(r.dropped, 8)
        self.assertEqual(r.drain(), 2)
        self.assertLessEqual(len(r.snapshot()["recent_events"]), 3)

    def test_d28_d29_reversing_time_and_duplicate_waiter_not_counted(self):
        r = PassiveR4Recorder(process_generation=4)
        for entry in (event("AF_SREQ_TIMEOUT", 10, 1),
                      event("AF_SREQ_TIMEOUT", 20, 1),
                      event("AF_SREQ_TIMEOUT", 11, 2)):
            r.offer(entry)
            r.drain()
        s = r.snapshot()
        self.assertEqual(s["af_sreq_timeouts"], 1)
        self.assertEqual(s["dropped"], 2)
        self.assertEqual(s["root_cause"], "UNDETERMINED")

    def test_d07_symlink_snapshots_refused(self):
        if os.name != "posix":
            self.skipTest("POSIX symlink check")
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "evidence.json"
            path.symlink_to(Path(d) / "elsewhere.json")
            with self.assertRaises(ValueError):
                PassiveR4Recorder.read_last_good(path)
            with self.assertRaises(ValueError):
                PassiveR4Recorder(process_generation=0).persist(path)

if __name__ == "__main__":
    unittest.main()
