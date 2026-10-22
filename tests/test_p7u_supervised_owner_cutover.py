"""Safe source-level acceptance tests; never contact HA or open serial."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "host/r4-b4/ha-addon/p7u_supervised_owner_cutover.py"
spec = importlib.util.spec_from_file_location("p7u_managed_cutover", SOURCE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class OneOwnerCutoverTests(unittest.TestCase):
    def test_default_execution_is_readonly_preflight(self):
        with patch.object(mod, "preflight") as check, patch.object(mod, "quiet_owner") as stop:
            with patch("sys.argv", ["p7u_supervised_owner_cutover.py"]):
                mod.main()
        check.assert_called_once()
        stop.assert_not_called()

    def test_docker_owner_query_fails_closed_on_daemon_error(self):
        from subprocess import CompletedProcess
        with patch.object(mod.subprocess, "run", return_value=CompletedProcess(
                ["docker"], 1, "", "Cannot connect to the Docker daemon")):
            with self.assertRaisesRegex(RuntimeError, "DOCKER_OWNER_STATE_UNAVAILABLE"):
                mod.running(mod.OLD)
        with patch.object(mod.subprocess, "run", return_value=CompletedProcess(
                ["docker"], 1, "", "Error: No such object: app_missing")):
            self.assertFalse(mod.running("missing"))

    def test_missing_backup_fails_closed(self):
        with patch.object(mod, "BACKUP", Path("/__p7u_test_not_real_backup__")):
            self.assertFalse(mod.backup_valid())

    def test_native_history_excludes_stale_and_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            hist = Path(tmp) / "history.json"
            hist.write_text(json.dumps({"schema": "p7u-b4-native-history-v1",
                "rows": [
                    {"utc": 100, "kind": "VALID", "abi": 4,
                     "probeLatencyMs": 22, "monotonicReceiveNs": "1"},
                    {"utc": 250, "kind": "SKIPPED"},
                    {"utc": 300, "kind": "VALID", "abi": 4,
                     "probeLatencyMs": 5, "monotonicReceiveNs": "2"},
                ]}))
            with patch.object(mod, "HISTORY", hist):
                good, skipped = mod.valid_native_samples(200)
            self.assertEqual([x["utc"] for x in good], [300])
            self.assertEqual(skipped, 1)

    def test_requires_three_native_records_same_epoch_and_last_good(self):
        with tempfile.TemporaryDirectory() as tmp:
            last = Path(tmp) / "last-good.json"
            last.write_text(json.dumps({"sequence": 9}))
            samples = [{"kind": "VALID", "sequence": v,
                        "radioEpochTag": "pseudonym-only"} for v in (7, 8, 9)]
            with patch.object(mod, "LAST_GOOD", last):
                self.assertTrue(mod.completed(samples))
                self.assertFalse(mod.completed(samples[:2]))
                invalid = [dict(x) for x in samples]
                invalid[2]["sequence"] = 8
                self.assertFalse(mod.completed(invalid))
                invalid[2]["sequence"] = 9
                invalid[2]["radioEpochTag"] = None
                self.assertFalse(mod.completed(invalid))

    def test_safe_rollback_does_not_restart_running_original(self):
        with patch.object(mod, "running", side_effect=lambda name: name == mod.OLD):
            with patch.object(mod, "run") as execute:
                mod.restore_old()
        execute.assert_not_called()

    def test_candidate_is_always_stopped_before_restoring_original(self):
        status = {mod.NEW: True, mod.OLD: False}
        def execute(*args, **_kw):
            if args == ("ha", "apps", "stop", mod.NEW):
                status[mod.NEW] = False
            elif args == ("ha", "apps", "start", mod.OLD):
                self.assertFalse(status[mod.NEW])
                status[mod.OLD] = True
            else:
                self.fail("unexpected command: " + repr(args))
            return ""
        with patch.object(mod, "running", side_effect=lambda name: status[name]):
            with patch.object(mod, "run", side_effect=execute):
                mod.restore_old()
        self.assertTrue(status[mod.OLD])
        self.assertFalse(status[mod.NEW])


if __name__ == "__main__":
    unittest.main()
