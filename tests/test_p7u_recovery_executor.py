"""Executor shell safety, crash replay and no-actuator-in-dry-run tests."""
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "host" / "recovery"))

from policy import Observation, State, Decision, evaluate
from executor import dispatch


class FakeHA:
    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail

    def perform_once(self, action):
        self.calls.append(action)
        if self.fail:
            raise TimeoutError("unknown whether remote action executed")
        return True


def ready():
    now = 1_800_000_000
    obs = Observation(utc=now, addon="error", adapter_error="SRSP_SYS_PING",
        expected_identity=True, expected_usb=True, esp_reachable=True,
        ha_reachable=True, mqtt_reachable=True)
    d = evaluate(obs)
    later = Observation(**{**vars(obs), "utc": now + 45})
    plan = evaluate(later, d.state)
    assert plan.action == "CAPTURE_EVIDENCE"
    return later, plan


class ExecutorShellTests(unittest.TestCase):
    def test_dry_run_is_the_default(self):
        o, d = ready()
        client = FakeHA()
        with TemporaryDirectory() as p:
            result = dispatch(d, o, client, Path(p))
            self.assertEqual(result.status, "DRY_RUN")
            self.assertEqual(client.calls, [])
            self.assertEqual(list(Path(p).iterdir()), [])

    def test_one_durable_capture_no_repeat(self):
        o, d = ready()
        client = FakeHA()
        with TemporaryDirectory() as p:
            out = dispatch(d, o, client, Path(p), enabled=True)
            self.assertEqual(out.status, "COMMAND_ACCEPTED_NOT_YET_VERIFIED")
            self.assertEqual(client.calls, ["CAPTURE_EVIDENCE"])
            self.assertTrue(Path(out.attempt_file).is_file())
            with self.assertRaises(FileExistsError):
                dispatch(d, o, client, Path(p), enabled=True)
            self.assertEqual(len(client.calls), 1)

    def test_timeout_never_replays(self):
        o, d = ready()
        client = FakeHA(fail=True)
        with TemporaryDirectory() as p:
            result = dispatch(d, o, client, Path(p), enabled=True)
            self.assertEqual(result.status, "AMBIGUOUS_NO_RETRY")
            with self.assertRaises(FileExistsError):
                dispatch(d, o, client, Path(p), enabled=True)
            self.assertEqual(client.calls, ["CAPTURE_EVIDENCE"])

    def test_stale_or_forged_decision_blocked(self):
        o, d = ready()
        client = FakeHA()
        with TemporaryDirectory() as p:
            forged = Decision(State(phase="RADIO_RESET_PENDING",
                                    incident_since=o.utc,
                                    last_sample_utc=o.utc),
                              "RESTART_ESP", "FORGED")
            with self.assertRaises(ValueError):
                dispatch(forged, o, client, Path(p), enabled=True)
            changed = Observation(**{**vars(o), "firmware_flash_active": True})
            with self.assertRaises(ValueError):
                dispatch(d, changed, client, Path(p), enabled=True)
            self.assertFalse(client.calls)

    def test_no_independent_physical_action_for_notifications(self):
        o, d = ready()
        client = FakeHA()
        with TemporaryDirectory() as p:
            no_op = Decision(d.state, "ALERT_HUMAN", "HOLD")
            self.assertEqual(dispatch(no_op, o, client, Path(p),
                                      enabled=True).status, "NO_PHYSICAL_ACTION")
            self.assertEqual(client.calls, [])

    def test_missing_private_dir_or_symlink_denied(self):
        o, d = ready()
        client = FakeHA()
        with TemporaryDirectory() as p:
            with self.assertRaises(ValueError):
                dispatch(d, o, client, Path(p) / "absent", enabled=True)
            self.assertFalse(client.calls)


if __name__ == "__main__":
    unittest.main()
