"""Executor shell safety, crash replay and no-actuator-in-dry-run tests."""
from dataclasses import replace
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest import mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "host" / "recovery"))

from policy import Observation, State, Decision, evaluate
from executor import dispatch, action_key, accepted_receipt, load_action_result


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
    return later, replace(plan, state=replace(plan.state, incident_id="a" * 32))


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
            self.assertEqual(out.action_key, action_key(d.state, "CAPTURE_EVIDENCE"))
            result = load_action_result(Path(p), d.state, "CAPTURE_EVIDENCE")
            self.assertEqual(result, out.outcome)
            self.assertTrue(accepted_receipt({out.action_key: result}, d.state,
                                             "CAPTURE_EVIDENCE"))
            with self.assertRaises(FileExistsError):
                dispatch(d, o, client, Path(p), enabled=True)
            self.assertEqual(len(client.calls), 1)

    def test_timeout_never_replays(self):
        o, d = ready()
        client = FakeHA(fail=True)
        with TemporaryDirectory() as p:
            result = dispatch(d, o, client, Path(p), enabled=True)
            self.assertEqual(result.status, "AMBIGUOUS_NO_RETRY")
            self.assertEqual(load_action_result(Path(p), d.state,
                                               "CAPTURE_EVIDENCE")["status"],
                             "AMBIGUOUS_NO_RETRY")
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
            with self.assertRaises(ValueError):
                dispatch(d, replace(o, observation_valid=False), client, Path(p), enabled=True)
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

    def test_unscoped_or_other_incident_receipt_is_never_accepted(self):
        o, d = ready()
        with TemporaryDirectory() as p:
            out = dispatch(d, o, FakeHA(), Path(p), enabled=True)
            receipts = {out.action_key: out.outcome, "CAPTURE_EVIDENCE": True}
            other = replace(d.state, incident_id="b"*32)
            self.assertFalse(accepted_receipt(receipts, other, "CAPTURE_EVIDENCE"))
            self.assertFalse(accepted_receipt({"CAPTURE_EVIDENCE": True}, d.state,
                                              "CAPTURE_EVIDENCE"))

    def test_missing_transaction_uuid_blocks_enabled_dispatch(self):
        o, d = ready()
        client = FakeHA()
        with TemporaryDirectory() as p:
            with self.assertRaises(ValueError):
                dispatch(replace(d, state=replace(d.state, incident_id="")),
                         o, client, Path(p), enabled=True)
        self.assertFalse(client.calls)

    def test_crash_before_result_can_never_replay_remote_call(self):
        o, d = ready()
        client = FakeHA()
        import executor
        original = executor._atomic_unique
        calls = 0
        def interrupted_write(path, document):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("simulated result persistence failure")
            return original(path, document)
        with TemporaryDirectory() as p:
            with mock.patch("executor._atomic_unique", side_effect=interrupted_write):
                with self.assertRaises(OSError):
                    dispatch(d, o, client, Path(p), enabled=True)
            self.assertIsNone(load_action_result(Path(p), d.state, "CAPTURE_EVIDENCE"))
            with self.assertRaises(FileExistsError):
                dispatch(d, o, client, Path(p), enabled=True)
        self.assertEqual(client.calls, ["CAPTURE_EVIDENCE"])

    def test_result_with_wrong_phase_or_uuid_is_rejected(self):
        o, d = ready()
        with TemporaryDirectory() as p:
            out = dispatch(d, o, FakeHA(), Path(p), enabled=True)
            path = next(Path(p).glob("*.result.json"))
            doc = json.loads(path.read_text())
            doc["incident_id"] = "b"*32
            path.write_text(json.dumps(doc))
            with self.assertRaises(ValueError):
                load_action_result(Path(p), d.state, "CAPTURE_EVIDENCE")

    def test_each_recovery_stage_has_one_attempt_and_starts_do_not_collide(self):
        o, base = ready()
        client = FakeHA()
        stages = (("CAPTURE_PENDING", "CAPTURE_EVIDENCE"),
                  ("STOP_PENDING", "STOP_Z2M"),
                  ("ESP_RESET_PENDING", "RESTART_ESP"),
                  ("ESP_START_PENDING", "START_Z2M"),
                  ("RADIO_RESET_PENDING", "RESET_RADIO"),
                  ("RADIO_START_PENDING", "START_Z2M"))
        with TemporaryDirectory() as p:
            for phase, action in stages:
                state = replace(base.state, phase=phase)
                decision = Decision(state, action, "TEST")
                current = replace(o, saved_evidence=True, stopped_receipt=True,
                                  esp_restart_ack=True, radio_reset_ack=True)
                result = dispatch(decision, current, client, Path(p), enabled=True)
                self.assertTrue(accepted_receipt({result.action_key: result.outcome},
                                                 state, action))
                with self.assertRaises(FileExistsError):
                    dispatch(decision, current, client, Path(p), enabled=True)
            self.assertEqual(client.calls, [action for phase, action in stages])
            self.assertEqual(len(list(Path(p).glob("*.attempt.json"))), len(stages))

    def test_quiesced_stage_uses_stop_receipt_without_requiring_live_app_logs(self):
        o, base = ready()
        decision = Decision(replace(base.state, phase="ESP_RESET_PENDING"),
                            "RESTART_ESP", "TEST")
        with TemporaryDirectory() as p:
            client = FakeHA()
            quiesced = replace(o, addon="stopped", observation_valid=False,
                               stopped_receipt=True)
            result = dispatch(decision, quiesced, client, Path(p), enabled=True)
            self.assertEqual(result.status, "COMMAND_ACCEPTED_NOT_YET_VERIFIED")
            self.assertEqual(client.calls, ["RESTART_ESP"])


if __name__ == "__main__":
    unittest.main()
