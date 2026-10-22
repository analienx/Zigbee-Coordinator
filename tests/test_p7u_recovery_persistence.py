"""Crash-boundary tests: private ledger durability and no action replay."""
from dataclasses import asdict, replace
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "host" / "recovery"))
from policy import Decision, Observation, State, evaluate
from executor import dispatch, accepted_receipt
from persistence import atomic_json, load_ledger, save_ledger, reconcile_pending


class FakeHA:
    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail

    def perform_once(self, action):
        self.calls.append(action)
        if self.fail:
            raise TimeoutError("test ambiguity")
        return True


def pending():
    now = 1_800_000_000
    return State(phase="CAPTURE_PENDING", incident_id="a"*32,
                 incident_since=now, stage_since=now, last_sample_utc=now)


def observation(state):
    return Observation(utc=state.last_sample_utc, addon="error",
                       expected_identity=True, expected_usb=True,
                       esp_reachable=True, ha_reachable=True, mqtt_reachable=True)


class RecoveryPersistenceTests(unittest.TestCase):
    def test_abandoned_temporary_does_not_block_next_atomic_save(self):
        with TemporaryDirectory() as raw:
            path = Path(raw)/"state.json"
            orphan = path.with_name("state.json.new")
            orphan.write_text("interrupted old save")
            atomic_json(path, {"current": 1})
            atomic_json(path, {"current": 2})
            self.assertEqual(json.loads(path.read_text()), {"current": 2})
            self.assertEqual(orphan.read_text(), "interrupted old save")

    def test_failed_replace_preserves_primary_and_cleans_only_own_temp(self):
        with TemporaryDirectory() as raw:
            path = Path(raw)/"state.json"
            path.write_text('{"old":true}')
            with mock.patch("persistence.os.replace", side_effect=OSError("test")):
                with self.assertRaises(OSError):
                    atomic_json(path, {"new": True})
            self.assertEqual(json.loads(path.read_text()), {"old": True})
            self.assertEqual(list(Path(raw).glob("*.new")), [])

    def test_roundtrip_normalizes_budget_tuple_before_resumed_transition(self):
        state = replace(pending(), phase="STOP_PENDING",
                        recovery_attempts_24h=(1_799_999_000,))
        with TemporaryDirectory() as raw:
            path = Path(raw)/"state.json"
            save_ledger(path, state, {})
            loaded, receipts = load_ledger(path)
            self.assertIsInstance(loaded.recovery_attempts_24h, tuple)
            observed = replace(observation(loaded), utc=loaded.last_sample_utc+1,
                               addon="stopped", stopped_receipt=True)
            decision = evaluate(observed, loaded)
            self.assertEqual(decision.action, "RESTART_ESP")
            self.assertEqual(len(decision.state.recovery_attempts_24h), 2)

    def test_legacy_pending_holds_and_drops_unscoped_acknowledgements(self):
        with TemporaryDirectory() as raw:
            path = Path(raw)/"state.json"
            state = asdict(replace(pending(), phase="ESP_RESET_PENDING"))
            state.pop("incident_id")
            state.pop("stable_since")
            path.write_text(json.dumps({"schema": "p7u-recovery-state-v1",
                                        "state": state,
                                        "receipts": {"RESTART_ESP": True}}))
            loaded, receipts = load_ledger(path)
            self.assertEqual(loaded.phase, "HOLD")
            self.assertEqual(receipts, {})

    def test_malformed_ledger_is_preserved_and_becomes_hold(self):
        for document in ('{broken', '{"schema":"unknown"}',
                         json.dumps({"schema":"p7u-recovery-state-v2",
                                     "state":{"last_sample_utc":True}})):
            with self.subTest(document=document), TemporaryDirectory() as raw:
                path = Path(raw)/"state.json"
                path.write_text(document)
                loaded, receipts = load_ledger(path)
                self.assertEqual((loaded.phase, loaded.reason), ("HOLD", "INVALID_LEDGER"))
                self.assertEqual(receipts, {})
                self.assertEqual(path.read_text(), document)
                quarantined = list(Path(raw).glob("*.rejected-*.json"))
                self.assertEqual(len(quarantined), 1)
                self.assertEqual(quarantined[0].read_text(), document)

    def test_ack_result_recovers_projection_without_resending_action(self):
        state = pending()
        client = FakeHA()
        with TemporaryDirectory() as raw:
            evidence = Path(raw)
            dispatch(Decision(state, "CAPTURE_EVIDENCE", "TEST"),
                     observation(state), client, evidence, enabled=True)
            receipts = {}
            restored = reconcile_pending(state, receipts, evidence)
            self.assertEqual(restored.phase, "CAPTURE_PENDING")
            self.assertTrue(accepted_receipt(receipts, state, "CAPTURE_EVIDENCE"))
            self.assertEqual(client.calls, ["CAPTURE_EVIDENCE"])

    def test_intent_without_result_or_ambiguous_result_holds_without_replay(self):
        for ambiguous in (False, True):
            with self.subTest(ambiguous=ambiguous), TemporaryDirectory() as raw:
                state = pending()
                client = FakeHA(fail=ambiguous)
                evidence = Path(raw)
                if ambiguous:
                    dispatch(Decision(state,"CAPTURE_EVIDENCE","TEST"),
                             observation(state),client,evidence,enabled=True)
                else:
                    # Persisted decision with crash before dispatch is also
                    # unresolved; it must never silently replay after restart.
                    (evidence/"unrelated.attempt.json").write_text("{}")
                receipts = {}
                restored = reconcile_pending(state,receipts,evidence)
                self.assertEqual(restored.phase,"HOLD")
                self.assertEqual(receipts,{})
                self.assertEqual(len(client.calls), int(ambiguous))

    def test_old_receipt_cannot_acknowledge_new_incident(self):
        with TemporaryDirectory() as raw:
            old = pending()
            client = FakeHA()
            result = dispatch(Decision(old,"CAPTURE_EVIDENCE","TEST"),
                              observation(old),client,Path(raw),enabled=True)
            receipts = {result.action_key:result.outcome}
            new = replace(old,incident_id="b"*32)
            restored = reconcile_pending(new,receipts,Path(raw))
            self.assertEqual(restored.phase,"HOLD")
            self.assertFalse(accepted_receipt(receipts,new,"CAPTURE_EVIDENCE"))

    def test_restart_resets_stability_even_when_boot_ack_is_proven(self):
        state = replace(pending(),phase="ESP_START_PENDING")
        with TemporaryDirectory() as raw:
            result = dispatch(Decision(state,"START_Z2M","TEST"),
                              replace(observation(state), esp_restart_ack=True),
                              FakeHA(),Path(raw),enabled=True)
            verify = replace(state,phase="ESP_VERIFY",stable_since=state.stage_since)
            receipts = {result.action_key:result.outcome}
            restored = reconcile_pending(verify,receipts,Path(raw))
            self.assertEqual(restored.phase,"ESP_VERIFY")
            self.assertEqual(restored.stable_since,0)


if __name__ == "__main__":
    unittest.main()
