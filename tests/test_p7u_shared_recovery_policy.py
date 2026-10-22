"""Safety regression tests for source-only common recovery policy."""
from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "host" / "recovery"))
from policy import Observation, State, evaluate


def sample(at=1_800_000_000, **values):
    base = Observation(
        utc=at, addon="started", mode="USB",
        expected_identity=True, expected_usb=True, esp_reachable=True,
        ha_reachable=True, mqtt_reachable=True,
        serial_owner_exclusive=True, app_uptime_s=400,
        srsp_120s=8, affected_devices_120s=6,
        fresh_device_topics_120s=0, health_fresh=True)
    return replace(base, **values)


class RecoveryPolicyTests(unittest.TestCase):
    def confirm(self, **values):
        a = sample(**values)
        first = evaluate(a)
        self.assertEqual(first.state.phase, "SUSPECT")
        second = evaluate(replace(a, utc=a.utc + 40), first.state)
        return second

    def test_consecutive_confirmed_hang_starts_evidence_first(self):
        d = self.confirm()
        self.assertEqual((d.action, d.state.phase),
                         ("CAPTURE_EVIDENCE", "CAPTURE_PENDING"))
        self.assertEqual(evaluate(sample(at=d.state.last_sample_utc+1),
                                  d.state).action, "NONE")

    def test_single_device_route_error_not_a_hang(self):
        d = evaluate(sample(srsp_120s=0, affected_devices_120s=1))
        self.assertEqual(d.state.phase, "MONITOR")
        self.assertEqual(d.action, "NONE")

    def test_no_fresh_health_cannot_trigger_reset(self):
        for override in (
            {"health_fresh": False},
            {"srsp_120s": 4},
            {"affected_devices_120s": 2},
            {"fresh_device_topics_120s": 1},
            {"app_uptime_s": 120},
            {"mqtt_reachable": False},
            {"mode": "Ethernet"},
            {"expected_identity": False},
            {"serial_owner_exclusive": False},
            {"maintenance": True},
            {"ota_active": True},
            {"firmware_flash_active": True},
        ):
            d = evaluate(sample(**override))
            self.assertNotEqual(d.action, "CAPTURE_EVIDENCE", override)
            self.assertNotEqual(d.action, "RESET_RADIO", override)

    def test_stale_error_or_generic_app_crash_does_not_trigger(self):
        d = evaluate(sample(addon="error", adapter_error="MQTT_NOT_CONNECTED"))
        self.assertEqual(d.action, "NONE")
        self.assertEqual(d.state.phase, "MONITOR")

    def test_specific_start_failure_needs_two_samples(self):
        a = sample(addon="error", adapter_error="SRSP_SYS_PING",
                   health_fresh=False, srsp_120s=0)
        x = evaluate(a)
        self.assertEqual(x.action, "NONE")
        y = evaluate(replace(a, utc=a.utc+45), x.state)
        self.assertEqual(y.action, "CAPTURE_EVIDENCE")

    def test_detection_resets_if_fault_disappears(self):
        a = evaluate(sample())
        b = evaluate(sample(at=1_800_000_033, srsp_120s=0), a.state)
        self.assertEqual(b.state.phase, "MONITOR")

    def test_no_duplicate_poll_counts(self):
        s = evaluate(sample()).state
        out = evaluate(sample(at=1_800_000_010), s)
        self.assertEqual(out.action, "NONE")
        self.assertEqual(out.state.fault_samples, 1)

    def test_would_stop_and_reset_only_after_durable_receipts(self):
        x = self.confirm()
        t = x.state.last_sample_utc
        y = evaluate(sample(at=t+1), x.state)
        self.assertEqual(y.action, "NONE")
        y = evaluate(sample(at=t+2, saved_evidence=True), x.state)
        self.assertEqual(y.action, "STOP_Z2M")
        z = evaluate(sample(at=t+3), y.state)
        self.assertEqual(z.action, "NONE")
        z = evaluate(sample(at=t+4, addon="stopped", stopped_receipt=True),
                     y.state)
        self.assertEqual(z.action, "RESET_RADIO")
        self.assertEqual(evaluate(sample(at=t+5, addon="stopped"),
                                  z.state).action, "NONE")
        self.assertEqual(len(z.state.radio_resets_24h), 1)

    def test_radio_then_esp_same_maintained_network(self):
        x = self.confirm()
        ts = x.state.last_sample_utc
        s = evaluate(sample(at=ts+1, saved_evidence=True), x.state).state
        s = evaluate(sample(at=ts+2, addon="stopped",
                            stopped_receipt=True), s).state
        s = evaluate(sample(at=ts+3, addon="stopped",
                            radio_reset_ack=True), s).state
        self.assertEqual(s.phase, "RADIO_BOOT")
        self.assertEqual(evaluate(sample(at=ts+15), s).action, "NONE")
        start = evaluate(sample(at=ts+24), s)
        self.assertEqual(start.action, "START_Z2M")
        radio_verify = evaluate(sample(at=ts+26, z2m_start_ack=True),
                                start.state)
        self.assertEqual(radio_verify.state.phase, "RADIO_VERIFY")
        esp = evaluate(sample(at=ts+50, addon="error",
                              adapter_error="SRSP_AF_REGISTER"),
                       radio_verify.state)
        self.assertEqual(esp.action, "RESTART_ESP")
        self.assertEqual(evaluate(sample(at=ts+55, addon="error",
                                         adapter_error="SRSP_AF_REGISTER"),
                                  esp.state).action, "NONE")
        s = evaluate(sample(at=ts+65, addon="error",
                            esp_restart_ack=True), esp.state).state
        self.assertEqual(evaluate(sample(at=ts+72), s).action, "NONE")
        start2 = evaluate(sample(at=ts+86), s)
        self.assertEqual(start2.action, "START_Z2M")
        s = evaluate(sample(at=ts+89, z2m_start_ack=True),
                     start2.state).state
        self.assertEqual(s.phase, "ESP_VERIFY")
        traffic = sample(at=ts+125, fresh_device_topics_120s=12,
                         srsp_120s=0, bridge_online_fresh=True,
                         herdsman_started_fresh=True)
        self.assertEqual(evaluate(traffic, s).action, "NONE")
        done = evaluate(replace(traffic, utc=ts+220), s)
        self.assertEqual(done.action, "RECOVERY_SUCCEEDED")
        self.assertEqual(done.state.phase, "COMPLETE")
        self.assertEqual(evaluate(replace(traffic, utc=ts+240),
                                  done.state).action, "NONE")

    def test_cooldown_and_cap(self):
        t = 1_800_000_000
        base = State(phase="SUSPECT", suspect_since=t-40,
                     last_sample_utc=t-40, reason="MULTI_DEVICE_AF_ZNP_STARVATION",
                     fault_samples=1, last_recovery_utc=t-300)
        decision = evaluate(sample(at=t), base)
        self.assertEqual(decision.action, "ALERT_HUMAN")
        self.assertIn("COOLDOWN", decision.reason)
        capped = replace(base, last_recovery_utc=0,
                         radio_resets_24h=(t-500, t-300))
        self.assertEqual(evaluate(sample(at=t), capped).action, "ALERT_HUMAN")

    def test_epoch_or_state_corruption_fail_closed(self):
        self.assertEqual(evaluate(sample(), State(phase="INVALID")).action,
                         "ALERT_HUMAN")
        self.assertEqual(evaluate(sample(at=10),
                         State(last_sample_utc=11)).action, "ALERT_HUMAN")


if __name__ == "__main__":
    unittest.main()
