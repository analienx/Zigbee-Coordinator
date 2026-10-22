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
        self.assertEqual(z.action, "RESTART_ESP")
        self.assertEqual(evaluate(sample(at=t+5, addon="stopped"),
                                  z.state).action, "NONE")
        self.assertEqual(len(z.state.recovery_attempts_24h), 1)

    def test_esp_first_success_in_actual_incident(self):
        x = self.confirm()
        ts = x.state.last_sample_utc
        s = evaluate(sample(at=ts+1, saved_evidence=True), x.state).state
        first = evaluate(sample(at=ts+2, addon="stopped",
                                stopped_receipt=True), s)
        self.assertEqual(first.action, "RESTART_ESP")
        self.assertEqual(first.state.phase, "ESP_RESET_PENDING")
        self.assertEqual(len(first.state.recovery_attempts_24h), 1)
        self.assertEqual(evaluate(sample(at=ts+3, addon="stopped"),
                                  first.state).action, "NONE")
        s = evaluate(sample(at=ts+5, addon="stopped",
                            esp_restart_ack=True), first.state).state
        self.assertEqual(s.phase, "ESP_BOOT")
        self.assertEqual(evaluate(sample(at=ts+15), s).action, "NONE")
        start = evaluate(sample(at=ts+26), s)
        self.assertEqual(start.action, "START_Z2M")
        s = evaluate(sample(at=ts+29, z2m_start_ack=True), start.state).state
        self.assertEqual(s.phase, "ESP_VERIFY")
        traffic = sample(at=ts+50, fresh_device_topics_120s=12,
                         srsp_120s=0, bridge_online_fresh=True,
                         herdsman_started_fresh=True)
        for delta in range(50, 170, 20):
            step = evaluate(replace(traffic, utc=ts+delta), s)
            self.assertEqual(step.action, "NONE")
            s = step.state
        done = evaluate(replace(traffic, utc=ts+170), s)
        self.assertEqual(done.action, "RECOVERY_SUCCEEDED")
        self.assertEqual(done.state.phase, "COMPLETE")
        self.assertEqual(done.state.last_recovery_utc, ts+2)

    def test_esp_failure_falls_back_once_to_radio(self):
        x = self.confirm()
        ts = x.state.last_sample_utc
        s = evaluate(sample(at=ts+1, saved_evidence=True), x.state).state
        s = evaluate(sample(at=ts+2, addon="stopped",
                            stopped_receipt=True), s).state
        s = evaluate(sample(at=ts+4, addon="stopped",
                            esp_restart_ack=True), s).state
        s = evaluate(sample(at=ts+26), s).state
        s = evaluate(sample(at=ts+28, z2m_start_ack=True), s).state
        radio = evaluate(sample(at=ts+51, addon="error",
                                adapter_error="SRSP_AF_REGISTER"), s)
        self.assertEqual(radio.action, "RESET_RADIO")
        self.assertEqual(radio.state.phase, "RADIO_RESET_PENDING")
        self.assertEqual(evaluate(sample(at=ts+52, addon="error"),
                                  radio.state).action, "NONE")
        s = evaluate(sample(at=ts+54, addon="error",
                            radio_reset_ack=True), radio.state).state
        start = evaluate(sample(at=ts+78), s)
        self.assertEqual(start.action, "START_Z2M")
        s = evaluate(sample(at=ts+82, z2m_start_ack=True), start.state).state
        failure = evaluate(sample(at=ts+103, addon="error",
                                  adapter_error="SRSP_SYS_PING"), s)
        self.assertEqual(failure.action, "ALERT_HUMAN")
        self.assertEqual(failure.state.phase, "HOLD")

    def test_cooldown_and_cap(self):
        t = 1_800_000_000
        base = State(phase="SUSPECT", suspect_since=t-40,
                     last_sample_utc=t-40, reason="MULTI_DEVICE_AF_ZNP_STARVATION",
                     fault_samples=1, last_recovery_utc=t-300)
        decision = evaluate(sample(at=t), base)
        self.assertEqual(decision.action, "ALERT_HUMAN")
        self.assertIn("COOLDOWN", decision.reason)
        capped = replace(base, last_recovery_utc=0,
                         recovery_attempts_24h=(t-500, t-300))
        self.assertEqual(evaluate(sample(at=t), capped).action, "ALERT_HUMAN")

    def test_esp_reboot_usb_detach_allowed_briefly_not_indefinitely(self):
        start=1_800_000_000
        state=State(phase="ESP_BOOT", stage_since=start,
                    incident_since=start, last_sample_utc=start)
        down=sample(at=start+50, esp_reachable=False, expected_usb=False,
                    expected_identity=False)
        d=evaluate(down,state)
        self.assertEqual(d.state.phase,"ESP_BOOT")
        self.assertEqual(d.action,"NONE")
        late=evaluate(replace(down,utc=start+181), d.state)
        self.assertEqual(late.action,"ALERT_HUMAN")

    def test_completed_recovery_rearms_with_cooldown(self):
        start=1_800_000_000
        s=State(phase="COMPLETE", last_recovery_utc=start-60,
                recovery_attempts_24h=(start-300,))
        d=evaluate(sample(at=start),s)
        self.assertEqual(d.state.phase,"MONITOR")
        next=evaluate(sample(at=start+30),d.state)
        self.assertEqual(next.state.phase,"SUSPECT")
        blocked=evaluate(sample(at=start+70),next.state)
        self.assertEqual(blocked.action,"ALERT_HUMAN")
        self.assertIn("COOLDOWN",blocked.reason)

    def test_epoch_or_state_corruption_fail_closed(self):
        self.assertEqual(evaluate(sample(), State(phase="INVALID")).action,
                         "ALERT_HUMAN")
        self.assertEqual(evaluate(sample(at=10),
                         State(last_sample_utc=11)).action, "ALERT_HUMAN")

    def test_intentional_stop_with_recent_adapter_error_never_recovers(self):
        first = evaluate(sample(addon="stopped", adapter_error="SRSP_SYS_PING"))
        later = evaluate(sample(at=1_800_000_040, addon="stopped",
                                adapter_error="SRSP_SYS_PING"), first.state)
        self.assertEqual(later.state.phase, "MONITOR")
        self.assertEqual(later.action, "NONE")

    def test_uncalibrated_observation_or_rx_cannot_confirm_running_hang(self):
        for field in ("observation_valid", "rx_valid"):
            first = evaluate(sample(**{field: False}))
            later = evaluate(sample(at=1_800_000_040, **{field: False}), first.state)
            self.assertEqual(later.action, "NONE")
            self.assertEqual(later.state.phase, "MONITOR")

    def test_first_healthy_sample_after_121_seconds_is_not_stability(self):
        t = 1_800_000_000
        state = State(phase="ESP_VERIFY", stage_since=t, last_sample_utc=t+101)
        healthy = sample(at=t+121, fresh_device_topics_120s=5, srsp_120s=0,
                         bridge_online_fresh=True, herdsman_started_fresh=True)
        result = evaluate(healthy, state)
        self.assertEqual(result.action, "NONE")
        self.assertEqual(result.state.stable_since, t+121)

    def test_unhealthy_or_missing_sample_restarts_stability(self):
        t = 1_800_000_000
        state = State(phase="RADIO_VERIFY", stage_since=t, last_sample_utc=t)
        healthy = sample(at=t+10, fresh_device_topics_120s=5, srsp_120s=0,
                         bridge_online_fresh=True, herdsman_started_fresh=True)
        state = evaluate(healthy, state).state
        bad = evaluate(replace(healthy, utc=t+30, rx_valid=False), state)
        self.assertEqual(bad.state.stable_since, 0)
        resumed = evaluate(replace(healthy, utc=t+50), bad.state)
        self.assertEqual(resumed.state.stable_since, t+50)
        gap = evaluate(replace(healthy, utc=t+111), resumed.state)
        self.assertEqual(gap.state.stable_since, t+111)
        self.assertEqual(gap.action, "NONE")

    def test_all_unacknowledged_actions_hold_at_bounded_deadline(self):
        t = 1_800_000_000
        for phase in ("CAPTURE_PENDING", "STOP_PENDING", "ESP_RESET_PENDING",
                      "RADIO_RESET_PENDING", "ESP_START_PENDING", "RADIO_START_PENDING"):
            with self.subTest(phase=phase):
                state = State(phase=phase, incident_since=t, stage_since=t,
                              last_sample_utc=t+110)
                result = evaluate(sample(at=t+121), state)
                self.assertEqual(result.state.phase, "HOLD")
                self.assertEqual(result.action, "ALERT_HUMAN")

    def test_late_usb_reappearance_does_not_extend_boot_forever(self):
        t = 1_800_000_000
        state = State(phase="ESP_BOOT", incident_since=t, stage_since=t,
                      last_sample_utc=t+170)
        result = evaluate(sample(at=t+181), state)
        self.assertEqual(result.state.phase, "HOLD")
        self.assertEqual(result.action, "ALERT_HUMAN")

    def test_outage_between_suspicions_requires_fresh_confirmation(self):
        first = evaluate(sample())
        later = evaluate(sample(at=1_800_000_070), first.state)
        self.assertEqual(later.state.phase, "SUSPECT")
        self.assertEqual(later.state.suspect_since, 1_800_000_070)
        self.assertEqual(later.action, "NONE")


if __name__ == "__main__":
    unittest.main()
