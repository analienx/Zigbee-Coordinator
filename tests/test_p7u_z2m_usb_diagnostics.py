"""No hardware, SSH, MQTT or process execution: offline diagnosis regressions."""
import datetime as dt
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] /
    "firmware/slzb-06p7u/r4/release"))
import p7u_z2m_usb_acceptance as start
import p7u_z2m_usb_health as health


class USBRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.started = health.start_local_time("2026-10-22T16:38:24+00:00", "+0200")
        self.before = ["[2026-10-20 19:29:53] error: AREQ - SYS - resetInd",
                       "[2026-10-20 19:29:53] error: Failed to start zigbee-herdsman"]
        self.after = [
            "[2026-10-22 18:38:28] info: z2m: zigbee-herdsman started",
            "[2026-10-22 18:38:29] info: z2m: Zigbee2MQTT started",
            "[2026-10-22 18:38:30] info: z2m: Connected to MQTT server",
            "[2026-10-22 18:38:50] info: z2m:mqtt: MQTT publish: topic 'zigbee2mqtt/RouterA', payload '{}'",
            "[2026-10-22 18:38:51] info: z2m:mqtt: MQTT publish: topic 'zigbee2mqtt/RouterB', payload '{}'",
            "[2026-10-22 18:38:52] info: z2m:mqtt: MQTT publish: topic 'zigbee2mqtt/PIR', payload '{}'",
            "[2026-10-22 18:38:53] warning: z2m: Failed to ping 'RouterX' (NWK_NO_ROUTE)"]

    def test_ha_timezone(self):
        self.assertEqual(self.started.hour, 18)
        self.assertEqual(self.started.minute, 38)
        with self.assertRaises(ValueError):
            health.start_local_time("2026-10-22T16:00:00", "+0200")
        with self.assertRaises(ValueError):
            health.start_local_time("2026-10-22T16:00:00Z", "secret")

    def test_old_failure_excluded_by_timestamp(self):
        matched = health.since_start(self.before + self.after, self.started)
        self.assertEqual(matched, self.after)
        report = health.diagnostic(matched, "started")
        self.assertEqual(report["status"], "RUNNING_WITH_LIVE_DEVICE_MQTT")
        self.assertEqual(report["distinct_mqtt_device_topics"], 3)
        self.assertEqual(report["nwk_no_route_counts"].get("RouterX"), 1)
        self.assertEqual(report["startup_error_signatures"], [])

    def test_baseline_anchor_eviction_falls_back_to_timestamp(self):
        self.assertEqual(start.after_baseline(self.after, self.before, self.started),
                         self.after)
        self.assertEqual(start.after_baseline(self.before + self.after, self.before),
                         self.after)
        self.assertEqual(start.after_baseline(self.after, self.before), [])

    def test_no_false_positive_without_mqtt(self):
        self.assertEqual(health.diagnostic([], "started")["status"],
                         "STARTED_WITHOUT_ENOUGH_LOG_EVIDENCE")
        self.assertEqual(health.diagnostic(self.after, "error")["status"],
                         "NOT_RUNNING")

    def test_old_failure_does_not_poison_new_success(self):
        self.assertEqual(start.classify("started", self.after)["status"],
                         "RUNNING_LOGS_CONFIRMED")
        self.assertEqual(start.classify("error", self.after)["status"],
                         "FAILED")
        self.assertEqual(start.classify("started", self.before)["status"],
                         "FAILED")

    def test_redaction(self):
        self.assertNotIn("mysecret", start.redacted("password: mysecret"))
        self.assertNotIn("abc", start.redacted("Bearer abc"))
        self.assertNotIn("\x1b", start.redacted("\x1b[31mERROR"))

    def test_vendor_flash_ui_is_not_proof_of_backend_safety(self):
        import p7u_slzb_ui_flash_audit as audit
        candidate = {"source_sha": audit.SOURCE,
                     "separate_ac000_handoff_required": True}
        ui = ("#customZBotaForm /fileUpload?customName=/fw.bin "
              "flashZBstartProgress API_FLASH_ZB eraseNVM local=1").encode()
        report = audit.qualification(ui, candidate)
        self.assertTrue(report["onboard_ui_local_flash_detected"])
        self.assertFalse(report["can_flash_with_this_audit"])
        self.assertEqual(report["status"], "HOLD_BACKEND_ERASE_SCOPE_UNPROVEN")
        # Even a documented web route must remain blocked without backend proof.
        self.assertFalse(audit.qualification(b"", candidate)["onboard_ui_local_flash_detected"])

    def test_no_route_warning_needs_no_route_error(self):
        messages = ["[2026-10-22 18:38:53] warning: Failed to ping 'Lamp' timeout",
                    "[2026-10-22 18:38:54] warning: Failed to ping 'Plug' NWK_NO_ROUTE"]
        report = health.diagnostic(messages, "started")
        self.assertEqual(report["nwk_no_route_counts"], {"Plug": 1})


if __name__ == "__main__":
    unittest.main()
