"""Offline evidence-boundary tests. No broker, HA, serial or hardware accessed."""
from datetime import datetime
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import mock_open, patch
from zoneinfo import ZoneInfo

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "host" / "recovery"))
import observer as module
from observer import PassiveObserver, start_failure_kind, timestamp
from mqtt_settings import load_broker_settings

T = 1_800_000_000
DEVICES = [{"friendly_name": name, "ieee_address": f"0x{i:016x}", "type": "Router"}
           for i, name in enumerate(("one", "two", "three"), 1)]


def log(at, text):
    stamp = datetime.fromtimestamp(at, ZoneInfo("Europe/Prague")).strftime("%Y-%m-%d %H:%M:%S")
    return f"[{stamp}] info: z2m: {text}"


def history(start=T - 300):
    return [log(start, "Starting Zigbee2MQTT version 2.14.0 (commit #test)"),
            log(start + 1, "zigbee-herdsman started (resumed)"),
            log(start + 2, "Zigbee2MQTT started!")]


def prepared():
    obs = PassiveObserver(last_seen_epoch=True, admission_floor=T)
    obs.seed_process_history(iter(history()), T)
    obs.connected = obs.subscribed = True
    obs.ingest_mqtt("zigbee2mqtt/bridge/devices", json.dumps(DEVICES), retained=True, now=T)
    obs.read_log("\n".join(history() + [log(T, "Current process heartbeat")]), T)
    return obs


def rx(obs, at=T):
    for row in DEVICES:
        obs.ingest_mqtt("zigbee2mqtt/" + row["friendly_name"],
                        json.dumps({"last_seen": at * 1000, "state": "ON"}), now=at)


class RadioEvidenceTests(unittest.TestCase):
    def test_startup_cache_retained_unknown_and_group_topics_never_count(self):
        obs = prepared()
        for topic, value, retained in (
            ("one", {"last_seen": (T - 1) * 1000}, False),
            ("one", {"last_seen": T * 1000}, True),
            ("unknown", {"last_seen": T * 1000}, False),
            ("group", {"last_seen": T * 1000}, False),
        ):
            obs.ingest_mqtt("zigbee2mqtt/" + topic, json.dumps(value), retained=retained, now=T)
        self.assertEqual(obs.sample(T)["fresh_device_topics_120s"], 0)
        self.assertFalse(obs.sample(T)["rx_valid"])

    def test_strict_advancement_uses_rf_time_not_mqtt_delivery_time(self):
        obs = prepared()
        rx(obs)
        self.assertTrue(obs.sample(T)["rx_valid"])
        self.assertEqual(obs.sample(T)["fresh_device_topics_120s"], 3)
        for row in DEVICES:
            obs.ingest_mqtt("zigbee2mqtt/" + row["friendly_name"],
                            json.dumps({"last_seen": T * 1000, "state": "OFF"}), now=T + 121)
        self.assertEqual(obs.sample(T + 121)["fresh_device_topics_120s"], 0)
        rx(obs, T + 122)
        self.assertEqual(obs.sample(T + 122)["fresh_device_topics_120s"], 3)

    def test_malformed_known_device_is_unknown_until_valid_rf_resumes(self):
        obs = prepared()
        rx(obs)
        for value in ("invalid-json", '[]', '{"last_seen":true}', '{"last_seen":"bad"}'):
            obs.ingest_mqtt("zigbee2mqtt/one", value, now=T + 1)
            self.assertFalse(obs.sample(T + 1)["rx_valid"])
            obs.ingest_mqtt("zigbee2mqtt/one", json.dumps({"last_seen": (T + 2) * 1000}), now=T + 2)
            self.assertTrue(obs.sample(T + 2)["rx_valid"])
            # Restore a new RF high-water mark for the next iteration.
            obs._last_seen.pop(DEVICES[0]["ieee_address"], None)

    def test_missing_last_seen_capability_cannot_interpret_silence(self):
        obs = prepared()
        rx(obs)
        obs.set_last_seen_epoch(False)
        self.assertFalse(obs.sample(T)["rx_valid"])
        self.assertEqual(obs.sample(T)["fresh_device_topics_120s"], 0)

    def test_duplicate_inventory_alias_invalidates_observation(self):
        obs = prepared()
        obs.ingest_mqtt("zigbee2mqtt/bridge/devices", json.dumps(DEVICES + [DEVICES[0]]), retained=True, now=T)
        self.assertFalse(obs.sample(T)["observation_valid"])


class ProcessEvidenceTests(unittest.TestCase):
    def test_history_tracks_delivery_line_coverage_without_counting_echo_errors(self):
        obs = PassiveObserver(last_seen_epoch=True, admission_floor=T)
        rows = history() + [log(T, "MQTT publish: topic 'zigbee2mqtt/bridge/response/x', payload 'SRSP - AF - dataRequest after 6000ms'")]
        obs.seed_process_history(iter(rows), T)
        obs.read_log(rows[-1], T)
        self.assertFalse(obs.sample(T)["log_gap"])
        self.assertFalse(obs.sample(T)["ota_unknown"])
        self.assertEqual(obs.sample(T)["srsp_120s"], 0)

    def test_repeated_prefix_is_idempotent(self):
        obs = prepared()
        rx(obs)
        obs.ingest_mqtt("zigbee2mqtt/bridge/state", '{"state":"online"}', now=T)
        obs.seed_process_epoch("\n".join(history()), T + 1)
        self.assertEqual(obs.sample(T + 1)["fresh_device_topics_120s"], 3)
        self.assertTrue(obs.sample(T + 1)["bridge_online_fresh"])
        self.assertFalse(obs.sample(T + 1)["ota_unknown"])

    def test_canonical_error_wrappers_and_semantic_deduplication(self):
        obs = prepared()
        rows = [
            log(T, "Publish 'set' 'state' to 'one' failed: SRSP - AF - dataRequest after 6000ms"),
            log(T, "Read response to 0x0000000000000001 failed (SRSP - AF - dataRequest after 6000ms)"),
            log(T, "Failed to poll onOff from two (ZCL command 0x0000000000000002/1 SRSP - AF - dataRequest after 6000ms)"),
            log(T, "Failed to configure 'three' (SRSP - ZDO - bindReq after 6000ms)"),
            log(T, "Failed to ping 'unknown' (SRSP - AF - dataRequest after 6000ms)"),
            log(T, "MQTT publish: topic 'zigbee2mqtt/bridge/response/x', Failed to ping 'one' SRSP - AF - dataRequest after 6000ms"),
        ]
        obs.read_log("\n".join(history() + rows), T)
        obs.read_log("\n".join(history() + rows), T + 1)
        result = obs.sample(T + 1)
        self.assertEqual(result["srsp_120s"], 3)
        self.assertEqual(result["affected_devices_120s"], 3)

    def test_new_epoch_excludes_previous_start_failure(self):
        old = log(T - 30, "SRSP - AF - register after 6000ms")
        new = history(T - 10)
        self.assertEqual(start_failure_kind("\n".join([old] + new), T), "")
        obs = prepared()
        obs.seed_process_epoch("\n".join(new), T)
        obs.read_log("\n".join([old] + new), T)
        self.assertEqual(obs.sample(T)["adapter_error"], "")

    def test_start_cutoff_handles_log_second_precision_and_manual_stop(self):
        obs = prepared()
        obs.begin_startup(T + 0.5)
        new = history(T)
        rows = new + [log(T + 3, "SRSP - SYS - ping after 6000ms")]
        obs.read_log("\n".join(rows), T + 4)
        self.assertEqual(obs.sample(T + 4)["adapter_error"], "SRSP_SYS_PING")
        stop = log(T + 5, "Stopping Zigbee2MQTT (restart=false, code=0, signal=SIGTERM)")
        obs.read_log("\n".join(rows + [stop]), T + 6)
        self.assertTrue(obs.sample(T + 6)["manual_stop"])
        self.assertEqual(obs.sample(T + 6)["adapter_error"], "")

    def test_tail_gap_and_repeated_old_tail_do_not_claim_fresh_health(self):
        obs = prepared()
        obs.read_log("\n".join(history() + [log(T, "Current process heartbeat")]), T + 41)
        self.assertFalse(obs.sample(T + 41)["observation_valid"])
        obs.read_log(log(T + 42, "A tail that dropped previous coverage"), T + 42)
        self.assertTrue(obs.sample(T + 42)["log_gap"])
        self.assertTrue(obs.sample(T + 42)["ota_unknown"])
        obs.seed_process_history(iter(history() + [log(T, "Heartbeat"), log(T + 42, "More")]), T + 42)
        self.assertFalse(obs.sample(T + 42)["log_gap"])

    def test_malformed_timestamp_is_ignored(self):
        self.assertIsNone(timestamp("[2026-99-22 19:59:00] error: bad"))


class OtaEvidenceTests(unittest.TestCase):
    def test_old_active_update_survives_history_age_and_message_expiry(self):
        obs = PassiveObserver(admission_floor=T)
        obs.ingest_mqtt("zigbee2mqtt/bridge/devices", json.dumps(DEVICES), retained=True, now=T)
        rows = history(T - 2000) + [log(T - 1900, "Updating 'one' to latest firmware"), log(T, "Current heartbeat")]
        obs.seed_process_history(iter(rows), T)
        self.assertTrue(obs.sample(T + 10000)["ota_active"])
        self.assertFalse(obs.sample(T)["ota_unknown"])

    def test_real_structured_start_progress_and_terminal_states(self):
        obs = prepared()
        obs.ingest_mqtt("zigbee2mqtt/bridge/logging", json.dumps({
            "namespace": "z2m", "level": "info", "message": "OTA updating 'one' to latest firmware"}), now=T)
        self.assertTrue(obs.sample(T)["ota_active"])
        obs.ingest_mqtt("zigbee2mqtt/one", json.dumps({"last_seen": T * 1000,
                                                     "update": {"state": "updating", "progress": 50}}), now=T + 1)
        self.assertTrue(obs.sample(T + 1)["ota_active"])
        obs.ingest_mqtt("zigbee2mqtt/one", json.dumps({"last_seen": T * 1000,
                                                     "update": {"state": "idle"}}), now=T + 2)
        self.assertFalse(obs.sample(T + 2)["ota_active"])

    def test_older_terminal_log_cannot_clear_new_live_ota(self):
        obs = prepared()
        obs.ingest_mqtt("zigbee2mqtt/bridge/logging", json.dumps({
            "namespace": "z2m", "level": "info", "message": "Updating 'one' to latest firmware"}), now=T + 10)
        obs.read_log("\n".join(history() + [log(T + 1, "Finished update of 'one'")]), T + 11)
        self.assertTrue(obs.sample(T + 11)["ota_active"])

    def test_incomplete_history_and_prefix_only_stay_unknown(self):
        obs = PassiveObserver(admission_floor=T)
        obs.seed_process_epoch("\n".join(history()), T)
        self.assertTrue(obs.sample(T)["ota_unknown"])
        def interrupted():
            yield history()[0]
            raise OSError("interrupted file read")
        with self.assertRaises(OSError):
            obs.seed_process_history(interrupted(), T)
        self.assertTrue(obs.sample(T)["ota_unknown"])


class SubscriptionTests(unittest.TestCase):
    def test_connack_and_denied_or_wrong_suback_do_not_establish_observation(self):
        class Client:
            def subscribe(self, *args, **kwargs): return 0, 17
            def connect(self, *args, **kwargs): pass
            def loop_start(self): pass
        client = Client()
        class MQTT:
            class CallbackAPIVersion:
                VERSION2 = 2
            @staticmethod
            def Client(*args, **kwargs): return client
        obs = PassiveObserver(admission_floor=T)
        with patch.object(module, "mqtt", MQTT):
            obs.start("broker", 1883, "", "")
        client.on_connect(client, None, None, 0, None)
        self.assertFalse(obs.sample(T)["mqtt_reachable"])
        client.on_subscribe(client, None, 17, [128], None)
        self.assertFalse(obs.sample(T)["mqtt_reachable"])
        client.on_subscribe(client, None, 99, [0], None)
        self.assertFalse(obs.sample(T)["mqtt_reachable"])
        client.on_subscribe(client, None, 17, [0], None)
        self.assertTrue(obs.sample(T)["mqtt_reachable"])


class BrokerSettingsTests(unittest.TestCase):
    def load(self, text):
        with patch.object(Path, "open", mock_open(read_data=text)):
            return load_broker_settings(Path("/homeassistant/zigbee2mqtt/configuration.yaml"))

    def test_existing_base_topic_and_last_seen_capability_are_preserved(self):
        broker = self.load("mqtt:\n  server: mqtt://broker:1883\n  base_topic: house/zigbee\nadvanced:\n  last_seen: epoch\n")
        self.assertEqual(broker.base_topic, "house/zigbee")
        self.assertTrue(broker.last_seen_epoch)

    def test_malformed_configuration_never_becomes_valid_broker_evidence(self):
        for text in ("- list-root", "mqtt: []", "mqtt:\n  server: mqtt://:secret@broker\n",
                     "mqtt:\n  server: mqtt://broker:0\n", "mqtt:\n  server: mqtt://broker\n  base_topic: '#'\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.load(text)


if __name__ == "__main__":
    unittest.main()
