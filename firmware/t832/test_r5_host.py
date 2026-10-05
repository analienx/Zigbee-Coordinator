from __future__ import annotations
import datetime as dt
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import t832_incident as incident
import t832_sideband as sideband


class R5HostTests(unittest.TestCase):
    def event(self, kind, seconds=0, **fields):
        return sideband.validate({"schema": sideband.SCHEMA, "kind": kind, "observer": "test-owner",
            "utc": incident.iso(self.now + dt.timedelta(seconds=seconds)), **fields})

    def setUp(self):
        self.now = incident.utcnow()

    def test_exact_reset_classes(self):
        for raw, expected in ((0, "PWR_ON"), (1, "PIN_RESET"), (4, "VDDR_LOSS"), (6, "SYSRESET"), (7, "WARMRESET")):
            record = struct.pack("<IIHBBHHHH", 0, 0, 1, 1, 0, raw, 9, 1, 1)
            self.assertEqual(incident.decode_record(record, 0)["reset_class"], expected)

    def test_missing_boot_is_not_reset_success(self):
        request = self.event("reset_request", attempt_id="reset-1", radio_index=1, tier="pin")
        report = sideband.correlate([request])
        self.assertIn("unproven", report["reset_attempts"][0]["outcome"])
        power = self.event("p10_boot", seconds=1, radio_index=1, reset_source=0)
        self.assertEqual(sideband.correlate([request, power])["reset_attempts"][0]["outcome"],
                         "unexpected-or-unclassified-reset-class")
        pin = self.event("p10_boot", seconds=1, radio_index=1, reset_source=1)
        self.assertEqual(sideband.correlate([request, pin])["reset_attempts"][0]["outcome"], "expected-reset-class")
        wrong_radio = self.event("p10_boot", seconds=1, radio_index=0, reset_source=1)
        self.assertIn("unproven", sideband.correlate([request, wrong_radio])["reset_attempts"][0]["outcome"])

    def test_startup_requires_fresh_owner_timeout_and_addon(self):
        addon = self.event("addon_health", seconds=-10, startup_id="boot-1", state="started",
                           startup_utc=incident.iso(self.now - dt.timedelta(seconds=90)), radio_index=1)
        probe = self.event("znp_health", seconds=-5, startup_id="boot-1", owner="herdsman",
                           command="SYS_PING", success=False, timed_out=True, deadline_ms=15000, radio_index=1)
        self.assertTrue(sideband.startup_verdict([addon, probe], "boot-1", self.now)["qualifies"])
        for events in ([addon], [probe], [], [addon, {**probe, "success": True}],
                       [addon, {**probe, "utc": incident.iso(self.now - dt.timedelta(seconds=70))}]):
            self.assertFalse(sideband.startup_verdict(events, "boot-1", self.now)["qualifies"])
        self.assertFalse(sideband.startup_verdict([addon, probe], "boot-2", self.now)["qualifies"])

    def test_private_sideband_ingest_and_capture_share_latch(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = incident.Store(Path(temporary) / "state")
            incoming = Path(temporary) / "input.jsonl"
            rows = [self.event("addon_health", seconds=-10, startup_id="boot-1", state="started",
                startup_utc=incident.iso(self.now - dt.timedelta(seconds=90)), radio_index=1),
                self.event("znp_health", seconds=-5, startup_id="boot-1", owner="herdsman",
                    command="ZDO", success=False, timed_out=True, deadline_ms=15000, radio_index=1)]
            incoming.write_text("\n".join(json.dumps(row) for row in rows))
            sideband.ingest(store, incoming)
            result = incident.capture(store, trigger="startup_health", trigger_payload={"startup_id": "boot-1"},
                sources=[], config_fingerprint=None, initial_tail_bytes=1 << 20,
                retain_days=7, max_bytes=1 << 30, window_seconds=900, deadline_seconds=30)
            latch = store.load_strict(store.latch)
            self.assertTrue(latch["trigger_qualifying"])
            self.assertEqual(latch["status"], "captured")
            self.assertFalse(latch["reset_used"])
            with self.assertRaises(RuntimeError):
                incident.capture(store, trigger="startup_health", trigger_payload={"startup_id": "boot-1"},
                    sources=[str(store.host_events)], config_fingerprint=None, initial_tail_bytes=1 << 20,
                    retain_days=7, max_bytes=1 << 30, window_seconds=900, deadline_seconds=30)

    def test_malformed_batch_writes_nothing(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = incident.Store(Path(temporary) / "state")
            incoming = Path(temporary) / "input.jsonl"
            incoming.write_text(json.dumps(self.event("usb_identity", vid="1a86", pid="55d4")) + '\n{"schema":"bogus"}')
            with self.assertRaises(ValueError):
                sideband.ingest(store, incoming)
            self.assertFalse(store.host_events.exists())


if __name__ == "__main__":
    unittest.main()
