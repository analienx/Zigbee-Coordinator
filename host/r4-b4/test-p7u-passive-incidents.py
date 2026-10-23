"""Hosted negative-control tests: passive incident reducer never actuates."""
import importlib.util
from pathlib import Path
import sys
import unittest

file = Path(__file__).with_name("p7u_passive_incidents.py")
spec = importlib.util.spec_from_file_location("p7u_passive_incidents", file)
assert spec and spec.loader
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)

def healthy(t, **kwargs):
    return m.Observation(
        at_mono_ms=t, host_heartbeat_fresh=kwargs.get("heart", True),
        usb_connected=kwargs.get("usb", True),
        parser_progress_fresh=kwargs.get("parser", True),
        mqtt_traffic_fresh=kwargs.get("mqtt", True),
        host_independent=kwargs.get("host_independent", True),
        usb_independent=kwargs.get("usb_independent", True),
    )

class Tests(unittest.TestCase):
    def setUp(self):
        self.l = m.Ledger()
    def trigger(self, now=0, kind="UTIL_SREQ_TIMEOUT", host=False, usb=True):
        return self.l.fault(now, kind, "host",
            host_heartbeat_fresh=host, usb_connected=usb)

    def test_first_util_timeout_latched_with_independent_timing_uncertainty(self):
        e=self.trigger()
        self.assertEqual(e.count, 1)
        self.assertEqual(e.attribution, "HOST_TIMING_UNCERTAIN")
        self.assertFalse(self.l.snapshot()["physical_recovery_allowed"])
        self.assertEqual(self.l.snapshot()["radio_epoch"], "UNKNOWN")

    def test_repeated_timeout_deduplicates_and_keeps_first_timestamp(self):
        self.trigger(100)
        self.trigger(110)
        e=self.trigger(120)
        self.assertEqual((e.first_mono_ms,e.last_mono_ms,e.count),(100,120,3))
        self.assertEqual(len(self.l.snapshot()["active"]),1)
        self.assertEqual(sum(x["first"] for x in self.l.snapshot()["events"]),1)

    def test_real_five_minute_consecutive_rearm(self):
        self.trigger()
        self.assertFalse(self.l.observe(healthy(1000)))
        for minute in range(1,5):
            self.assertFalse(self.l.observe(healthy(1000+minute*60000)))
        self.assertTrue(self.l.observe(healthy(301000)))
        self.assertEqual(self.l.snapshot()["active"],[])
        self.assertEqual(self.l.snapshot()["generation"],1)

    def test_missing_or_unqualified_heartbeats_cannot_rearm(self):
        self.trigger()
        for minute in range(6):
            self.l.observe(healthy(1000+minute*60000,host_independent=False))
        self.assertEqual(len(self.l.snapshot()["active"]),1)
        self.assertEqual(self.l.snapshot()["generation"],0)

    def test_intermittent_usb_detach_restarts_healthy_window(self):
        self.trigger()
        for minute in range(5):
            self.l.observe(healthy(1000+minute*60000))
        self.assertFalse(self.l.observe(healthy(301000,usb=False)))
        self.assertEqual(len(self.l.snapshot()["active"]),1)
        self.assertFalse(self.l.observe(healthy(361000)))
        self.assertEqual(self.l.snapshot()["generation"],0)

    def test_time_acceleration_and_missing_interval_do_not_rearm(self):
        self.trigger()
        for i in range(5):
            self.assertFalse(self.l.observe(healthy(1000+i*1000)))
        self.assertFalse(self.l.observe(healthy(400000)))
        self.assertEqual(self.l.snapshot()["generation"],0)

    def test_parser_uncertainty_prevents_rearm(self):
        self.trigger()
        for i in range(6):
            self.assertFalse(self.l.observe(healthy(1000+i*60000,parser=False)))
        self.assertEqual(len(self.l.snapshot()["active"]),1)

    def test_clock_regression_holds(self):
        self.trigger(1000)
        with self.assertRaisesRegex(ValueError,"UNTRUSTED_CLOCK"):
            self.l.observe(healthy(900))

    def test_private_bounded_ring(self):
        for i in range(300):
            self.trigger(i)
        s=self.l.snapshot()
        self.assertEqual(len(s["events"]),256)
        self.assertEqual(s["dropped"],44)
        self.assertNotIn("ieeeAddr",str(s))
        self.assertNotIn("network_key",str(s))

    def test_radio_failure_never_proven_from_sreq_timeout(self):
        incident=self.trigger(host=True)
        self.assertEqual(incident.attribution, "RADIO_SUSPECT_NOT_PROVEN")
        self.assertFalse(self.l.snapshot()["physical_recovery_allowed"])

if __name__ == "__main__":
    unittest.main()
