"""HA warning/notification tests: no device access, no HA calls outside fakes."""
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "host" / "recovery"))

from alerts import HAIncidentReporter, NOTIFICATION_ID, _content


class FakeSupervisor:
    def __init__(self, broken_channel=None):
        self.calls = []
        self.broken = broken_channel

    def call(self, path, *, method="GET", payload=None, **kwargs):
        self.calls.append((path, method, payload))
        if self.broken and self.broken in path:
            raise TimeoutError("Ambiguous service response")
        return []


class HAWarningTests(unittest.TestCase):
    def test_confirmed_hang_emits_warning_in_both_places(self):
        api = FakeSupervisor()
        with TemporaryDirectory() as temp:
            reporter = HAIncidentReporter(api, Path(temp))
            result = reporter.report(
                "DETECTED", 1800000000, "ADAPTER_SPECIFIC_START_FAILURE")
            self.assertEqual(result, {"system_log":"ACCEPTED",
                                      "notification":"ACCEPTED"})
            self.assertEqual(len(api.calls), 2)
            a, b = api.calls
            self.assertEqual(a[0], "/core/api/services/system_log/write")
            self.assertEqual(a[1], "POST")
            self.assertEqual(a[2]["level"], "warning")
            self.assertIn("incident=1800000000", a[2]["message"])
            self.assertEqual(b[0], "/core/api/services/persistent_notification/create")
            self.assertEqual(b[1], "POST")
            self.assertEqual(b[2]["notification_id"], NOTIFICATION_ID)
            self.assertIn("WARNING", b[2]["title"])
            self.assertIn("SLZB-06P7U", b[2]["message"])
            second = reporter.report(
                "DETECTED", 1800000000, "ADAPTER_SPECIFIC_START_FAILURE")
            self.assertTrue(all("ALREADY_ATTEMPTED" in val for val in second.values()))
            self.assertEqual(len(api.calls), 2)

    def test_recovery_updates_same_notification(self):
        api = FakeSupervisor()
        with TemporaryDirectory() as temp:
            r = HAIncidentReporter(api, Path(temp))
            r.report("DETECTED", 1800000000, "MULTI_DEVICE_AF_ZNP_STARVATION")
            r.report("RECOVERED", 1800000000, "REAL_TRAFFIC_VERIFIED_AFTER_ESP")
            self.assertEqual(len(api.calls), 4)
            self.assertEqual(api.calls[3][2]["notification_id"],
                             api.calls[1][2]["notification_id"])
            self.assertEqual(api.calls[2][2]["level"], "info")

    def test_failure_stays_as_warning(self):
        api = FakeSupervisor()
        with TemporaryDirectory() as temp:
            r = HAIncidentReporter(api, Path(temp))
            r.report("DETECTED", 1800000000, "ADAPTER_SPECIFIC_START_FAILURE")
            r.report("RECOVERY_FAILED", 1800000000, "AMBIGUOUS_ACTION")
            self.assertEqual(api.calls[2][2]["level"], "warning")
            self.assertIn("WARNING", api.calls[3][2]["title"])
            self.assertIn("No further reset", api.calls[3][2]["message"])

    def test_ambiguous_api_does_not_spam(self):
        api = FakeSupervisor(broken_channel="persistent_notification")
        with TemporaryDirectory() as temp:
            r = HAIncidentReporter(api, Path(temp))
            result = r.report("DETECTED", 1800000000,
                              "ADAPTER_SPECIFIC_START_FAILURE")
            self.assertIn("NOT_CONFIRMED_NO_REPEAT", result["notification"])
            again = r.report("DETECTED", 1800000000,
                             "ADAPTER_SPECIFIC_START_FAILURE")
            self.assertEqual(len(api.calls), 2)
            self.assertIn("ALREADY_ATTEMPTED", again["notification"])

    def test_bad_reason_is_redacted_and_invalid_incident_rejected(self):
        title,body,level=_content("DETECTED",1800000000,
                                  "secret=network-key")
        self.assertNotIn("secret=network-key",body)
        self.assertIn("COORDINATOR_HEALTH_DEGRADED",body)
        with self.assertRaises(ValueError):
            _content("DETECTED",0,"foo")
        with self.assertRaises(ValueError):
            _content("UNKNOWN",1800000000,"foo")


if __name__=="__main__":
    unittest.main()
