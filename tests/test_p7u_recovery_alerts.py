"""HA warning/notification tests: no device access, no HA calls outside fakes."""
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
import json
from unittest.mock import patch
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "host" / "recovery"))

from alerts import (HAIncidentReporter, NOTIFICATION_ID, TEST_NOTIFICATION_ID,
                    _content)


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

    def test_passive_observed_recovery_never_claims_automatic_reset(self):
        api=FakeSupervisor()
        with TemporaryDirectory() as temp:
            r=HAIncidentReporter(api,Path(temp))
            r.report("DETECTED",1800000000,"MULTI_DEVICE_AF_ZNP_STARVATION")
            r.report("OBSERVED_RECOVERED",1800000000,"PASSIVE_OBSERVED_RECOVERED")
            self.assertEqual(len(api.calls),4)
            body=api.calls[-1][2]["message"]
            self.assertIn("No automatic restart",body)
            self.assertIn("120 seconds",body)
            self.assertEqual(api.calls[-1][2]["notification_id"],NOTIFICATION_ID)
            self.assertEqual(api.calls[-2][2]["level"],"info")
            self.assertTrue(all("ALREADY_ATTEMPTED" in x for x in
                r.report("OBSERVED_RECOVERED",1800000000,"PASSIVE_OBSERVED_RECOVERED").values()))
            self.assertEqual(len(api.calls),4)

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
            self.assertIn("NOT_CONFIRMED_RETRY_PENDING", result["notification"])
            again = r.report("DETECTED", 1800000000,
                             "ADAPTER_SPECIFIC_START_FAILURE")
            self.assertEqual(len(api.calls), 2)
            self.assertEqual(again["notification"],"DELIVERY_PENDING_RETRY")

    def test_bad_reason_is_redacted_and_invalid_incident_rejected(self):
        title,body,level=_content("DETECTED",1800000000,
                                  "secret=network-key")
        self.assertNotIn("secret=network-key",body)
        self.assertIn("COORDINATOR_HEALTH_DEGRADED",body)
        with self.assertRaises(ValueError):
            _content("DETECTED",0,"foo")
        with self.assertRaises(ValueError):
            _content("UNKNOWN",1800000000,"foo")

    def test_bad_reason_redacted_in_actual_payloads_and_journals(self):
        api=FakeSupervisor()
        with TemporaryDirectory() as temp:
            r=HAIncidentReporter(api,Path(temp))
            r.report("DETECTED",1800000000,"secret=network-key")
            self.assertNotIn("secret=network-key",json.dumps(api.calls))
            self.assertIn("COORDINATOR_HEALTH_DEGRADED",api.calls[0][2]["message"])
            for path in Path(temp).glob("*.json"):
                self.assertNotIn("secret=network-key",path.read_text())

    def test_idempotent_notification_retry_is_bounded_and_durable(self):
        api=FakeSupervisor(broken_channel="persistent_notification")
        with TemporaryDirectory() as temp, patch("alerts.time.time",return_value=1800000000) as clock:
            directory=Path(temp)
            r=HAIncidentReporter(api,directory)
            r.report("DETECTED",1800000000,"ADAPTER_SPECIFIC_START_FAILURE")
            for seconds in (61,122):
                clock.return_value=1800000000+seconds
                r=HAIncidentReporter(api,directory)  # simulated process restart
                r.retry_pending()
            clock.return_value=1800000200
            self.assertEqual(r.retry_pending()["notification"],"DELIVERY_RETRY_BUDGET_EXHAUSTED")
            self.assertEqual(len(api.calls),4)  # one log plus three same-ID notifications
            self.assertEqual({c[2]["notification_id"] for c in api.calls[1:]},{NOTIFICATION_ID})
            self.assertEqual(len(list(directory.glob("*notification.outcome*.json"))),3)

    def test_recovery_supersedes_failed_detection_retry(self):
        api=FakeSupervisor(broken_channel="persistent_notification")
        with TemporaryDirectory() as temp, patch("alerts.time.time",return_value=1800000000) as clock:
            r=HAIncidentReporter(api,Path(temp))
            r.report("DETECTED",1800000000,"ADAPTER_SPECIFIC_START_FAILURE")
            clock.return_value=1800000001
            api.broken=None
            r.report("RECOVERED",1800000000,"REAL_TRAFFIC_VERIFIED_AFTER_ESP")
            clock.return_value=1800000200
            r.retry_pending()
            old=r.report("DETECTED",1800000000,"ADAPTER_SPECIFIC_START_FAILURE")
            self.assertEqual(old["notification"],"SUPERSEDED_NO_SEND")
            self.assertEqual(len(api.calls),4)
            self.assertIn("recovered",api.calls[-1][2]["title"])

    def test_definite_client_rejection_is_recorded_without_retry(self):
        class Denied(FakeSupervisor):
            def call(self,*args,**kwargs):
                super().call(*args,**kwargs)
                raise HTTPError("http://supervisor",403,"Forbidden",{},None)
        api=Denied()
        with TemporaryDirectory() as temp, patch("alerts.time.time",return_value=1800000000) as clock:
            r=HAIncidentReporter(api,Path(temp))
            result=r.report("DETECTED",1800000000,"ADAPTER_SPECIFIC_START_FAILURE")
            self.assertEqual(result["notification"],"REJECTED_HTTP_403")
            clock.return_value=1800001000
            self.assertEqual(r.retry_pending()["notification"],"DELIVERY_REJECTED_NO_RETRY")
            self.assertEqual(len(api.calls),2)

    def test_ambiguous_system_log_is_not_repeated(self):
        api=FakeSupervisor(broken_channel="system_log")
        with TemporaryDirectory() as temp:
            r=HAIncidentReporter(api,Path(temp))
            result=r.report("DETECTED",1800000000,"ADAPTER_SPECIFIC_START_FAILURE")
            self.assertIn("NOT_CONFIRMED_NO_REPEAT",result["system_log"])
            r.report("DETECTED",1800000000,"ADAPTER_SPECIFIC_START_FAILURE")
            self.assertEqual(len(api.calls),2)

    def test_synthetic_warning_has_dedicated_id_and_cannot_replace_real_incident(self):
        api=FakeSupervisor()
        with TemporaryDirectory() as temp:
            r=HAIncidentReporter(api,Path(temp))
            r.report("DETECTED",1800000000,"ADAPTER_SPECIFIC_START_FAILURE")
            latest=(Path(temp)/"notification-latest.json").read_text()
            r.report_test(1800000100)
            self.assertEqual(api.calls[-1][2]["notification_id"],TEST_NOTIFICATION_ID)
            self.assertIn("TEST",api.calls[-1][2]["title"])
            self.assertIn("no reset",api.calls[-2][2]["message"])
            self.assertEqual((Path(temp)/"notification-latest.json").read_text(),latest)

    def test_malformed_success_body_is_not_accepted(self):
        api=FakeSupervisor()
        api.call=lambda *args,**kwargs:{"result":"error"}
        with TemporaryDirectory() as temp:
            result=HAIncidentReporter(api,Path(temp)).report(
                "DETECTED",1800000000,"ADAPTER_SPECIFIC_START_FAILURE")
            self.assertTrue(all("NOT_CONFIRMED" in value for value in result.values()))


if __name__=="__main__":
    unittest.main()
