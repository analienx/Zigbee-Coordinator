"""Runner integration: no HA, MQTT, serial or production hardware."""
from dataclasses import replace
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "host" / "recovery"))
from policy import Observation, State
from run import GuardRunner, active_admission, configuration, owner_configuration_valid


class FakeActor:
    def __init__(self, timeout=False):
        self.calls = []
        self.timeout = timeout
    def perform_once(self, action):
        self.calls.append(action)
        if self.timeout:
            raise TimeoutError("ambiguous")
        return True


class FakeReporter:
    def __init__(self):
        self.calls = []
    def report(self, *args):
        self.calls.append(args)
        return {"system_log": "ACCEPTED", "notification": "ACCEPTED"}


class FakeObserver:
    def begin_startup(self, *args):
        pass


def fault(now=1800000000):
    return Observation(utc=now, addon="error", adapter_error="SRSP_SYS_PING",
        expected_identity=True, expected_usb=True, esp_reachable=True,
        ha_reachable=True, mqtt_reachable=True)


class RunnerTests(unittest.TestCase):
    def test_full_esp_transaction_uses_one_restart_and_start(self):
        with TemporaryDirectory() as directory:
            actor = FakeActor()
            runner = GuardRunner(Path(directory), actor, FakeReporter(), FakeObserver())
            for delta, addon in ((0,"error"),(40,"error"),(60,"error"),
                                 (80,"stopped"),(100,"stopped"),(120,"stopped")):
                runner.step(replace(fault(1800000000+delta),addon=addon),active=True)
            runner.step(replace(fault(1800000140),addon="started"),active=True)
            for delta in range(160,281,20):
                state=runner.step(replace(fault(1800000000+delta),addon="started",
                    adapter_error="",srsp_120s=0,fresh_device_topics_120s=5,
                    bridge_online_fresh=True,herdsman_started_fresh=True,
                    health_fresh=True),active=True)
            self.assertEqual(state.phase,"COMPLETE")
            self.assertEqual(actor.calls,["CAPTURE_EVIDENCE","STOP_Z2M","RESTART_ESP","START_Z2M"])
            runner.step(replace(fault(1800000300),addon="started"),active=True)
            self.assertEqual(runner.state.phase,"MONITOR")
            self.assertEqual(runner.receipts,{})

    def test_failed_esp_stage_allows_only_one_radio_fallback(self):
        with TemporaryDirectory() as directory:
            actor=FakeActor()
            runner=GuardRunner(Path(directory),actor,FakeReporter(),FakeObserver())
            for delta,addon in ((0,"error"),(40,"error"),(60,"error"),
                (80,"stopped"),(100,"stopped"),(120,"stopped"),(140,"started")):
                runner.step(replace(fault(1800000000+delta),addon=addon),active=True)
            for delta in (160,180,200,220,240):
                runner.step(replace(fault(1800000000+delta),adapter_error="SRSP_AF_REGISTER"),active=True)
            self.assertEqual(runner.state.phase,"HOLD")
            self.assertEqual(actor.calls.count("RESTART_ESP"),1)
            self.assertEqual(actor.calls.count("RESET_RADIO"),1)
            self.assertEqual(actor.calls.count("START_Z2M"),2)
            runner.step(fault(1800000260),active=True)
            self.assertEqual(actor.calls.count("RESET_RADIO"),1)

    def test_dry_run_preserves_suspicion_and_never_calls_actor(self):
        with TemporaryDirectory() as directory:
            actor, reporter = FakeActor(), FakeReporter()
            runner = GuardRunner(Path(directory), actor, reporter, FakeObserver())
            first = runner.step(fault())
            self.assertEqual(first.phase, "SUSPECT")
            final = runner.step(fault(1800000040), notify=True)
            self.assertEqual(final.phase, "CAPTURE_PENDING")
            self.assertTrue(final.incident_id)
            self.assertEqual(actor.calls, [])
            self.assertEqual(runner.state.phase, "MONITOR")
            self.assertEqual(runner.receipts, {})
            self.assertEqual(reporter.calls[0][0], "DETECTED")

    def test_active_ambiguous_capture_holds_and_warns(self):
        with TemporaryDirectory() as directory:
            actor, reporter = FakeActor(timeout=True), FakeReporter()
            runner = GuardRunner(Path(directory), actor, reporter, FakeObserver())
            runner.step(fault(), active=True, notify=True)
            state = runner.step(fault(1800000040), active=True, notify=True)
            self.assertEqual(state.phase, "HOLD")
            self.assertEqual(actor.calls, ["CAPTURE_EVIDENCE"])
            self.assertEqual(reporter.calls[-1][0], "RECOVERY_FAILED")
            runner.step(fault(1800000060), active=True, notify=True)
            self.assertEqual(actor.calls, ["CAPTURE_EVIDENCE"])

    def test_maintenance_changed_before_dispatch_blocks_side_effect(self):
        with TemporaryDirectory() as directory:
            actor = FakeActor()
            runner = GuardRunner(Path(directory), actor, FakeReporter(), FakeObserver(),
                pre_action=lambda state: replace(fault(1800000040), maintenance=True))
            runner.step(fault(), active=True)
            state = runner.step(fault(1800000040), active=True)
            self.assertEqual(state.phase, "HOLD")
            self.assertEqual(actor.calls, [])

    def test_dry_run_does_not_erase_real_hold(self):
        with TemporaryDirectory() as directory:
            runner = GuardRunner(Path(directory), FakeActor(), FakeReporter(), FakeObserver())
            runner.hold("AMBIGUOUS_ACTION", False)
            runner.step(fault())
            self.assertEqual(runner.state.phase, "HOLD")
            restarted = GuardRunner(Path(directory), FakeActor(), FakeReporter(), FakeObserver())
            self.assertEqual(restarted.state.phase, "HOLD")

    def test_active_mode_requires_explicit_admission(self):
        opts = dict(enabled=True, dry_run=False, maintenance=False,
                    allow_private_http_fallback=True)
        self.assertFalse(active_admission(opts, configuration(opts)))

    def test_owner_configuration_checks_actual_serial_options(self):
        cfg = configuration(dict(allow_private_http_fallback=False))
        info = {"watchdog": False, "options": {"serial": {
            "port": "/dev/serial/by-id/" + cfg.expected_by_id, "adapter": "zstack",
            "baudrate": 115200, "rtscts": False}, "socat": {"enabled": False}}}
        self.assertTrue(owner_configuration_valid(info, cfg))
        info["watchdog"] = True
        self.assertFalse(owner_configuration_valid(info, cfg))


if __name__ == "__main__":
    unittest.main()
