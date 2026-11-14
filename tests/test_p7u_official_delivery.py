"""Official-owner delivery runner: hang phase and automation toggles (no hardware)."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import p7u_official_delivery as runner  # noqa: E402


class Runner(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.work = Path(tmp.name)

    def main(self, *args):
        with patch.object(sys, "argv", ["runner", *args, "--workdir", str(self.work)]):
            return runner.main()

    def installed(self):
        (self.work / "state.json").write_text(json.dumps({"boot_result": {"status": "NATIVE_STATE9"}}))

    def test_hang_needs_installed_delivery_and_explicit_stop(self):
        with patch.object(runner, "driver") as drv, patch.object(runner, "set_window_automations") as auto:
            with self.assertRaisesRegex(SystemExit, "HANG_REFUSED: --workdir"):
                self.main("hang", "--stop-z2m")
            self.installed()
            with self.assertRaisesRegex(SystemExit, "--stop-z2m"):
                self.main("hang")
        drv.assert_not_called()
        auto.assert_not_called()

    def test_hang_never_stops_z2m_with_automations_on(self):
        self.installed()
        with patch.object(runner, "driver") as drv, \
             patch.object(runner, "set_window_automations", side_effect=[False, True]) as auto:
            with self.assertRaisesRegex(SystemExit, "could not be turned off"):
                self.main("hang", "--stop-z2m")
        drv.assert_not_called()
        self.assertEqual([c.args[1] for c in auto.call_args_list], ["off", "on"])

    def test_hang_always_turns_automations_back_on(self):
        self.installed()
        for outcome in (0, 1, RuntimeError("ssh dropped")):
            with patch.object(runner, "driver", side_effect=[outcome] if isinstance(outcome, Exception)
                              else None, return_value=outcome) as drv, \
                 patch.object(runner, "set_window_automations", return_value=True) as auto:
                if isinstance(outcome, Exception):
                    with self.assertRaises(RuntimeError):
                        self.main("hang", "--stop-z2m")
                else:
                    self.assertEqual(self.main("hang", "--stop-z2m"), outcome)
            drv.assert_called_once_with(self.work, "hang")
            self.assertEqual([c.args[1] for c in auto.call_args_list], ["off", "on"])

    def test_automation_toggle_retries_a_timed_out_call(self):
        replies = iter([RuntimeError("timed out"), {"entity": "a", "after": "on"},
                        {"entity": "b", "after": "on"}])

        def ssh(code, exit_on_error=True):
            reply = next(replies)
            if isinstance(reply, Exception):
                raise reply
            return reply

        with patch.object(runner, "ssh_python", side_effect=ssh), patch.object(runner.time, "sleep"):
            self.assertTrue(runner.set_window_automations(self.work, "on"))

    def test_automation_toggle_reports_failure_after_retries(self):
        with patch.object(runner, "ssh_python", side_effect=RuntimeError("timed out")), \
             patch.object(runner.time, "sleep"):
            self.assertFalse(runner.set_window_automations(self.work, "off"))

    def test_preserve_zero_write_hold_never_autorestarts_radio(self):
        operation = "a" * 32
        (self.work / "state.json").write_text(json.dumps({"operation_id": operation, "plan_pin": "f" * 64}))

        def attempted(work, phase, *arguments):
            self.assertEqual(phase, "deploy")
            (self.work / "state.json").write_text(json.dumps({
                "operation_id": operation, "deploy_result": {"status": "HOLD",
                    "reason": "P7U_DEPLOY_HOLD_NATIVE_SECURITY"}}))
            return 1

        with patch.object(runner, "driver", side_effect=attempted) as drv, \
             patch.object(runner, "restore_after_hold") as restore, \
             patch.object(runner, "set_window_automations") as auto:
            self.assertEqual(self.main("flash", "--authorize", operation,
                                       "--on-hold", "preserve"), 1)
            drv.assert_called_once()
            restore.assert_not_called()
            auto.assert_not_called()

    def test_preflight_carries_explicit_held_operation_and_checks_pins(self):
        from argparse import Namespace
        fw = runner.DEFAULTS["firmware"]
        hold_op = "a" * 32
        a = Namespace(firmware=fw, installed=runner.DEFAULTS["installed"],
                      previous_operation=runner.DEFAULTS["previous_operation"],
                      native_run=runner.DEFAULTS["native_run"], package_run="123456",
                      continue_hold=hold_op, workdir=str(self.work))
        def gh(run):
            if run == a.native_run:
                return {"head_sha": fw, "conclusion": "success",
                        "path": ".github/workflows/test-r4-stock20260311-native.yml"}
            return {"conclusion": "success", "event": "workflow_dispatch",
                    "path": ".github/workflows/package-p7u-paired-operator.yml"}
        with patch.object(runner, "gh_run", side_effect=gh), \
             patch.object(runner, "ssh_python", return_value=[{"check": "immutable zero-write security HOLD",
                 "result": "PASS", "detail": {"operation": hold_op[:8]}}]) as remote, \
             patch.object(runner, "prediction_check", return_value={"check": "NV prediction",
                 "result": "WARN", "detail": "capture not staged"}):
            self.assertEqual(runner.run_preflight(a), 0)
        sent = remote.call_args.args[0]
        self.assertIn(hold_op, sent)
        self.assertIn("continued_hold", sent)

if __name__ == "__main__":
    unittest.main()
