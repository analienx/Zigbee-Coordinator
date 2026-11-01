"""Workstation flash driver: fail-closed gates that survive `python -O`."""
import ast
import re
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import p7u_ha_flash_driver as driver

FW = "a" * 40


class FlashDriver(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.d = driver.Driver(tmp.name)

    def test_no_assert_gates_in_driver_or_remote_snippets(self):
        tree = ast.parse((ROOT / "tools/p7u_ha_flash_driver.py").read_text())
        self.assertFalse([n for n in ast.walk(tree) if isinstance(n, ast.Assert)])
        for name in ("EXTRACT", "VERIFY_STAGE", "STAGE_BINDING", "SERVING", "STARTUP_SUMMARY", "HOLD_BINDING"):
            snippet = getattr(driver, name)
            self.assertIsNone(re.search(r"\bassert\b", snippet), name)
        # Every remote need() call takes exactly (condition, reason).
        fill = {"EXTRACT": tuple("abcde") + (True,), "VERIFY_STAGE": tuple("abcd"),
                "SERVING": ("app_" + driver.LEGACY_OWNER, driver.HOST_IMAGE),
                "STAGE_BINDING": {k: "x" for k in ("op", "installed", "source", "oldinput",
                                                   "oldcand", "newinput", "newbind", "fw")}}
        for name, args in fill.items():
            for node in ast.walk(ast.parse(getattr(driver, name) % args)):
                if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "need":
                    self.assertEqual(len(node.args), 2, name + ":" + ast.unparse(node)[:80])
        self.assertIn("unknownTopicsRejected", driver.SERVING)
        self.assertIn("rh:2", driver.SERVING)

    def fetch(self, native, package):
        args = SimpleNamespace(firmware=FW, native_run=1, package_run=2, installed="b" * 40,
                               previous_operation="c" * 32)
        runs = {1: native, 2: package}
        with patch.object(driver, "run_meta", side_effect=lambda run: runs[run]), \
             patch.object(driver.subprocess, "run") as run:
            with self.assertRaises(SystemExit) as stop:
                self.d.fetch(args)
            run.assert_not_called()  # refused before any download
        return str(stop.exception)

    def test_fetch_refuses_pr_package_and_inexact_native_runs(self):
        native = {"path": driver.NATIVE_WORKFLOW, "head_sha": FW, "status": "completed",
                  "conclusion": "success"}
        package = {"path": driver.PACKAGE_WORKFLOW, "event": "pull_request", "status": "completed",
                   "conclusion": "success", "head_sha": "d" * 40}
        self.assertIn("PACKAGE_RUN_NOT_EXPLICIT_DISPATCH_SUCCESS", self.fetch(native, package))
        self.assertIn("NATIVE_RUN_NOT_EXACT_SUCCESS",
                      self.fetch(dict(native, head_sha="e" * 40), dict(package, event="workflow_dispatch")))
        self.assertIn("NATIVE_RUN_NOT_EXACT_SUCCESS",
                      self.fetch(dict(native, conclusion="failure"), package))

    def test_serving_requires_operator_state9_marker_proof(self):
        self.d.save(boot_result={"status": "HOLD"})
        with patch.object(sys, "argv", ["driver", "serving", "--workdir", str(self.d.workdir)]), \
             patch.object(driver.Driver, "remote_python") as remote:
            with self.assertRaises(SystemExit) as stop:
                driver.main()
            remote.assert_not_called()
        self.assertIn("SERVING_WITHOUT_OPERATOR_STATE9_MARKER_PROOF", str(stop.exception))

    def test_live_phases_never_replay_a_consumed_intent(self):
        self.d.save(operation_id="f" * 32, plan_pin="1" * 64, deploy_result={"status": "X"},
                    boot_intent=1.0)
        with patch.object(driver.Driver, "operator") as op:
            with self.assertRaises(SystemExit) as stop:
                self.d.live("boot", "boot-native", 300, require="deploy_result")
            op.assert_not_called()
        self.assertIn("BOOT_CONSUMED", str(stop.exception))


    def test_repackage_only_after_boot_and_only_explicit_dispatch(self):
        self.d.save(firmware=FW, candidate_pin="1" * 64, deploy_result={"status": "X"})
        with patch.object(driver, "run_meta") as meta:
            with self.assertRaises(SystemExit) as stop:
                self.d.repackage(SimpleNamespace(package_run=3))
            meta.assert_not_called()
        self.assertIn("REPACKAGE_BEFORE_BOOT", str(stop.exception))
        self.d.save(boot_result={"status": "NATIVE_STATE9"})
        pr = {"path": driver.PACKAGE_WORKFLOW, "event": "pull_request", "status": "completed",
              "conclusion": "success"}
        with patch.object(driver, "run_meta", return_value=pr),              patch.object(driver.subprocess, "run") as run:
            with self.assertRaises(SystemExit) as stop:
                self.d.repackage(SimpleNamespace(package_run=3))
            run.assert_not_called()
        self.assertIn("PACKAGE_RUN_NOT_EXPLICIT_DISPATCH_SUCCESS", str(stop.exception))

    def test_hang_stops_host_captures_then_restarts_with_one_retry(self):
        self.d.save(operation_id="f" * 32, plan_pin="1" * 64)
        calls = []
        outputs = iter([driver.HOST_IMAGE + "\n", "", "exited " + driver.HOST_IMAGE,
                        "running " + driver.HOST_IMAGE])

        def ssh(command, timeout):
            calls.append(command)
            return SimpleNamespace(stdout=next(outputs), returncode=0)

        with patch.object(sys, "argv", ["driver", "hang", "--workdir", str(self.d.workdir)]),              patch.object(driver.Driver, "ssh", side_effect=ssh),              patch.object(driver.Driver, "operator", return_value=(0, {"status": "OK"})) as op:
            self.assertFalse(driver.main())
        op.assert_called_once()
        self.assertIn("docker inspect", calls[0])
        self.assertEqual(calls[1], "ha apps stop local_p7u_r4_native_host")
        self.assertEqual(len(calls), 4)
        state = driver.Driver(str(self.d.workdir)).state
        self.assertEqual(state["hang_runs"][-1]["restart"], {"host": "RUNNING", "attempts": 2})

    def _hang_with(self, responses):
        self.d.save(operation_id="f" * 32, plan_pin="1" * 64)
        calls = []
        replies = iter(responses)

        def ssh(command, timeout):
            calls.append(command)
            stdout, code = next(replies)
            return SimpleNamespace(stdout=stdout, returncode=code)

        with patch.object(sys, "argv", ["driver", "hang", "--workdir", str(self.d.workdir)]),              patch.object(driver.Driver, "ssh", side_effect=ssh),              patch.object(driver.Driver, "operator", return_value=(0, {"status": "OK"})) as op:
            with self.assertRaises(SystemExit) as stop:
                driver.main()
        return calls, op, str(stop.exception)

    def test_hang_refuses_when_paired_host_is_not_installed(self):
        # Bound to the custom host, but production runs the official app.
        calls, op, message = self._hang_with([("", 1)])
        self.assertIn("HANG_BOUND_OWNER_NOT_INSTALLED", message)
        self.assertEqual(len(calls), 1)  # no stop, no capture, no restart
        op.assert_not_called()

    def test_hang_refuses_a_different_host_image(self):
        calls, op, message = self._hang_with([("sha256:" + "0" * 64 + "\n", 0)])
        self.assertIn("HANG_BOUND_OWNER_NOT_INSTALLED", message)
        self.assertEqual(len(calls), 1)
        op.assert_not_called()

    def test_hang_refuses_when_stop_fails(self):
        calls, op, message = self._hang_with([(driver.HOST_IMAGE, 0), ("", 1)])
        self.assertIn("HANG_OWNER_STOP_FAILED", message)
        self.assertEqual(len(calls), 2)
        op.assert_not_called()

    def test_hang_with_official_owner_stops_and_restarts_that_app(self):
        slug, image = "45df7312_zigbee2mqtt", "sha256:" + "2" * 64
        self.d.save(owner_slug=slug, owner_image=image)
        calls, op, message = self._hang_with([(image + "\n", 0), ("", 1)])
        self.assertIn("docker inspect -f '{{.Image}}' app_" + slug, calls[0])
        self.assertEqual(calls[1], "ha apps stop " + slug)
        self.assertIn("HANG_OWNER_STOP_FAILED", message)
        op.assert_not_called()
        self.d.save(owner_slug=slug, owner_image=image)
        outputs = iter([image + "\n", "", "running " + image])
        seen = []

        def ssh(command, timeout):
            seen.append(command)
            return SimpleNamespace(stdout=next(outputs), returncode=0)

        with patch.object(sys, "argv", ["driver", "hang", "--workdir", str(self.d.workdir)]), \
             patch.object(driver.Driver, "ssh", side_effect=ssh), \
             patch.object(driver.Driver, "operator", return_value=(0, {"status": "OK"})) as op:
            self.assertFalse(driver.main())
        op.assert_called_once()
        self.assertIn("ha apps start " + slug, seen[2])

    def test_hang_refuses_malformed_owner_pins(self):
        self.d.save(owner_slug="x; reboot", owner_image="sha256:" + "2" * 64)
        calls, op, message = self._hang_with([])
        self.assertIn("HANG_OWNER_PIN_SHAPE", message)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
