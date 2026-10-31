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
        fill = {"EXTRACT": tuple("abcde"), "VERIFY_STAGE": tuple("abcd"),
                "SERVING": (driver.HOST_IMAGE,),
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


if __name__ == "__main__":
    unittest.main()
