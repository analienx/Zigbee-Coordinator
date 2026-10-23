"""Offline unit tests for the HA native-control binder (no device access)."""
import importlib.util
from pathlib import Path
from unittest.mock import Mock, patch
import unittest

source = Path(__file__).resolve().parents[1] / "host" / "recovery" / "bind_native_controls.py"
spec = importlib.util.spec_from_file_location("native_binder", source)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class NativeBinderTests(unittest.TestCase):
    def test_exact_entities_and_no_hardware_reset_route(self):
        self.assertEqual(mod.CORE, "button.slzb_06p7u_core_restart")
        self.assertEqual(mod.RADIO, "button.slzb_06p7u_zigbee_restart")
        self.assertIn('new["esp_restart_entity"]=core', mod.REMOTE)
        self.assertIn('new["zigbee_restart_entity"]=radio', mod.REMOTE)
        self.assertIn('old.get("enabled") is not False', mod.REMOTE)
        self.assertIn('old.get("dry_run") is not True', mod.REMOTE)
        self.assertIn('"core/api/states/"', mod.REMOTE)
        self.assertIn('"/addons/"+slug+"/options"', mod.REMOTE)
        self.assertNotIn('"/core/api/services/button/press"', mod.REMOTE)
        self.assertNotIn('"/api2?action=4"', mod.REMOTE)
        self.assertNotIn('CMD_HARD_RESET', mod.REMOTE)

    def test_remote_runner_is_ssh_argv_without_shell(self):
        process = Mock(returncode=0,stdout="NATIVE_BIND_PLAN",stderr="")
        with patch.object(mod.subprocess, "run", return_value=process) as called:
            mod.run("plan","")
        self.assertEqual(called.call_args.args[0][-3:],
                         ["-", "plan", ""])
        self.assertEqual(called.call_args.kwargs["input"],mod.REMOTE)
        self.assertNotIn("shell",called.call_args.kwargs)

    def test_apply_requires_exact_hash(self):
        import sys
        with patch.object(sys,"argv",["bind_native_controls.py","apply","--expected-plan-hash","bad"]):
            with patch.object(mod,"run") as run:
                with self.assertRaises(SystemExit):
                    mod.main()
                run.assert_not_called()

    def test_plan_has_no_backend_calls_if_no_approval(self):
        import sys
        with patch.object(sys,"argv",["bind_native_controls.py","plan"]):
            with patch.object(mod,"run") as run:
                mod.main()
                run.assert_called_once_with("plan","")

    def test_registry_supports_actual_ha_2026_schema(self):
        self.assertIn('d[0].get("config_entry_id")!=entry',mod.REMOTE)
        self.assertIn('entry not in d[0].get("config_entries",[])',mod.REMOTE)
        self.assertIn('e[0].get("config_entry_id")!=entry',mod.REMOTE)
        self.assertIn('e.get("source")=="user"',mod.REMOTE)

if __name__=="__main__":
    unittest.main()
