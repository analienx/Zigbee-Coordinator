"""Guard-only deploy safety test (no HA or files mutated)."""
from pathlib import Path
import importlib.util
import json
from unittest.mock import patch
import unittest

path=Path(__file__).resolve().parents[1]/"host"/"recovery"/"deploy_native_guard_024.py"
spec=importlib.util.spec_from_file_location("native_guard_deploy",path)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class DeploySafetyTests(unittest.TestCase):
    def test_only_local_guard_is_updatable(self):
        self.assertEqual(m.GUARD,"local_p7u_recovery")
        self.assertEqual(m.ORIGINAL,"45df7312_zigbee2mqtt")
        self.assertEqual(m.VERSION,"0.2.4")
        self.assertEqual(m.EXPECTED_CORE,"button.slzb_06p7u_core_restart")
        self.assertEqual(m.EXPECTED_RADIO,"button.slzb_06p7u_zigbee_restart")
        text=path.read_text()
        self.assertIn('app("stop","local_p7u_recovery")',text)
        self.assertIn('app("update","local_p7u_recovery")',text)
        self.assertIn('app("start","local_p7u_recovery")',text)
        self.assertNotIn('app("start","45df7312_zigbee2mqtt")',text)
        self.assertNotIn('app("stop","45df7312_zigbee2mqtt")',text)
        self.assertNotIn('"/api2?action=4"',text)
        self.assertNotIn('"/core/api/services/button/press"',text)

    def test_no_source_beyond_versioned_fixed_allowlist(self):
        self.assertEqual(len(m.MODULES),9)
        self.assertEqual(len(m.EXTRA),3)
        self.assertIn("ha_adapter.py",m.MODULES)
        self.assertTrue(all("/" not in f for f in m.MODULES+m.EXTRA))
        self.assertTrue(all(".." not in f for f in m.MODULES+m.EXTRA))

    def test_commit_check_is_fail_closed(self):
        response={"check_runs":[{"name":"unittest","status":"completed","conclusion":"success"}]}
        with patch.object(m,"run",return_value=json.dumps(response)):
            with self.assertRaisesRegex(RuntimeError,"GITHUB_CHECKS_NOT_GREEN"):
                m.git_checks_ok("0"*40)

    def test_plan_sanitizes_report(self):
        options={"enabled":False,"dry_run":True,
                 "esp_restart_entity":m.EXPECTED_CORE,
                 "zigbee_restart_entity":m.EXPECTED_RADIO,
                 "expected_mac":"secret_should_not_print"}
        def fake_gh(path,sha):
            if path.endswith("config.yaml"):return b'version: "0.2.4"'
            if path.endswith("Dockerfile"):return b'BUILD_VERSION=0.2.4'
            return b"verified"
        state={"guard_options":options,"z2m_state":"error",
               "z2m_version":"2.14.0-1","version":"0.2.3"}
        with patch.object(m,"git_checks_ok"),patch.object(m,"preflight",return_value=state),patch.object(m,"gh",side_effect=fake_gh):
            p,h=m.plan("0"*40)
        self.assertEqual(len(h),64)
        self.assertNotIn("secret_should_not_print",json.dumps(p))
        self.assertEqual(p["z2m_state"],"error")

if __name__=="__main__":
    unittest.main()
