"""The HA readiness checker never claims permission to flash or changes services."""
import importlib.util
import json
from pathlib import Path
import tempfile
from unittest import TestCase,main,mock

P=Path(__file__).resolve().parents[1]/"tools/p7u_ha_fast_preflight.py"
spec=importlib.util.spec_from_file_location("p7u_ha_fast_preflight",P)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class PreflightTests(TestCase):
    def test_missing_private_runtime_can_only_report_hold(self):
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.object(module,"addon_state",return_value={
                "state":"started","boot":"manual","watchdog":False}):
                a=module.inspect(Path(td))
            self.assertEqual(a["status"],"HOST_CHECKS_COMPLETE_FLASH_BLOCKED")
            self.assertFalse(a["flash_authorized"])
            self.assertFalse(a["port_opened"])
            self.assertFalse(a["z2m_service_mutated"])
            self.assertFalse(a["radio_reset_requested"])
            self.assertIn("approved_immutable_ti_sdk_not_yet_provisioned",a["hold_reasons"])
            self.assertIn("hardware_mutating_operator_not_yet_qualified",a["hold_reasons"])

    def test_ha_info_command_is_allowlisted_read_only(self):
        def command(args,**kwargs):
            self.assertEqual(args,["ha","apps","info",module.Z2M,"--raw-json"])
            return mock.Mock(returncode=0,stdout=json.dumps({"data":{
                "state":"started","boot":"manual","watchdog":False}}))
        with mock.patch.object(module.subprocess,"run",side_effect=command):
            self.assertEqual(module.addon_state()["state"],"started")


if __name__=="__main__":main()
