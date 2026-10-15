#!/usr/bin/env python3
"""Operator boundary tests; no hardware or real management request."""
import asyncio
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch, AsyncMock

BASE = Path(__file__).resolve().parents[2] / "firmware/slzb-06p7u/qualification"
sys.path.insert(0, str(BASE))
import p7u_tool as tool


class OperatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.target = dict(schema="p7u-operator-target-v1", model="SLZB-06P7U",
                           management_host="p7u.example", management_mac="AA:BB:CC:DD:EE:FF",
                           board_revision="1.73", host_version="v3.2.6.dev3",
                           device="/dev/ttyACM0", packet="packet", candidate_sha256="a" * 64)
        self.path = self.root / "target.json"
        self.path.write_text(json.dumps(self.target))
        self.info = {"Info": dict(model="SLZB-06p7U", MAC="AA:BB:CC:DD:EE:FF",
                                  hw_version=173, sw_version="v3.2.6.dev3",
                                  zb_hw="CC2652P7", coord_mode=2, zb_version=20240316)}

    def args(self, command="check", *extra):
        return tool.parser().parse_args([command, "--target", str(self.path),
                                        "--out", str(self.root / "result"), *extra])

    def run_tool(self, args):
        return asyncio.run(tool.run(args))

    def test_default_offline_and_bad_packet_stops_before_contact(self):
        with patch.object(tool, "validate_packet", return_value={}), \
             patch.object(tool, "management_get", side_effect=AssertionError("network")), \
             patch.object(tool.app, "run", side_effect=AssertionError("radio")), \
             patch.object(tool.nv, "run", side_effect=AssertionError("radio")):
            self.assertFalse(self.run_tool(self.args())["hardware_contacted"])
        with patch.object(tool, "validate_packet", side_effect=ValueError("bad kit")), \
             patch.object(tool, "management_get") as contact:
            with self.assertRaises(ValueError): self.run_tool(self.args("enter-bsl", "--unused-p7u"))
            contact.assert_not_called()

    def test_wifi_management_and_usb_data_are_distinct(self):
        target = tool.load_target(self.path)
        self.assertEqual(target["packet"], self.root / "packet")
        with patch.object(tool, "management_get", return_value=json.dumps(self.info).encode()) as get:
            self.assertEqual(tool.identify(target)["coordinator_mode"], 2)
            get.assert_called_once_with("p7u.example", "/ha_info")
        self.assertEqual(tool.app_request(target, self.args("flash")).device, "/dev/ttyACM0")

    def test_wrong_model_mac_board_os_or_radio_never_sends_control(self):
        target = tool.load_target(self.path)
        for field, value in (("MAC", "00:11:22:33:44:55"), ("model", "SLZB-MR4U"),
                             ("hw_version", 172), ("sw_version", "v0"), ("zb_hw", "CC2674P10")):
            info = copy.deepcopy(self.info)
            info["Info"][field] = value
            with patch.object(tool, "management_get", return_value=json.dumps(info).encode()) as get:
                with self.assertRaises(Exception): tool.radio_control(target, "enter-bsl")
                self.assertEqual(get.call_count, 1)
                self.assertEqual(get.call_args.args[1], "/ha_info")

    def test_control_only_uses_ti_radio_commands_after_identity(self):
        for command, code in (("enter-bsl", 2), ("restart-radio", 1)):
            with patch.object(tool, "management_get", side_effect=[json.dumps(self.info).encode(), b"ok"]) as get:
                result = tool.radio_control(tool.load_target(self.path), command)
                self.assertFalse(result["flash_performed"])
                self.assertEqual(get.call_args.args, ("p7u.example", f"/api2?action=4&cmd={code}"))

    def test_existing_output_and_unapproved_writes_stop_before_contact(self):
        with patch.object(tool, "validate_packet", return_value={}), \
             patch.object(tool, "management_get") as get, patch.object(tool.app, "run") as app:
            for command in ("flash", "rollback", "prepare-nv5", "restore-nv5"):
                with self.assertRaises(tool.core.StrictError): self.run_tool(self.args(command, "--write"))
            self.args().out.write_bytes(b"preserve backup")
            with self.assertRaises(tool.core.StrictError):
                self.run_tool(self.args("enter-bsl", "--unused-p7u"))
            self.assertEqual(self.args().out.read_bytes(), b"preserve backup")
            get.assert_not_called()
            app.assert_not_called()

    def test_app_and_nv_keep_core_guards_and_do_not_infer_recovery(self):
        target = tool.load_target(self.path)
        for command, image in (("flash", "candidate"), ("rollback", "stock")):
            args = self.args(command, "--unused-p7u", "--already-in-rom-bsl")
            request = tool.app_request(target, args)
            self.assertEqual((request.phase, request.target_image), ("inspect", image))
            self.assertFalse(request.execute_radio_write)
            self.assertFalse(request.rom_bsl_reentry_twice_confirmed)
            runner = AsyncMock(return_value={"status": "simulated_inspection"})
            with patch.object(tool, "validate_packet", return_value={}), patch.object(tool.app, "run", runner):
                self.run_tool(args)
                self.assertEqual(runner.call_args.args[0].phase, "inspect")
            args.out.unlink()
        for command, action in (("prepare-nv5", "prepare-nv5"), ("restore-nv5", "restore-original-nv5")):
            request = tool.nv_request(target, self.args(command))
            self.assertEqual((request.command, request.action), ("inspect", action))
            self.assertFalse(request.execute_nv_write)
            self.assertFalse(request.independent_copy_confirmed)
            self.assertIsNone(request.original_network_declaration)
        args = self.args("flash", "--write", "--recovery-proven", "--plan", "plan.json", "--approve", "123")
        request = tool.app_request(target, args)
        self.assertTrue(request.execute_radio_write)
        self.assertEqual(request.approve_digest, "123")


if __name__ == "__main__":
    unittest.main()
