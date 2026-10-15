#!/usr/bin/env python3
"""Operator boundary tests; no hardware or real management request."""
import asyncio
import binascii
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
import p7u_strict_sector_writer as core


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
        with patch.object(tool, "management_get") as get:
            with self.assertRaises(tool.core.StrictError):
                tool.radio_control(tool.load_target(self.path), "reboot-esp")
            get.assert_not_called()
        for command, code in (("enter-bsl", 2), ("restart-radio", 1)):
            with patch.object(tool, "management_get", side_effect=[json.dumps(self.info).encode(), b"ok"]) as get:
                result = tool.radio_control(tool.load_target(self.path), command)
                self.assertFalse(result["flash_performed"])
                self.assertEqual(get.call_args.args, ("p7u.example", f"/api2?action=4&cmd={code}"))

    def test_existing_output_and_unapproved_writes_stop_before_contact(self):
        with patch.object(tool, "validate_packet", return_value={}), \
             patch.object(tool, "management_get") as get, patch.object(tool.app, "run") as app:
            for command in ("flash", "rollback", "prepare-nv5", "restore-nv5", "restore-app"):
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

    def test_installed_inspection_matches_each_pinned_image_and_is_read_only(self):
        class FakeROM:
            def __init__(self, image):
                self.flash = bytearray(b"\xff" * core.gate.RADIO_SIZE)
                for address, block in image.sectors:
                    self.flash[address:address + len(block)] = block
                self.writes = 0

            async def crc32(self, address, length):
                return binascii.crc32(self.flash[address:address + length]) & 0xffffffff

            async def read_word(self, address):
                return bytes(self.flash[address:address + 4])

            async def erase_sector(self, address):
                self.writes += 1
                raise AssertionError("erase forbidden")

            async def begin_download(self, address, length):
                self.writes += 1
                raise AssertionError("program forbidden")

            async def send_data(self, packet):
                self.writes += 1
                raise AssertionError("program forbidden")

        def bundle(seed):
            sectors = []
            for address in range(0, 23 * core.gate.SECTOR, core.gate.SECTOR):
                block = bytearray(bytes([seed]) * core.gate.SECTOR)
                if address == 0:
                    block[:8] = (0x20010000).to_bytes(4, "little") + (0x00000101).to_bytes(4, "little")
                sectors.append((address, bytes(block)))
            return core.Bundle("p7u-cap192-f07", str(seed) * 64, "b" * 64, tuple(sectors))

        images = {"r2": bundle(0x11), "stock_20240710": bundle(0x22),
                  "stock_20240316": bundle(0x33)}
        identity = {"ccfg_sha256": "c" * 64, "factory_id_digest": "d" * 64}
        for name, expected in images.items():
            rom = FakeROM(expected)
            result = asyncio.run(tool.inspect_installed_rom(rom, identity, images, "/dev/ttyACM0"))
            self.assertEqual(result["application_classification"], name)
            self.assertTrue(result["installed_vectors"]["plausible_cc26x2_vector"])
            self.assertEqual(len(result["nv5_pages"]), 5)
            self.assertFalse(result["flash_write_or_erase_performed"])
            self.assertEqual(rom.writes, 0)

    def test_installed_inspection_marks_corrupt_sector_and_invalid_vectors_unmatched(self):
        class FakeROM:
            def __init__(self, image):
                self.flash = bytearray(b"\xff" * core.gate.RADIO_SIZE)
                for address, block in image.sectors:
                    self.flash[address:address + len(block)] = block

            async def crc32(self, address, length):
                return binascii.crc32(self.flash[address:address + length]) & 0xffffffff

            async def read_word(self, address):
                return bytes(self.flash[address:address + 4])

        sectors = []
        for address in range(0, 23 * core.gate.SECTOR, core.gate.SECTOR):
            block = bytearray(b"\x11" * core.gate.SECTOR)
            if address == 0:
                block[:8] = (0x20010000).to_bytes(4, "little") + (0x00000101).to_bytes(4, "little")
            sectors.append((address, bytes(block)))
        images = {"r2": core.Bundle("p7u-cap192-f07", "a" * 64, "b" * 64, tuple(sectors)),
                  "stock_20240710": core.Bundle("p7u-cap192-f07", "c" * 64, "d" * 64, tuple(
                      (a, bytes([0x22]) * core.gate.SECTOR) for a, _ in sectors)),
                  "stock_20240316": core.Bundle("p7u-cap192-f07", "e" * 64, "f" * 64, tuple(
                      (a, bytes([0x33]) * core.gate.SECTOR) for a, _ in sectors))}
        rom = FakeROM(images["r2"])
        rom.flash[0x2000] ^= 1
        result = asyncio.run(tool.inspect_installed_rom(rom, {}, images, "/dev/ttyACM0"))
        self.assertEqual(result["application_classification"], "unmatched")
        self.assertNotEqual(result["installed_sector_crc32"]["0x02000"],
                            result["images"]["r2"]["sector_crc32"][0x2000])
        rom.flash[0:8] = b"\x00" * 8
        result = asyncio.run(tool.inspect_installed_rom(rom, {}, images, "/dev/ttyACM0"))
        self.assertFalse(result["installed_vectors"]["plausible_cc26x2_vector"])

    def test_installed_inspection_refuses_management_socket_without_reset(self):
        args = self.args("inspect-installed", "--unused-p7u", "--already-in-rom-bsl")
        target = {"device": "socket://p7u.example:6638"}
        with self.assertRaisesRegex(core.StrictError, "INSPECT_INSTALLED_USB_ONLY_NO_MANAGEMENT_RESET"):
            asyncio.run(tool.inspect_installed(target, args))

    def test_vector_limits_follow_linked_p7_sram_and_application_envelope(self):
        for msp, reset, valid in ((0x20024000, 0x101, True),
                                  (0x20024008, 0x101, False),
                                  (0x20000000, 0x101, False),
                                  (0x20010004, 0x101, False),
                                  (0x20010000, 0x2E001, False),
                                  (0x20010000, 0x100, False)):
            raw = msp.to_bytes(4, "little") + reset.to_bytes(4, "little")
            self.assertEqual(tool._vector_record(raw)["plausible_cc26x2_vector"], valid)

    def test_20240316_filename_cannot_substitute_another_stock_source(self):
        target = tool.load_target(self.path)
        target["packet"].mkdir()
        (target["packet"] / "official-stock-20240316.bin").write_bytes(b"not the pinned original")
        with patch.object(tool.app, "load_request", return_value=(object(), object())):
            with self.assertRaisesRegex(core.StrictError, "INSPECT_PINNED_20240316_HASH_MISMATCH"):
                tool.expected_application_images(target, self.args("inspect-installed"))


    def test_inspection_fails_closed_if_actual_radio_identity_is_wrong(self):
        args = self.args("inspect-installed", "--unused-p7u", "--already-in-rom-bsl")
        target = tool.load_target(self.path)
        target["radio_factory_id_digest"] = "a" * 64
        target["radio_ccfg_sha256"] = "b" * 64
        class FakeSession:
            async def __aenter__(self):
                return object()
            async def __aexit__(self, *ignored):
                return False
        with patch.object(tool, "identify", return_value={"status": "P7U_MANAGEMENT_IDENTITY_MATCHED"}), \
             patch.object(tool, "expected_application_images", return_value={}), \
             patch.object(tool, "LiveSmlightSession", return_value=FakeSession()), \
             patch.object(core, "observe", side_effect=core.StrictError("NOT_CC26X2X7_SILICON")), \
             patch.object(tool, "inspect_installed_rom", new_callable=AsyncMock) as inspect:
            with self.assertRaisesRegex(core.StrictError, "NOT_CC26X2X7_SILICON"):
                asyncio.run(tool.inspect_installed(target, args))
            inspect.assert_not_awaited()


    def test_installed_inspection_binds_usb_identity_to_original_rom_capture(self):
        args = self.args("inspect-installed", "--unused-p7u", "--already-in-rom-bsl")
        target = tool.load_target(self.path)
        actual = {"factory_id_digest": "a" * 64, "ccfg_sha256": "b" * 64}
        blank_crc = format(binascii.crc32(bytes([255]) * core.gate.SECTOR) & 0xffffffff, "08x")
        evidence = {"application_classification": "r2", "exact_image_matches": ["r2"],
                    "installed_vectors": {"plausible_cc26x2_vector": True},
                    "nv5_pages": [{"header_all_ff": True, "sector_crc32": blank_crc}]}
        class FakeSession:
            async def __aenter__(self):
                return object()
            async def __aexit__(self, *ignored):
                return False
        with patch.object(tool, "identify", return_value={"status": "P7U_MANAGEMENT_IDENTITY_MATCHED"}), \
             patch.object(tool, "expected_application_images", return_value={}), \
             patch.object(tool, "LiveSmlightSession", return_value=FakeSession()), \
             patch.object(core, "observe", return_value=actual), \
             patch.object(tool, "inspect_installed_rom", new_callable=AsyncMock) as inspect:
            inspect.return_value = evidence
            with self.assertRaisesRegex(core.StrictError, "INSPECT_ORIGINAL_RADIO_IDENTITY_PIN_REQUIRED"):
                asyncio.run(tool.inspect_installed(target, args))
            inspect.assert_not_awaited()
            target["radio_factory_id_digest"] = "c" * 64
            target["radio_ccfg_sha256"] = "b" * 64
            with self.assertRaisesRegex(core.StrictError, "INSPECT_WRONG_RADIO_OR_CCFG_CHANGED"):
                asyncio.run(tool.inspect_installed(target, args))
            inspect.assert_not_awaited()
            target["radio_factory_id_digest"] = actual["factory_id_digest"]
            result = asyncio.run(tool.inspect_installed(target, args))
            self.assertEqual(result["application_classification"], "r2")
            self.assertFalse(result["flash_write_or_erase_performed"])
            self.assertTrue(args.out.exists())
            self.assertEqual(inspect.await_count, 1)

if __name__ == "__main__":
    unittest.main()
