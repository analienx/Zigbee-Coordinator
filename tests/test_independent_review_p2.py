"""Six-P2 independent review regression controls (all offline)."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy"))
sys.path.insert(0, str(ROOT / "firmware/slzb-06p7u/r4/tools"))
sys.path.insert(0, str(ROOT / "firmware/slzb-06p7u/r4/b0/tools"))

import p10_config_stage as config
import p10_migration_workflow as migration
from p10_quarantine_identity import check as quarantine, refusal_reasons
from r4_passive_recorder import PassiveR4Recorder
import b0_provision as provision


class ProvisionP2(unittest.TestCase):
    def test_wrong_tool_versions_cannot_be_certified_by_substrings(self):
        clang = "/tmp/ti/tiarmclang"
        cases = [
            ("ti_arm_clang", "TI Arm Clang Compiler 13.2.2.LTS\n", False),
            ("ti_arm_clang", "TI Arm Clang Compiler 4.0.0.LTS\nInstalledDir: /ti/3.2.2.LTS/bin\n", False),
            ("ti_arm_clang", "TI Arm Clang Compiler 3.2.2.LTS\nTarget: arm-ti-none-eabi\n", True),
            ("sysconfig", "1.21.1+37720\n", False),
            ("sysconfig", "1.21.1+3772\n", True),
            ("sysconfig", "1.21.1.3772\n", True),
            ("sysconfig", "1.21.1+3772\n1.21.1+37720\n", False),
        ]
        for key, output, expected in cases:
            with self.subTest(key=key, output=output):
                self.assertIs(provision._matches_version(key, clang, output), expected)
        with patch.dict("os.environ", {"B0_CCS_PACKAGE_PATH": "",
                                       "CCS_ECLIPSE": clang}):
            self.assertFalse(provision._matches_version(
                "ccs", clang, "CCS 12.8.0.00012 -ccs.projects"))


class QuarantineP2(unittest.TestCase):
    def test_direct_running_revision_and_socket_mapping_must_match(self):
        good = quarantine(20260310, 20260310, 20260310,
                          "CC2674P10", "CC2674P10", 7638, 7638)
        self.assertEqual(refusal_reasons(good), [])
        for overrides in (
            (20200101, 20260310, "CC2674P10", 7638),
            (20260310, 20200101, "CC2674P10", 7638),
            (20260310, 20260310, "CC2652P7", 7638),
            (20260310, 20260310, "CC2674P10", 7639),
            (20260310, 20260310, "CC2674P10", None),
        ):
            actual, management, hw, port = overrides
            gates = quarantine(20260310, actual, management, hw, "CC2674P10", port, 7638)
            self.assertTrue(refusal_reasons(gates))


class RecorderP2(unittest.TestCase):
    def test_drop_only_updates_are_persisted_without_waiter_identifiers(self):
        rec = PassiveR4Recorder(process_generation=1)
        self.assertTrue(rec.offer({"kind": "AF_SREQ_TIMEOUT", "at_ms":100,
                                   "waiter_id":7}))
        self.assertEqual(rec.drain(), 1)
        for n in range(14):
            rec.offer({"kind": "AF_SREQ_TIMEOUT", "at_ms":101 + n,
                       "waiter_id":7})
            rec.drain()
        self.assertEqual(rec.dropped, 14)
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "recorder.json"
            rec.persist(f)
            disk = PassiveR4Recorder.read_last_good(f)
            self.assertEqual(disk["dropped"], 14)
            self.assertNotIn("waiter_id", f.read_text())
            rec.offer({"kind": "ZCL_TIMEOUT", "at_ms":5})
            rec.drain()  # out of order, no accepted event
            rec.persist(f)
            self.assertEqual(PassiveR4Recorder.read_last_good(f)["dropped"], 15)


class StagedTcpP2(unittest.TestCase):
    def test_missing_optional_serial_settings_are_added_and_preserve_rollback(self):
        raw = (b"serial:\n  port: /dev/ttyUSB0\n  adapter: ember\n"
               b"advanced:\n  channel: 11\n")
        staged = config.render(raw, "192.168.50.200", 7638)
        self.assertEqual(staged.count(b"  baudrate: 115200"), 1)
        self.assertEqual(staged.count(b"  rtscts: false"), 1)
        self.assertIn(b"advanced:\n  channel: 11", staged)
        self.assertEqual(raw, bytes(raw))
        for value in (b"  baudrate: 460800\n  rtscts: true\n", b""):
            candidate = raw.replace(b"advanced:", value + b"advanced:")
            target = config.render(candidate, "192.168.50.200", 7638)
            parsed = config.yaml.safe_load(target)
            self.assertEqual(parsed["serial"]["baudrate"], 115200)
            self.assertIs(parsed["serial"]["rtscts"], False)

    def test_addon_stage_also_overrides_serial_and_keeps_other_options(self):
        options = {"serial": {"port": "/dev/ttyUSB0", "adapter": "ember",
                              "baudrate": 460800, "rtscts": True},
                   "mqtt": {"server": "mqtt://not-touched"}}
        rendered = migration.render_addon_options(options, "192.168.50.200", 7638)
        self.assertEqual(rendered["serial"]["baudrate"], 115200)
        self.assertIs(rendered["serial"]["rtscts"], False)
        self.assertEqual(rendered["mqtt"], options["mqtt"])
        self.assertEqual(options["serial"]["baudrate"], 460800)
        optional = {"serial": {"port": "/dev/ttyUSB0", "adapter": "ember"}}
        target = migration.render_addon_options(optional, "192.168.50.200", 7638)
        self.assertEqual(target["serial"]["baudrate"], 115200)
        self.assertIs(target["serial"]["rtscts"], False)

    def test_yaml_crlf_stays_crlf(self):
        raw = b"serial:\r\n  port: /dev/a\r\n  adapter: ember\r\n"
        converted = config.render(raw, "192.168.50.200", 7638)
        self.assertNotIn(b"\n", converted.replace(b"\r\n", b""))
        self.assertIn(b"  rtscts: false\r\n", converted)


if __name__ == "__main__":
    unittest.main()
