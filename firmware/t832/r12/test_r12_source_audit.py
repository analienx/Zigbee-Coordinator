"""Negative tests for the pinned, fail-closed R12 AUX source gate."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import r12_source_audit as audit


class SourceGateTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.sdk = base / "sdk"
        self.examples = base / "examples"
        self.sdk.mkdir()
        self.examples.mkdir()
        self.paths = {
            "opts": self.sdk / "source/ti/zstack/apps/znp/znp_cnf.opts",
            "mem": self.sdk / "source/ti/devices/cc13x4_cc26x4/inc/hw_memmap.h",
            "power": self.sdk / "source/ti/drivers/power/PowerCC26X2.c",
            "syscfg": self.examples / audit.ZNP_SUBPATH / "znp.syscfg",
        }
        self.data = {
            "opts": "-DMAC_CFG",
            "mem": ("#define AUX_RAM_BASE 0x400E0000\n"
                    "#define AUX_RAM_NONBUF_BASE 0x600E0000\n"),
            "power": ("AUXWUCPowerCtrl(AUX_POWER_OFF);\n"
                      "int_fast16_t Power_sleep(uint_fast16_t state) {}\n"),
            "syscfg": 'var Power=scripting.addModule("/ti/drivers/Power");\n',
        }
        for key, path in self.paths.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(self.data[key], encoding="utf-8")

    def audited(self):
        with patch.object(audit, "commit_pin") as verify:
            result = audit.audit(self.sdk, self.examples)
            self.assertEqual(verify.call_count, 2)
        return result

    def test_empty_znp_references_never_mean_ownership_proven(self):
        result = self.audited()
        self.assertEqual(result["znp_direct_aux"]["matching_lines"], 0)
        self.assertTrue(result["power_driver_uses_aux_subsystem"])
        self.assertEqual(result["status"], "AUX_OWNERSHIP_AND_RESET_UNPROVEN")
        self.assertFalse(result["unused_bounded_80_byte_aux_window_proven"])
        self.assertFalse(result["actual_slzb_radio_reset_retention_proven"])

    def test_direct_aux_usage_is_detected_not_whitelisted(self):
        p = self.sdk / "source/ti/zstack/startup/main.c"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("HWREG(AUX_RAM_BASE)=1;\n", encoding="utf-8")
        result = self.audited()
        self.assertEqual(result["znp_direct_aux"]["matching_lines"], 1)
        self.assertEqual(result["status"], "AUX_OWNERSHIP_AND_RESET_UNPROVEN")

    def test_invalid_aux_address_fails(self):
        self.paths["mem"].write_text("#define AUX_RAM_BASE 0x400F0000\n")
        with patch.object(audit, "commit_pin"):
            with self.assertRaisesRegex(audit.AuditError, "address drift"):
                audit.audit(self.sdk, self.examples)

    def test_missing_sysconfig_power_module_fails(self):
        self.paths["syscfg"].write_text("/* empty */\n")
        with patch.object(audit, "commit_pin"):
            with self.assertRaisesRegex(audit.AuditError, "Power module"):
                audit.audit(self.sdk, self.examples)

    def test_invalid_sdk_commit_fails(self):
        # Not a git checkout: the actual pin checker must fail immediately.
        with self.assertRaises(Exception):
            audit.audit(self.sdk, self.examples)


if __name__ == "__main__":
    unittest.main()
