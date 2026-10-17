"""Offline only: direct P7U R4 ROM vector source layout, negative controls."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

DIR = Path(__file__).resolve().parents[1] / "firmware/slzb-06p7u/r4/release"
sys.path.insert(0, str(DIR))
spec = importlib.util.spec_from_file_location("r4_direct", DIR/"r4_prepare_direct_rom_boot.py")
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
from tests.test_r4_preserve_resident_boot_nvs import SYSCFG, LINKER


class DirectROMSourceTests(unittest.TestCase):
    def test_independent_rom_vectors_and_relocated_nv(self):
        sc, ld = tool.transform(SYSCFG, LINKER)
        self.assertIn("#define FLASH_BASE              0x00000000", ld)
        self.assertIn("#define FLASH_SIZE              0xA0000", ld)
        self.assertIn("    .resetVecs: load > 0\n", ld)
        self.assertNotIn("    .resetVecs: load > 0x80", ld)
        self.assertIn("FLASH_NV_BASE           0xA0000", ld)
        self.assertIn("FLASH_LAST_BASE         0xAE000", ld)
        self.assertIn("NVS1.internalFlash.regionBase = 0xA0000", sc)

    def test_drift_and_repeat_denied(self):
        for source, linker in (
            (SYSCFG, LINKER.replace("FLASH_SIZE", "FLASH_LEN")),
            (SYSCFG, LINKER.replace("FLASH_LAST_BASE", "FLASH_TOP_BASE")),
            (SYSCFG.replace("0xAA000", "0xA0000"), LINKER),
            (SYSCFG + SYSCFG, LINKER),
        ):
            with self.subTest(source=source[:36], linker=linker[:36]):
                with self.assertRaises(ValueError):
                    tool.transform(source, linker)
        sc, ld = tool.transform(SYSCFG, LINKER)
        with self.assertRaises(ValueError):
            tool.transform(sc, ld)

    def test_receipt_is_not_flash_authorization(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg, linker, report = root/"znp.syscfg", root/"app.cmd", root/"receipt.json"
            cfg.write_text(SYSCFG)
            linker.write_text(LINKER)
            receipt = tool.apply(cfg, linker, report)
            self.assertEqual(receipt["vector_table"], "0x00000000")
            self.assertFalse(receipt["flash_authorized"])
            self.assertFalse(receipt["ccfg_recovery_qualified"])
            self.assertFalse(receipt["flash_performed"])
            self.assertEqual(receipt["ccfg_boot_address_needed"], "0x00000000")
            self.assertTrue(report.exists())
            with self.assertRaises(ValueError):
                tool.apply(cfg, linker, report)

    def test_no_partial_files_modified_on_drift(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg, linker, report = root/"znp.syscfg", root/"app.cmd", root/"receipt.json"
            cfg.write_text(SYSCFG)
            linker.write_text(LINKER.replace("FLASH_NV_SIZE", "FLASH_NV_BYTES"))
            with self.assertRaises(ValueError):
                tool.apply(cfg, linker, report)
            self.assertEqual(cfg.read_text(), SYSCFG)
            self.assertFalse(report.exists())


if __name__ == "__main__":
    unittest.main()
