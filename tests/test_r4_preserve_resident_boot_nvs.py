"""Offline fail-closed checks for preserving original P7U 0xAC000 boot code."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

MODULE = (Path(__file__).resolve().parents[1] /
          "firmware/slzb-06p7u/r4/release/r4_preserve_resident_boot_nvs.py")
spec = importlib.util.spec_from_file_location("preserve_boot", MODULE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

SYSCFG = (
    'if (deviceName.includes("R7") || deviceName.includes("P7"))\n'
    '{\n'
    '    NVS1.internalFlash.regionBase = 0xAA000;\n'
    '    NVS1.internalFlash.regionSize = 0x4000;\n'
    '}\n'
)
LINKER = (
    "#define FLASH_BASE              0x00000000\n"
    "#define FLASH_SIZE              0xAA000\n"
    "#define FLASH_NV_BASE           0xAA000\n"
    "#define FLASH_NV_SIZE           0x4000\n"
    "#define FLASH_LAST_BASE         0xAE000\n"
    "#define FLASH_LAST_SIZE         0x2000\n"
)

class ResidentBootTests(unittest.TestCase):
    def test_explicit_two_page_relocation(self):
        sc, ld = m.transform(SYSCFG, LINKER)
        self.assertIn("regionBase = 0xA0000;", sc)
        self.assertIn("FLASH_SIZE              0xA0000", ld)
        self.assertIn("FLASH_NV_BASE           0xA0000", ld)
        self.assertIn("FLASH_LAST_BASE         0xAE000", ld)
        self.assertNotIn("regionBase = 0xAA000;", sc)
        self.assertNotIn("FLASH_NV_BASE           0xAA000", ld)
        self.assertEqual((m.NVS_BEGIN, m.NVS_END, m.RESERVED_FROM),
                         (0xA0000, 0xA4000, 0xA4000))
        self.assertEqual(m.transform(SYSCFG.replace("\n", "\r\n"), LINKER), (sc, ld))
    def test_no_duplicate_or_unqualified_source(self):
        for sc, ld in (
            (SYSCFG + SYSCFG, LINKER),
            (SYSCFG.replace('deviceName.includes("P7")', 'deviceName.includes("P10")'), LINKER),
            (SYSCFG.replace("0xAA000", "0xA0000"), LINKER),
            (SYSCFG, LINKER.replace("0xAA000", "0xA0000")),
            (SYSCFG, LINKER.replace("0xAE000", "0xAC000")),
        ):
            with self.subTest(sc=sc[:48], ld=ld[:48]):
                with self.assertRaises(ValueError):
                    m.transform(sc, ld)
    def test_double_application_rejected(self):
        sc, ld = m.transform(SYSCFG, LINKER)
        with self.assertRaises(ValueError):
            m.transform(sc, ld)
    def test_private_board_data_never_required_and_no_flash(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            s, l, r = root / "znp.syscfg", root / "app.cmd", root / "receipt.json"
            s.write_text(SYSCFG); l.write_text(LINKER)
            report = m.apply(s,l,r)
            self.assertFalse(report["flash_authorized"])
            self.assertFalse(report["resident_stage_handoff_proven"])
            self.assertFalse(report["installed_ccfg_to_be_written"])
            self.assertEqual(report["relocated_nvs_range"],["0xA0000","0xA4000"])
            self.assertEqual(report["reserved_existing_region"],["0xA4000","0xB0000"])
            self.assertIn("regionBase = 0xA0000", s.read_text())
            self.assertTrue(r.is_file())
    def test_transactional_drift_rejects_before_changes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            s,l,r = root / "znp.syscfg", root / "app.cmd", root / "receipt.json"
            s.write_text(SYSCFG); l.write_text(LINKER.replace("FLASH_LAST_BASE", "FLASH_LAST_ROOT"))
            with self.assertRaises(ValueError):
                m.apply(s,l,r)
            self.assertEqual(s.read_text(),SYSCFG)
            self.assertFalse(r.exists())

if __name__ == "__main__":
    unittest.main()
