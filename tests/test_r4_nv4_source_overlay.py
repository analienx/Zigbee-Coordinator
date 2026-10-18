"""Exact source-geometry corrections for a P7U stock NV4, no physical writes."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


PATH = (Path(__file__).resolve().parents[1] /
        "firmware/slzb-06p7u/r4/qualification/nv4_source_overlay.py")
spec = importlib.util.spec_from_file_location("r4_nv4_source_overlay", PATH)
overlay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(overlay)


def fixture() -> tuple[str, str, str]:
    sc = ('NVS1.$name                    = "CONFIG_NVSINTERNAL";\n' +
          overlay.P7_SYSCFG_OLD + '\n')
    ld = ('#define FLASH_BASE              0x00000000\n' +
          '\n'.join(before for before, _ in overlay.LINKER_EDITS) + '\n' +
          '#define FLASH_LAST_BASE         0xAE000\n' +
          '#define FLASH_LAST_SIZE         0x2000\n')
    project = ('device="Cortex M.CC1352P7"\n' +
               '\n'.join(before for before, _ in overlay.PROJECT_EDITS) + '\n')
    return sc, ld, project


class Nv4OverlayTests(unittest.TestCase):
    def test_geometry_is_stock_exact_and_not_donor_nv2(self):
        sc, ld, project = overlay.transform(*fixture())
        self.assertIn('NVS1.internalFlash.regionBase = 0xA6000;', sc)
        self.assertIn('NVS1.internalFlash.regionSize = 0x8000;', sc)
        for original, updated in overlay.LINKER_EDITS:
            self.assertNotIn(original, ld)
            self.assertEqual(ld.count(updated), 1)
        for original, updated in overlay.PROJECT_EDITS:
            self.assertNotIn(original, project)
            self.assertEqual(project.count(updated), 1)
        self.assertIn('FLASH_LAST_BASE         0xAE000', ld)
        self.assertIn('FLASH_LAST_SIZE         0x2000', ld)
        self.assertEqual(overlay.STOCK_BASE + overlay.STOCK_SIZE,
                         overlay.STOCK_END)
        self.assertEqual(overlay.STOCK_SIZE // overlay.SECTOR,
                         overlay.STOCK_PAGES)

    def test_reapplication_drift_and_partial_config_refused(self):
        sc, ld, project = fixture()
        changed = overlay.transform(sc, ld, project)
        with self.assertRaisesRegex(ValueError, "SYSCFG_ANCHOR_DRIFT"):
            overlay.transform(*changed)
        with self.assertRaisesRegex(ValueError, "PROJECT_1_ANCHOR_DRIFT"):
            overlay.transform(sc, ld, project.replace('--define=NVOCMP_NVPAGES=2',
                                                      '--define=NVOCMP_NVPAGES=4'))
        with self.assertRaisesRegex(ValueError, "LINKER_2_ANCHOR_DRIFT"):
            overlay.transform(sc, ld.replace('0x4000', '0x8000'), project)
        with self.assertRaisesRegex(ValueError, "PINNED_BOARD_OR_CCFG_MISMATCH"):
            overlay.transform(sc, ld.replace('0xAE000', '0xAC000'), project)

    def test_source_pin_required_before_any_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / name for name in
                     ('znp.syscfg', 'p7.cmd', 'znp.projectspec')]
            for path, content in zip(paths, fixture()):
                path.write_text(content)
            before = [p.read_bytes() for p in paths]
            receipt = Path(directory) / 'receipt.json'
            with self.assertRaisesRegex(ValueError, "UPSTREAM_BLOB_PIN_MISMATCH"):
                overlay.apply(*paths, receipt)
            self.assertEqual(before, [p.read_bytes() for p in paths])
            self.assertFalse(receipt.exists())


if __name__ == '__main__':
    unittest.main()
