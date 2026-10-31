"""Fail-closed one-profile B0-B4 P7U NV4 source composition (synthetic only)."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "firmware/slzb-06p7u/r4/qualification"))
import full_nv4_profile as full
import nv4_source_overlay as nv4


def pinned_fixture():
    sc = ('NVS1.$name                    = "CONFIG_NVSINTERNAL";\n'
          + nv4.P7_SYSCFG_OLD + '\n')
    ld = ('--stack_size=1024\n'
          + '#define FLASH_BASE              0x00000000\n'
          + '\n'.join(before for before, _ in nv4.LINKER_EDITS) + '\n'
          + '#define FLASH_LAST_BASE         0xAE000\n'
          + '#define FLASH_LAST_SIZE         0x2000\n')
    project = ('device="Cortex M.CC1352P7"\n'
               + '\n'.join(before for before, _ in nv4.PROJECT_EDITS) + '\n')
    return sc, ld, project


def board_source():
    sc, _, _ = full.transform_pinned(*pinned_fixture())
    return (sc +
            'for(var setting in ccfgSettings)\n'
            '{\n'
            '    device[setting] = ccfgSettings[setting];\n'
            '}\n'
            'Display_UART.uart.$name = "CONFIG_DISPLAY_UART";\n')


class FullNv4ProfileTests(unittest.TestCase):
    def test_selected_profile_exact_capacity_layout_and_off_policy(self):
        profile = full.validate_profile(full.DEFAULT_PROFILE)
        self.assertEqual(profile['capacities'], full.CAPACITIES)
        self.assertEqual(profile['flash']['conservative_app_ceiling_exclusive'], '0xA0000')
        self.assertEqual(profile['flash']['stock_nv4_start'], '0xA6000')
        self.assertEqual(profile['flash']['stock_nv4_end_exclusive'], '0xAE000')
        self.assertEqual(profile['flash']['nvocmp_pages'], 4)
        self.assertEqual(profile['flash']['stock_20240716_ccfg_sha256'], full.CCFG_SHA)
        self.assertFalse(profile['policies']['full_b0_b4_sealed'])
        self.assertFalse(profile['policies']['auto_flash'])
        self.assertFalse(profile['policies']['b5_mto'])

    def test_one_full_nv4_geometry_with_conservative_app_cap(self):
        sc, ld, project = full.transform_pinned(*pinned_fixture())
        self.assertEqual(sc.count('regionBase = 0xA6000;'), 1)
        self.assertEqual(sc.count('regionSize = 0x8000;'), 1)
        self.assertIn('#define FLASH_SIZE              0xA0000', ld)
        self.assertIn('#define FLASH_NV_BASE           0xA6000', ld)
        self.assertIn('#define FLASH_NV_SIZE           0x8000', ld)
        self.assertIn('#define FLASH_LAST_BASE         0xAE000', ld)
        self.assertIn('--stack_size=4096', ld)
        self.assertNotIn('--stack_size=1024', ld)
        self.assertIn('-DNVOCMP_NVPAGES=4', project)
        self.assertIn('--define=NVOCMP_NVPAGES=4', project)
        self.assertLess(full.APP_END, full.NV_START)
        self.assertEqual(full.NV_END, 0xAE000)
        with self.assertRaisesRegex(ValueError, 'ANCHOR_DRIFT'):
            full.transform_pinned(sc, ld, project)

    def test_tampered_profile_refused(self):
        with tempfile.TemporaryDirectory() as t:
            altered = copy.deepcopy(full.validate_profile(full.DEFAULT_PROFILE))
            altered['capacities']['trust_center_devices'] = 255
            path = Path(t) / 'mutated.json'
            path.write_text(json.dumps(altered))
            with self.assertRaisesRegex(ValueError, 'EXACT_PROFILE_SEMANTICS_DRIFT'):
                full.validate_profile(path)

    def test_pinned_source_rejects_synthetic_inputs_without_mutation(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            paths = [root / f for f in ('znp.syscfg', 'znp.cmd', 'znp.projectspec')]
            for path, contents in zip(paths, pinned_fixture()):
                path.write_text(contents)
            initial = [x.read_bytes() for x in paths]
            out = root / 'receipt.json'
            with self.assertRaisesRegex(ValueError, 'PINNED_TI_SOURCE_BLOB_DRIFT'):
                full.apply_pinned(*paths, out)
            self.assertEqual(initial, [x.read_bytes() for x in paths])
            self.assertFalse(out.exists())

    def test_imported_pinned_nv4_board_power_is_20240716(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            source = root / 'imported.syscfg'
            source.write_text(board_source())
            profile_sha = full.sha(full.DEFAULT_PROFILE.read_bytes())
            prior = {
                'schema': 'p7u-r4-full-nv4-source-composition-v1',
                'profile_sha256': profile_sha,
                'sdk_commit': full.SDK_SHA,
                'full_b0_b4_sealed': False,
                'composed_source_sha256': [full.sha(source.read_bytes())],
            }
            receipt = root / 'pinned.json'
            receipt.write_text(json.dumps(prior))
            result = full.apply_imported(source, receipt, root/'board.json')
            after = source.read_text()
            self.assertEqual(after.count('device.forceVddr = true;'), 1)
            self.assertEqual(after.count('device.enableDCDC = true;'), 1)
            self.assertEqual(after.count('NVS1.internalFlash.regionBase = 0xA6000;'), 1)
            self.assertEqual(result['ccfg_expected_sha256'], full.CCFG_SHA)
            self.assertFalse(result['native_verified'])
            self.assertFalse(result['flash_authorized'])
            with self.assertRaisesRegex(ValueError, 'IMPORTED_INPUT_OR_RECEIPT_INVALID'):
                full.apply_imported(source, receipt, root/'board.json')

    def test_imported_modified_after_pinning_is_refused(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            source = root/'imported.syscfg'
            source.write_text(board_source())
            prior = {
                'schema': 'p7u-r4-full-nv4-source-composition-v1',
                'profile_sha256': full.sha(full.DEFAULT_PROFILE.read_bytes()),
                'sdk_commit': full.SDK_SHA,
                'full_b0_b4_sealed': False,
                'composed_source_sha256': [full.sha(source.read_bytes())],
            }
            receipt = root/'pinned.json'
            receipt.write_text(json.dumps(prior))
            source.write_text(source.read_text().replace('0xA6000', '0xA0000'))
            changed = source.read_bytes()
            with self.assertRaisesRegex(ValueError, 'CCS_IMPORT_SOURCE_DIFFERS'):
                full.apply_imported(source, receipt, root/'board.json')
            self.assertEqual(source.read_bytes(), changed)
            self.assertFalse((root/'board.json').exists())


if __name__ == '__main__':
    unittest.main()
