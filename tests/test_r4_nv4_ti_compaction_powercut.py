"""Pinned TI >2-page compaction and deterministic NOR media cuts, no flash."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from tests.test_r4_nv4_readonly_admission import (
    PAGE_SIZE, encoded_record, legacy_osal_record, stock_like,
    stock_like_semantic,
)

ROOT = Path(__file__).resolve().parents[1]
QUAL = ROOT / 'firmware/slzb-06p7u/r4/qualification'
sys.path.insert(0, str(QUAL))
spec = importlib.util.spec_from_file_location('r4_t4_compact',
                                             QUAL / 'nv4_ti_compaction_powercut.py')
cut = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cut)


class T4FourPageSourcePinTests(unittest.TestCase):
    def test_vendor_source_or_crc_mutation_cannot_create_harness(self):
        with self.assertRaisesRegex(ValueError, 'T4_PINNED_TI_SOURCE_BLOB_MISMATCH'):
            cut.transform(b'not pinned nvocmp', b'not pinned CRC')

    def test_generator_contains_real_ti_four_page_not_old_two_page_branch(self):
        self.assertIn("('static int16_t NVOCMP_compactPage(', 0)",
                      (QUAL / 'nv4_ti_compaction_powercut.py').read_text())
        self.assertIn("('static NVOCMP_compactStatus_t NVOCMP_compact(', 0)",
                      (QUAL / 'nv4_ti_compaction_powercut.py').read_text())
        self.assertIn('longjmp(power_cut_boundary,1)', cut.WRITE_NEW)
        self.assertIn('longjmp(power_cut_boundary,1)', cut.ERASE_NEW)
        self.assertNotIn('flash_authorized', cut.MAIN.lower())


@unittest.skipUnless(shutil.which('gcc') and
                     os.environ.get('R4_TI_NVOCMP_SOURCE') and
                     os.environ.get('R4_TI_CRC_SOURCE'),
                     'requires gcc and two public pinned TI source files')
class T4PinnedSourceFourPageCuts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='r4-t4-four-page-cuts-')
        binary = Path(cls.temp.name) / 'nv4-cuts'
        source = Path(cls.temp.name) / 'nv4-cuts.c'
        transformed = cut.transform(
            Path(os.environ['R4_TI_NVOCMP_SOURCE']).read_bytes(),
            Path(os.environ['R4_TI_CRC_SOURCE']).read_bytes())
        source.write_text(transformed)
        build = subprocess.run([
            'gcc', '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
            '-Wno-unused-function', '-Wno-unused-variable',
            '-Wno-unused-parameter', '-Wno-sign-compare',
            '-fsanitize=undefined', '-fno-sanitize-recover=all',
            '-I', str(ROOT / 'firmware/slzb-06p7u/r4/b1'),
            '-I', str(QUAL), str(source), '-o', str(binary),
        ], capture_output=True, text=True)
        if build.returncode:
            raise RuntimeError(build.stderr)
        cls.binary = binary

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_cuts(self, image: bytes):
        self.assertEqual(len(image), 4 * PAGE_SIZE)
        result = subprocess.run([str(self.binary)], input=image,
                                capture_output=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertFalse(result.stderr, result.stderr.decode())
        output = result.stdout.decode()
        self.assertIn('R4_T4_PINNED_TI_FOUR_PAGE_COMPACTION_CUTS_PASS', output)
        self.assertIn('native_holds=0', output)
        self.assertIn('NOT_PROVEN=counter_monotonicity', output)
        return output

    def test_three_public_unformed_records_and_torn_erase(self):
        output = self.run_cuts(stock_like_semantic())
        # TI sets seven harmless early F8 *mode* variants before entering
        # PGXSRC. The C harness proves their media bytes are unchanged except
        # for mode offsets; all interrupted relocation/erase states HOLD.
        self.assertIn('operations=26 trials=52 held=44 candidates=8 '
                      'prep=7 committed=1', output)

    def test_formed_like_synthetic_nib_bdb_and_role_markers(self):
        self.run_cuts(stock_like_semantic(bdb=1, nib=True))

    def test_120_public_synthetic_live_items_plus_network_markers(self):
        media = bytearray(stock_like(records=120))
        cursor = 16 + 120 * len(encoded_record(0))
        for row in (legacy_osal_record(0x55, b'\x00'),
                    legacy_osal_record(0x87, b'\x00')):
            media[cursor:cursor + len(row)] = row
            cursor += len(row)
        self.run_cuts(bytes(media))


if __name__ == '__main__':
    unittest.main()
