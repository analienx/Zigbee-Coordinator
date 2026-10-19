"""Pinned TI four-page compaction NOR cuts, on synthetic flash only."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from tests.test_r4_nv4_readonly_admission import stock_like_semantic


ROOT = Path(__file__).resolve().parents[1]
QUAL = ROOT / 'firmware/slzb-06p7u/r4/qualification'
sys.path.insert(0, str(QUAL))
spec = importlib.util.spec_from_file_location('r4_nv4_ti_powercut',
                                             QUAL / 'nv4_powercut_ti_host_clone.py')
powercut = importlib.util.module_from_spec(spec)
spec.loader.exec_module(powercut)


class GeneratorIntegrityTests(unittest.TestCase):
    def test_ti_source_pin_is_fail_closed(self):
        with self.assertRaisesRegex(ValueError, 'PINNED_TI_833_SOURCE_BLOB_MISMATCH'):
            powercut.transform(b'changed TI source', b'changed CRC source')

    def test_vendor_bodies_are_selected_without_rewriting_them(self):
        self.assertIn('NVOCMP_compactPage(', powercut.MAIN)
        self.assertIn('longjmp(cut_boundary,1)', powercut.WRITE_NOR)
        self.assertIn('longjmp(cut_boundary,1)', powercut.ERASE_NOR)
        self.assertIn('r4_nv4_admit(independent_read,NULL)', powercut.MAIN)


@unittest.skipUnless(shutil.which('gcc') and os.environ.get('R4_TI_NVOCMP_SOURCE')
                     and os.environ.get('R4_TI_CRC_SOURCE'),
                     'requires gcc and exact pinned public TI 8.33 NV and CRC sources')
class PinnedTiFourPagePowercutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='r4-ti-nv4-cut-')
        nv = Path(os.environ['R4_TI_NVOCMP_SOURCE']).read_bytes()
        crc = Path(os.environ['R4_TI_CRC_SOURCE']).read_bytes()
        generated = powercut.transform(nv, crc)
        source = Path(cls.temp.name) / 'powercut.c'
        cls.binary = Path(cls.temp.name) / 'powercut'
        source.write_text(generated, encoding='utf-8')
        proc = subprocess.run([
            'gcc', '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror',
            '-Wno-unused-function', '-Wno-unused-variable', '-Wno-unused-parameter',
            '-Wno-sign-compare', '-I', str(ROOT / 'firmware/slzb-06p7u/r4/b1'),
            '-I', str(QUAL), str(source), str(QUAL / 'nv4_readonly_admission.c'),
            '-o', str(cls.binary),
        ], capture_output=True, text=True)
        if proc.returncode:
            raise RuntimeError(proc.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_every_compaction_write_erase_boundary_holds_or_readonly_resumes(self):
        proc = subprocess.run([str(self.binary)], input=stock_like_semantic(),
                              capture_output=True, timeout=20, check=True)
        self.assertFalse(proc.stderr)
        self.assertIn(b'R4_T4_PINNED_TI_NV4_NOR_CUTS_PASS', proc.stdout)
        self.assertIn(b'cuts=24703 ops=26 holds=24701 candidates=2', proc.stdout)
        self.assertIn(b'flash_authorized=false', proc.stdout)

    def test_short_nv_snapshot_is_refused(self):
        proc = subprocess.run([str(self.binary)], input=stock_like_semantic()[:-1],
                              capture_output=True, timeout=10)
        self.assertEqual(proc.returncode, 7)
        self.assertFalse(proc.stdout)


if __name__ == '__main__':
    unittest.main()
