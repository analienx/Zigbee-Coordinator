"""Pinned, genuine TI 8.33 NVOCMP v3 four-page RAM-only initialization.

CI fetches pristine public source. No private captures or device flash needed.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tests.test_r4_nv4_readonly_admission import stock_like


ROOT = Path(__file__).resolve().parents[1]
QUAL = ROOT / 'firmware/slzb-06p7u/r4/qualification'
module_spec = importlib.util.spec_from_file_location('r4_ti_nv4_clone',
                                                     QUAL / 'nv4_ti_host_clone.py')
clone = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(clone)


class TiNv4GeneratorTests(unittest.TestCase):
    def test_pins_and_readonly_clone_are_explicit(self):
        self.assertEqual(clone.TI_NV_GIT_BLOB, '01b2b0827d278c10c012b33e5791e53bc5662f10')
        self.assertEqual(clone.TI_CRC_GIT_BLOB, '55f7bc7b617cde41f46110216d897ddfc908b870')
        self.assertRaisesRegex(ValueError, 'PINNED_TI_833_SOURCE_BLOB_MISMATCH',
                               clone.transform, b'not TI code', b'not TI crc')


@unittest.skipUnless(shutil.which('gcc') and os.environ.get('R4_TI_NVOCMP_SOURCE')
                     and os.environ.get('R4_TI_CRC_SOURCE'),
                     'host gcc and two exact public TI 8.33 source paths required')
class TiNv4PinnedSourceIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='ti-nv4-pinned-host-')
        cls.source = Path(os.environ['R4_TI_NVOCMP_SOURCE']).read_bytes()
        cls.crc = Path(os.environ['R4_TI_CRC_SOURCE']).read_bytes()
        cls.generated = clone.transform(cls.source, cls.crc)
        cls.binary = Path(cls.temp.name) / 'nv4_ti_host_probe'
        target = Path(cls.temp.name) / 'nv4_ti_host.c'
        target.write_text(cls.generated)
        build = subprocess.run([
            'gcc', '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror',
            '-Wno-unused-function', '-Wno-unused-variable', '-Wno-unused-parameter',
            '-Wno-sign-compare', '-I', str(ROOT / 'firmware/slzb-06p7u/r4/b1'),
            str(target), '-o', str(cls.binary),
        ], capture_output=True, text=True)
        if build.returncode:
            raise RuntimeError(build.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_real_compiler_branch_regular_item_search(self):
        self.assertIn('#define NVOCMP_FASTITEM     0', self.source.decode('utf-8'))
        self.assertIn('NVOCMP_readHeader(p, ofs, &iHdr, false);', self.generated)
        self.assertNotIn('NVOCMP_readHeader(p, ofs, &iHdr, true);', self.generated)

    def test_stock_like_four_pages_initialize_without_mutation(self):
        result = subprocess.run([str(self.binary)], input=stock_like(),
                                capture_output=True, timeout=10, check=True)
        self.assertFalse(result.stderr)
        receipt = json.loads(result.stdout)
        self.assertTrue(receipt['ti_init_readonly_accepted'])
        self.assertEqual(receipt['init_code'], 0)
        self.assertEqual(receipt['ti_init_action'], 1)
        self.assertEqual(receipt['nv_pages'], 4)
        self.assertEqual(receipt['all_items'], 1)
        self.assertEqual(receipt['active_items'], 1)
        self.assertEqual(receipt['write_attempts'], 0)
        self.assertEqual(receipt['erase_attempts'], 0)
        self.assertEqual(receipt['compaction_attempts'], 0)
        self.assertFalse(receipt['flash_authorized'])

    def test_fail_closed_on_bad_input_length(self):
        result = subprocess.run([str(self.binary)], input=stock_like()[:-1],
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 7)
        self.assertFalse(result.stdout)


if __name__ == '__main__':
    unittest.main()
