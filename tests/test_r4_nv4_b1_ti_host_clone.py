"""Actual pinned TI + B1 + NV4 bridge initialize using protected host RAM."""
from __future__ import annotations

import importlib.util
import json
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
spec = importlib.util.spec_from_file_location('r4_b1_ti_nv4_host',
                                             QUAL / 'nv4_b1_ti_host_clone.py')
clone = importlib.util.module_from_spec(spec)
spec.loader.exec_module(clone)
NEEDED = ('R4_TI_NVOCMP_SOURCE', 'R4_TI_CRC_SOURCE',
          'R4_B1_NV4_SOURCE', 'R4_B1_NV4_RECEIPT')


class PinnedIntegrityTests(unittest.TestCase):
    def test_public_pinned_sources_and_bridge_receipt_required(self):
        with self.assertRaisesRegex(ValueError, 'PINNED_TI_OR_CRC_MISMATCH'):
            clone.transform(b'wrong', b'wrong', b'wrong', '0' * 64)


@unittest.skipUnless(shutil.which('gcc') and all(os.environ.get(k) for k in NEEDED),
                     'requires gcc, pinned TI sources and actual post-B1 NV4 overlay')
class PostB1Nv4TiIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='r4-nv4-b1-host-')
        pristine = Path(os.environ['R4_TI_NVOCMP_SOURCE']).read_bytes()
        crc = Path(os.environ['R4_TI_CRC_SOURCE']).read_bytes()
        bridged = Path(os.environ['R4_B1_NV4_SOURCE']).read_bytes()
        receipt = json.loads(Path(os.environ['R4_B1_NV4_RECEIPT']).read_text())
        cls.generated = clone.transform(pristine, crc, bridged,
                                        receipt['source_after_sha256'])
        cls.binary = Path(cls.temp.name) / 'b1_nv4_ti'
        source = Path(cls.temp.name) / 'host.c'
        source.write_text(cls.generated)
        build = subprocess.run([
            'gcc', '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror',
            '-Wno-unused-function', '-Wno-unused-variable', '-Wno-unused-parameter',
            '-Wno-sign-compare', '-I', str(ROOT/'firmware/slzb-06p7u/r4/b1'),
            '-I', str(QUAL), str(source), '-o', str(cls.binary),
        ], capture_output=True, text=True)
        if build.returncode:
            raise RuntimeError(build.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def probe(self, image: bytes) -> dict:
        proc = subprocess.run([str(self.binary)], input=image,
                              capture_output=True, check=True, timeout=10)
        self.assertFalse(proc.stderr)
        return json.loads(proc.stdout)

    def test_real_b1_boot_existing_nv4_no_flash(self):
        result = self.probe(stock_like_semantic())
        self.assertTrue(result['ti_init_readonly_accepted'])
        self.assertEqual(result['init_code'], 0)
        self.assertEqual(result['ti_init_action'], 1)
        self.assertEqual(result['nv_pages'], 4)
        self.assertEqual((result['all_items'], result['active_items']), (3, 3))
        self.assertEqual((result['write_attempts'], result['erase_attempts'],
                          result['compaction_attempts']), (0, 0, 0))
        self.assertFalse(result['flash_authorized'])

    def test_real_b1_boot_after_ti_cleanpage_formatted_inactive_pages(self):
        media = bytearray(stock_like_semantic())
        for page in (1, 2):
            media[page * 8192] = 0xff  # PGNACT with intact TI-signed header
        result = self.probe(bytes(media))
        self.assertTrue(result['ti_init_readonly_accepted'])
        self.assertEqual(result['ti_init_action'], 1)
        self.assertEqual((result['all_items'], result['active_items']), (3, 3))
        self.assertEqual((result['write_attempts'], result['erase_attempts'],
                          result['compaction_attempts']), (0, 0, 0))
        self.assertFalse(result['flash_authorized'])

    def test_bad_crc_holds_before_ti_initialization(self):
        image = bytearray(stock_like_semantic())
        image[16] ^= 1
        result = self.probe(bytes(image))
        self.assertFalse(result['ti_init_readonly_accepted'])
        self.assertEqual(result['init_code'], 2)
        self.assertEqual((result['write_attempts'], result['erase_attempts'],
                          result['compaction_attempts']), (0, 0, 0))

    def test_repair_page_state_holds_without_writes(self):
        image = bytearray(stock_like_semantic())
        image[0] = 0x70  # Power-loss/compaction in progress, not normal NV4
        result = self.probe(bytes(image))
        self.assertFalse(result['ti_init_readonly_accepted'])
        self.assertEqual(result['init_code'], 2)
        self.assertEqual((result['write_attempts'], result['erase_attempts'],
                          result['compaction_attempts']), (0, 0, 0))

    def test_structurally_valid_unidentified_store_holds_before_native_init(self):
        from tests.test_r4_nv4_readonly_admission import stock_like
        result = self.probe(stock_like())
        self.assertFalse(result['ti_init_readonly_accepted'])
        self.assertEqual(result['init_code'], 2)
        self.assertEqual((result['write_attempts'], result['erase_attempts'],
                          result['compaction_attempts']), (0, 0, 0))

    def test_semantic_contradictions_hold_before_native_init(self):
        for variant in (dict(bdb=1), dict(nib=True), dict(logical=1),
                        dict(bdb=None), dict(bdb_payload=b'\x00\x00')):
            with self.subTest(**variant):
                result = self.probe(stock_like_semantic(**variant))
                self.assertFalse(result['ti_init_readonly_accepted'])
                self.assertEqual(result['init_code'], 2)
                self.assertEqual((result['write_attempts'], result['erase_attempts'],
                                  result['compaction_attempts']), (0, 0, 0))


if __name__ == '__main__':
    unittest.main()
