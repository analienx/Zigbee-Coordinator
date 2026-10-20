"""HOSTED ONLY: exact C oracle over public synthetic media, never private NV."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tests.test_r4_nv4_readonly_admission import (
    PAGE_SIZE, stock_like, stock_like_semantic,
)


ROOT = Path(__file__).resolve().parents[1]
QUAL = ROOT / 'firmware/slzb-06p7u/r4/qualification'
spec = importlib.util.spec_from_file_location(
    'nv4_host_trace', QUAL / 'nv4_admission_host_trace.py')
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


class SourcePinTests(unittest.TestCase):
    def test_original_source_and_bridge_drift_cannot_be_instrumented(self):
        source = oracle.public_source('nv4_readonly_admission.c')
        with self.assertRaisesRegex(ValueError, 'OBSERVER_SOURCE_DRIFT'):
            oracle.instrument(source.replace('1024u', '512u'))
        bridge = oracle.public_source('nv4_b1_bridge.py')
        with self.assertRaisesRegex(ValueError, 'BRIDGE_SOURCE_DRIFT'):
            oracle.bridge_c(bridge.replace('B1_NV_HOLD_MIXED_LAYOUT',
                                         'B1_NV2_HEADER_CANDIDATE'))
        with tempfile.TemporaryDirectory() as name:
            out = Path(name) / 'generated'
            report = oracle.generate(out, '1' * 40)
            self.assertEqual(report['nv_region'], ['0xA4000', '0xAC000'])
            self.assertFalse(report['firmware_modified'])
            self.assertFalse(report['flash_authorized'])
            self.assertEqual((out / 'nv4_readonly_admission.c').read_text(), source)
            self.assertIn('#line 1 "nv4_readonly_admission.c"',
                          (out / 'nv4_admission_traced.c').read_text())
            with self.assertRaisesRegex(ValueError, 'NONEMPTY_OUTPUT_DENIED'):
                oracle.generate(out, '1' * 40)


@unittest.skipUnless(shutil.which('gcc'), 'hosted gcc required for C oracle')
class CompiledOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='nv4-host-trace-')
        cls.out = Path(cls.temporary.name) / 'generated'
        oracle.generate(cls.out, '1' * 40)
        cls.binary = cls.compile('nv4-oracle')

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    @classmethod
    def compile(cls, name):
        binary = cls.out / name
        process = subprocess.run([
            'gcc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
            '-I', str(cls.out),
            *(str(cls.out / name) for name in (
                'nv4_readonly_admission.c', 'nv4_admission_traced.c',
                'nv4_bridge_reason.c', 'nv4_admission_trace_cli.c')),
            '-o', str(binary),
        ], capture_output=True)
        if process.returncode:
            raise RuntimeError(process.stderr.decode('utf-8', 'replace'))
        return binary

    def run_oracle(self, media, mode='--stdin-nv4-a4000', binary=None,
                   expected_status=0):
        process = subprocess.run([str(binary or self.binary), mode], input=media,
                                 capture_output=True)
        self.assertEqual(process.returncode, expected_status, process.stderr)
        self.assertNotIn(b'not-a-real-key', process.stdout)
        self.assertNotIn(b'synthetic-nib-not-a-secret', process.stdout)
        report = json.loads(process.stdout)
        self.assertFalse(report['flash_authorized'])
        if expected_status == 0:
            self.assertTrue(report['original_traced_result_equal'])
            self.assertTrue(report['read_sequence_equal'])
            self.assertFalse(report['runtime_equivalence_proven'])
        return report

    def test_every_probe_four_return_site_has_actual_c_line(self):
        fixtures = []
        metadata = bytearray(stock_like())
        metadata[6] = 0xf0
        fixtures.append((metadata, 'page_metadata', 268, 4, 0))
        state = bytearray(stock_like())
        state[PAGE_SIZE] = 0x70
        fixtures.append((state, 'page_state', 278, 4, 1))
        destination = bytearray(stock_like())
        destination[3 * PAGE_SIZE + 16] = 0
        fixtures.append((destination, 'empty_page_contents', 297, 4, 3))
        counts = bytearray(stock_like())
        counts[PAGE_SIZE] = 0x7c
        fixtures.append((counts, 'page_counts', 308, 4, None))
        fixtures.append((stock_like(records=2, duplicate=True),
                         'duplicate_active_identity', 172, 9, 0))
        fixtures.append((stock_like(), 'semantic_unknown_hold', 326, 8, None))
        for media, reason, line, code, page in fixtures:
            with self.subTest(reason=reason):
                report = self.run_oracle(media)
                self.assertEqual((report['code'], report['bridge_probe']), (code, 4))
                self.assertEqual((report['reason'], report['line'], report['page']),
                                 (reason, line, page))
                self.assertTrue(report['bridge_hold_nv_expected'])

    def test_coherent_formed_markers_and_crc_rejection_remain_unchanged(self):
        formed = stock_like_semantic(bdb=1, nib=True)
        report = self.run_oracle(formed)
        self.assertEqual((report['code'], report['semantic_state'],
                          report['bridge_probe']), (8, 2, 7))
        self.assertEqual(report['reason'], 'structure_candidate')
        self.assertFalse(report['bridge_hold_nv_expected'])
        self.assertEqual(report['markers'], {
            'bdb_seen': 1, 'bdb_class_zero_one_other': 1, 'role_seen': 1,
            'role_is_coordinator': 1, 'nib_seen': 1, 'malformed': 0,
        })
        broken = bytearray(formed)
        broken[16] ^= 1
        report = self.run_oracle(broken)
        self.assertEqual((report['code'], report['bridge_probe'],
                          report['reason'], report['line']), (6, 9, 'item_crc', 151))
        for kwargs in (dict(bdb=None), dict(logical=None), dict(bdb=2),
                       dict(logical=1), dict(bdb=1), dict(nib=True),
                       dict(bdb_payload=b'\0\0')):
            with self.subTest(markers=kwargs):
                report = self.run_oracle(stock_like_semantic(**kwargs))
                self.assertEqual((report['code'], report['semantic_state'],
                                  report['bridge_probe']), (8, 0, 4))

    def test_full_capture_explicit_a4000_slice_and_exact_length_only(self):
        region = stock_like_semantic(bdb=1, nib=True)
        full = bytearray(b'\xff' * 0xB0000)
        full[0xA4000:0xAC000] = region
        report = self.run_oracle(full, '--stdin-full-a4000')
        region_report = self.run_oracle(region)
        self.assertEqual(report, region_report)
        for media, mode in ((region, '--stdin-full-a4000'),
                            (region[:-1], '--stdin-nv4-a4000'),
                            (region + b'X', '--stdin-nv4-a4000'),
                            (full, '--stdin-full-a6000')):
            with self.subTest(length=len(media), mode=mode):
                result = self.run_oracle(media, mode, expected_status=2)
                self.assertIn('oracle_error', result)

    def test_trace_result_or_read_sequence_changes_fail_closed(self):
        path = self.out / 'nv4_admission_traced.c'
        original = path.read_text()
        anchor = 'r.code = R4_NV4_READONLY_STRUCTURE_ACCEPTED;'
        mutations = (
            '++r.records; ' + anchor,
            '{ uint8_t ignored; (void)reader(ctx, 0u, &ignored, 1u); } ' + anchor,
        )
        try:
            for i, mutation in enumerate(mutations):
                with self.subTest(mutation=i):
                    path.write_text(original.replace(anchor, mutation))
                    binary = self.compile(f'parity-mutant-{i}')
                    report = self.run_oracle(stock_like_semantic(), binary=binary,
                                             expected_status=3)
                    self.assertEqual(report['oracle_error'],
                                     'original_traced_parity_failed')
        finally:
            path.write_text(original)


if __name__ == '__main__':
    unittest.main()
