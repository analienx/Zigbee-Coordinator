"""Host-only T5 source ordering oracle; never a network/flash qualification."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / 'firmware/slzb-06p7u/r4/b1/tools'
sys.path.insert(0, str(TOOLS))
from make_t5_security_harness import transform  # noqa: E402


class GeneratorGuards(unittest.TestCase):
    def test_refuses_missing_real_ti_function(self):
        with self.assertRaisesRegex(RuntimeError, 'ZDAPP_FUNCTION_NOT_UNIQUE'):
            transform('void unrelated(void) {}')

    def test_refuses_unknown_mutant(self):
        with self.assertRaisesRegex(ValueError, 'T5_UNKNOWN_MUTANT'):
            transform('unused', mutant='not-a-real-negative-control')


@unittest.skipUnless(shutil.which('gcc') and os.environ.get('R4_T5_SECURITY_SOURCE'),
                     'requires gcc and exact B1-overlaid pinned TI zd_sec_mgr.c')
class ActualB1TiCounterOrdering(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix='r4-t5-security-')
        cls.source = Path(os.environ['R4_T5_SECURITY_SOURCE']).read_text()
        cls.binary = cls.compile('normal')

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    @classmethod
    def compile(cls, name, mutant=None):
        generated = Path(cls.work.name) / (name + '.c')
        binary = Path(cls.work.name) / name
        generated.write_text(transform(cls.source, mutant))
        result = subprocess.run([
            'gcc', '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
            '-Wno-unused-parameter', '-Wno-unused-function',
            '-Wno-unused-variable', '-Wno-type-limits',
            '-fsanitize=undefined', '-fno-sanitize-recover=all',
            str(generated), '-o', str(binary),
        ], capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise RuntimeError(result.stderr)
        return binary

    def test_every_commit_failure_and_reboot_at_tc_index_edges(self):
        for scenario in ('write_fail', 'readback_fail', 'commit_crash'):
            for n, slot in enumerate((0, 255, 256, 299)):
                with self.subTest(scenario=scenario, slot=slot):
                    result = subprocess.run([str(self.binary), scenario, str(n)],
                                            capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn(f'ORDERING_PASS {scenario} slot={slot}', result.stdout)
                    self.assertIn('seed_immutable=true', result.stdout)
                    self.assertIn('TI_NOR_ATOMICITY_NOT_PROVEN', result.stdout)

    def test_aps_commit_crash_before_ram_publication(self):
        result = subprocess.run([str(self.binary), 'aps_crash', '0'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('ORDERING_PASS aps_crash slot=0', result.stdout)

    def test_successful_300_slot_preflight_and_reservation(self):
        result = subprocess.run([str(self.binary), 'success', '3'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('ORDERING_PASS success slot=299', result.stdout)

    def test_compiled_uint8_loop_mutant_rejected(self):
        binary = self.compile('short_index', 'short_index')
        result = subprocess.run([str(binary), 'success', '3'],
                                capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('reads <= gZDSECMGR_TC_DEVICE_MAX * 5u + 150u', result.stderr)

    def test_premature_counter_publication_mutant_rejected(self):
        binary = self.compile('publish_before_commit', 'publish_before_commit')
        result = subprocess.run([str(binary), 'write_fail', '2'],
                                capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('TCLinkKeyRAMEntry', result.stderr)


if __name__ == '__main__':
    unittest.main()
