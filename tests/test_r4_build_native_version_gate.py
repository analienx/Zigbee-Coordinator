"""Secondary native entry point rejects lookalike TI version fingerprints."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest


QUAL = Path(__file__).resolve().parents[1] / 'firmware/slzb-06p7u/r4/qualification'
sys.path.insert(0, str(QUAL))
from build_native import verify_ti_versions


GOOD_CLANG = ('TI Arm Clang Compiler 3.2.2.LTS\nTarget: arm-ti-none-eabi\n'
              'InstalledDir: /tmp/ti-clang/3.2.2.LTS/bin\n')


class NativeVersionGateTests(unittest.TestCase):
    def test_valid_pinned_tool_versions_pass(self):
        verify_ti_versions('1.21.1+3772\n', GOOD_CLANG)

    def test_wrong_sysconfig_suffix_rejected(self):
        with self.assertRaisesRegex(ValueError, 'SYSCONFIG_PIN_MISMATCH'):
            verify_ti_versions('1.21.1+37720\n', GOOD_CLANG)

    def test_clang_major_version_substring_mutant_rejected(self):
        with self.assertRaisesRegex(ValueError, 'COMPILER_PIN_MISMATCH'):
            verify_ti_versions('1.21.1+3772\n', GOOD_CLANG.replace('3.2.2', '13.2.2'))

    def test_hidden_wrong_clang_after_correct_installdir_rejected(self):
        with self.assertRaisesRegex(ValueError, 'COMPILER_PIN_MISMATCH'):
            verify_ti_versions('1.21.1+3772\n',
                               GOOD_CLANG.replace('Compiler 3.2.2', 'Compiler 4.0.0'))


if __name__ == '__main__':
    unittest.main()
