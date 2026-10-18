"""Source-only negative controls for the exact B1 native NV4 role seal."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'firmware/slzb-06p7u/r4/b1/tools/seal_native.py'
spec = importlib.util.spec_from_file_location('r4_exact_b1_seal', SCRIPT)
seal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(seal)


class Nv4NativeSealTests(unittest.TestCase):
    def test_nv2_probe_cannot_substitute_for_native_nv4_observer(self):
        self.assertIn('b1_nv_probe', seal.REQUIRED_FUNCTIONS)
        self.assertNotIn('b1_nv_probe', seal.NV4_REQUIRED_FUNCTIONS)
        self.assertIn('r4_nv4_admit', seal.NV4_REQUIRED_FUNCTIONS)
        self.assertNotIn('r4_nv4_admit', seal.REQUIRED_FUNCTIONS)
        self.assertEqual(len(seal.NV4_REQUIRED_FUNCTIONS),
                         len(seal.REQUIRED_FUNCTIONS))
        self.assertEqual(len(set(seal.NV4_REQUIRED_FUNCTIONS)),
                         len(seal.NV4_REQUIRED_FUNCTIONS))

    def test_corrupt_elf_is_not_symbol_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'native.out'
            for mutated in (b'', b'R4D4', b'\x7fELF' + b'\0'*128):
                path.write_bytes(mutated)
                with self.assertRaisesRegex(ValueError, 'real ELF32'):
                    seal.elf_functions(path)

    def test_full_native_workflow_wires_executable_nv4_seal(self):
        native = (ROOT / '.github/workflows/test-r4-final-composite-native.yml').read_text()
        self.assertIn('--b1-overlay-receipt /tmp/b0out/b1-overlay.json', native)
        self.assertIn('qualification/nv4_b1_bridge.py', native)
        self.assertIn('--expected-sha "$B1_SOURCE_SHA" --nv4-bridge', native)
        self.assertLess(native.index('qualification/nv4_b1_bridge.py'),
                        native.index('--expected-sha "$B1_SOURCE_SHA" --nv4-bridge'))


if __name__ == '__main__':
    unittest.main()
