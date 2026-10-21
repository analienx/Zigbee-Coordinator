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
    def test_reduced_source_shim_cannot_satisfy_native_startup_guard(self):
        for require, present, donor, blob, modified in (
                (seal.require_retained_zdo_source, "retained_zdo_guard_source_present",
                 "upstream_mt_zdo_blob", seal.MT_ZDO_BLOB, "modified_mt_zdo_sha256"),
                (seal.require_retained_bdb_source, "retained_bdb_restore_source_present",
                 "upstream_bdb_blob", seal.BDB_BLOB, "modified_bdb_sha256")):
            overlay = {present: True, donor: blob, modified: "a" * 64,
                       "additional_source_bindings": {modified: seal.SOURCE_BINDINGS[modified]}}
            require(overlay)
            for key, bad in ((present, False), (donor, None), (modified, None),
                             ("additional_source_bindings", {})):
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, "reduced SDK shim"):
                    require({**overlay, key: bad})

    def test_guard_symbol_alone_cannot_substitute_for_mt_zdo_object(self):
        document = """<link_info><input_file id="f"><kind>object</kind>
<file>{owner}</file></input_file><object_component><name>.text.{name}</name>
<run_address>0x100</run_address><size>0x24</size><executable>true</executable>
<input_file_ref idref="f"/></object_component></link_info>"""
        functions = {seal.MT_ZDO_GUARD: {"address": 0x100, "size": 0x20}}
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "native.xml"
            path.write_text(document.format(owner="mt_zdo.o", name=seal.MT_ZDO_GUARD))
            evidence = seal.retained_zdo_ownership(path, functions)
            self.assertEqual(evidence["owner"], "mt_zdo.o")
            self.assertFalse(evidence["shared_startup_hang_fixed"])
            path.write_text(document.format(owner="synthetic_stub.o", name=seal.MT_ZDO_GUARD))
            with self.assertRaisesRegex(ValueError, "ownership differs"):
                seal.retained_zdo_ownership(path, functions)

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
