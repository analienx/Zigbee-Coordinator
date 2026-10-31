"""Source-only negative controls for the exact B1 native NV4 role seal."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'firmware/slzb-06p7u/r4/b1/tools/seal_native.py'
spec = importlib.util.spec_from_file_location('r4_exact_b1_seal', SCRIPT)
seal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(seal)
sys.path.insert(0,str(ROOT/'tools'))
import r4_srsp_runtime_priority as priority


class Nv4NativeSealTests(unittest.TestCase):
    @staticmethod
    def priority_elf(value, *, symbol_type=1, symbol_size=4, symbol_address=0x1000):
        strings=b'\0ti_sysbios_knl_Task_numPriorities\0'
        raw=bytearray(52)
        raw[:7]=b'\x7fELF\x01\x01\x01'
        struct.pack_into('<HHI',raw,16,2,40,1)
        data_offset=len(raw);raw.extend(struct.pack('<I',value))
        str_offset=len(raw);raw.extend(strings)
        while len(raw)%4:raw.append(0)
        sym_offset=len(raw);raw.extend(bytes(16))
        raw.extend(struct.pack('<IIIBBH',1,symbol_address,symbol_size,0x10|symbol_type,0,1))
        shoff=len(raw);struct.pack_into('<I',raw,32,shoff)
        struct.pack_into('<HHH',raw,46,40,4,0)
        for row in ((0,0,0,0,0,0,0,0,0,0),
                    (0,1,2,0x1000,data_offset,4,0,0,4,0),
                    (0,3,0,0,str_offset,len(strings),0,0,1,0),
                    (0,2,0,0,sym_offset,32,2,0,4,16)):
            raw.extend(struct.pack('<10I',*row))
        return bytes(raw)

    def test_priority_count_must_be_real_defined_allocated_elf_object(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'native.out';path.write_bytes(self.priority_elf(16))
            self.assertEqual(seal.elf_u32_object(path,'ti_sysbios_knl_Task_numPriorities')['value'],16)
            for mutation in ({'symbol_type':0},{'symbol_size':8},{'symbol_address':0x1004}):
                path.write_bytes(self.priority_elf(16,**mutation))
                with self.subTest(mutation=mutation),self.assertRaises(ValueError):
                    seal.elf_u32_object(path,'ti_sysbios_knl_Task_numPriorities')
            path.write_bytes(self.priority_elf(16))
            with self.assertRaisesRegex(ValueError,'missing or ambiguous'):
                seal.elf_u32_object(path,'synthetic_priority_count')

    def test_priority_native_gate_rejects_unusable_range_and_wrong_owner(self):
        name='B4_V46_RefreshNpiPriority'
        functions={name:{'address':0x200,'size':0x20}}
        template='<link_info><input_file id="f"><kind>object</kind><file>{owner}</file></input_file><object_component><name>.text.{name}</name><run_address>0x200</run_address><size>0x20</size><executable>true</executable><input_file_ref idref="f"/></object_component></link_info>'
        with tempfile.TemporaryDirectory() as temp:
            elf=Path(temp)/'native.out';xml=Path(temp)/'native.xml'
            xml.write_text(template.format(owner='npi_task.o',name=name))
            for count in (8,):
                elf.write_bytes(self.priority_elf(count))
                self.assertEqual(seal.srsp_priority_native_abi(elf,xml,functions)['pending_srsp_priority'],6)
            for count in (0,6,7,16,32,33):
                elf.write_bytes(self.priority_elf(count))
                with self.subTest(count=count),self.assertRaisesRegex(ValueError,'requires native'):
                    seal.srsp_priority_native_abi(elf,xml,functions)
            elf.write_bytes(self.priority_elf(8));xml.write_text(template.format(owner='synthetic.o',name=name))
            with self.assertRaisesRegex(ValueError,'ownership differs'):
                seal.srsp_priority_native_abi(elf,xml,functions)

    def test_syscfg_configures_eight_priorities_without_changing_other_input(self):
        src='const Task = scripting.addModule("/ti/sysbios/knl/Task");\n\tTask.numPriorities = 6;\nRF.unchanged = true;\n'
        result=priority.transform_syscfg(src)
        self.assertIn('Task.numPriorities = 8;',result)
        self.assertTrue(result.endswith('RF.unchanged = true;\n'))
        for bad in (result,src.replace('6;','5;'),src+'Task.numPriorities = 6;\n',src.replace('const Task','const Other')):
            with self.subTest(bad=bad),self.assertRaises(ValueError):priority.transform_syscfg(bad)

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
