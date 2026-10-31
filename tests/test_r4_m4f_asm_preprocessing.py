"""Offline proof that the disposable TI M4F build evaluates .s #if guards."""
import tempfile
import unittest
import importlib.util
import struct
import sys
from pathlib import Path

SOURCE = (Path(__file__).resolve().parents[1] /
          "firmware/slzb-06p7u/r4/b0/tools/b0_sdk_build_scope.py")
SPEC = importlib.util.spec_from_file_location("b0_sdk_build_scope", SOURCE)
scope_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scope_module)
sys.path.insert(0, str(SOURCE.parents[2] / "qualification"))
import rtos_context_audit as abi


class ScopeTest(unittest.TestCase):
    def test_m4f_only_asm_sources_promoted_without_modifying_ti_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            sdk = Path(directory)
            cmake = sdk / scope_module.RELATIVE
            cmake.parent.mkdir(parents=True)
            baseline = scope_module.BEFORE + "\n" + scope_module.SOURCE_LIST + "\n"
            cmake.write_text(baseline)
            asm = cmake.parent / "family/arm/m3"
            asm.mkdir(parents=True)
            for name in scope_module.M4F_ASM:
                (asm / name).write_text("#if defined(__ARM_ARCH_8M_MAIN__)\n"
                                        "mrs r2, psplim\n#endif\n")
            receipt = scope_module.scope(sdk)
            self.assertEqual(receipt["asm_input_suffix"], ".S")
            self.assertIn(scope_module.PREPROCESS_M4F, cmake.read_text())
            self.assertEqual(len(receipt["m4f_preprocessed_asm_source_sha256"]), 3)
            for name in scope_module.M4F_ASM:
                self.assertEqual((asm / name).read_bytes(), (asm / name).with_suffix(".S").read_bytes())
            with self.assertRaisesRegex(ValueError, "pinned baseline"):
                scope_module.scope(sdk)


class MachineFrameTest(unittest.TestCase):
    def setUp(self):
        m = {
            abi.SWAP: ("push.w {r4, r5, r6, r7, r8, r9, r10, r11, lr}",
                       "vpush {d8, d9, d10, d11, d12, d13, d14, d15}",
                       "str sp, [r0]", "ldr sp, [r1]",
                       "vpop {d8, d9, d10, d11, d12, d13, d14, d15}",
                       "pop.w {r4, r5, r6, r7, r8, r9, r10, r11, pc}"),
            abi.HWI[0]: ("mrs r1, basepri", "mrs r2, psp", "vmrs r3, fpscr"),
            abi.HWI[1]: ("mrsne r1, psp", "bx lr"),
            abi.HWI[2]: ("msr psp, r1", "msr msp, r0", "msr control, r0"),
            abi.HWI[3]: ("mrs r4, control", "blx r0"),
        }
        self.instructions = m

    def disassembly(self):
        return {name: "000034ac <" + name + ">:\n" + "\n".join(
            f"  {0x34ac + i * 4:08x}:  {code}" for i, code in enumerate(codes))
            for name, codes in self.instructions.items()}

    def test_correct_m4f_frame_returns_to_glue(self):
        result = abi.verify_m4f_disassembly(self.disassembly())
        self.assertEqual(result["m4f_restored_pc_word_index"], 24)
        self.assertTrue(result["m4f_first_task_returns_to_glue"])

    def test_prior_linked_armv8m_psplim_frame_is_rejected(self):
        asm = list(self.instructions[abi.SWAP])
        asm.insert(2, "mrs r2, psplim")
        asm.insert(3, "push {r2, r3}")
        asm.insert(-1, "pop {r2, r3}")
        self.instructions[abi.SWAP] = tuple(asm)
        with self.assertRaisesRegex(ValueError, "ARMV8_STACK_LIMIT"):
            abi.verify_m4f_disassembly(self.disassembly())

    def test_missing_critical_hwi_path_is_rejected(self):
        self.instructions[abi.HWI[2]] = ()
        with self.assertRaisesRegex(ValueError, "EMPTY_DISASSEMBLY"):
            abi.verify_m4f_disassembly(self.disassembly())

    def test_armv8m_msplim_in_linked_hwi_is_rejected(self):
        self.instructions[abi.HWI[2]] += ("msr msplim, r0",)
        with self.assertRaisesRegex(ValueError, "ARMV8_STACK_LIMIT"):
            abi.verify_m4f_disassembly(self.disassembly())

    def test_objdump_sb_sl_fp_register_aliases(self):
        self.instructions[abi.SWAP] = tuple(
            code.replace("r9", "sb").replace("r10", "sl").replace("r11", "fp")
            for code in self.instructions[abi.SWAP]
        )
        self.assertEqual(abi.verify_m4f_disassembly(self.disassembly())["m4f_restored_pc_word_index"], 24)

    def test_linked_swap_is_pinned_machine_frame_not_text_mnemonics(self):
        from xml.etree import ElementTree
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            elf = root / "linked.out"
            elf.with_suffix(".bin").write_bytes(b"\x00" * 128 + abi.M4F_SWAP_SECTION)
            xml = root / "linked.xml"
            section = ElementTree.Element("object_component")
            ElementTree.SubElement(section, "name").text = ".text." + abi.SWAP
            ElementTree.SubElement(section, "run_address").text = "0x80"
            ElementTree.SubElement(section, "size").text = "0x28"
            ElementTree.ElementTree(section).write(xml)
            self.assertEqual(abi.audit_linked_swap_bytes(xml, elf)["size"], 40)
            # The earlier unpreprocessed SYS/BIOS code had two extra stack
            # words before PC; any changed frame must be rejected.
            old = elf.with_suffix(".bin").read_bytes().replace(
                abi.M4F_SWAP_INSTRUCTIONS, b"\x00" * len(abi.M4F_SWAP_INSTRUCTIONS))
            elf.with_suffix(".bin").write_bytes(old)
            with self.assertRaisesRegex(ValueError, "MACHINE_BYTES_MISMATCH"):
                abi.audit_linked_swap_bytes(xml, elf)

    def full_frame_fixture(self, root, frame, *, flags=5):
        from xml.etree import ElementTree
        address = 0x239B4
        elf = root / "full.out"
        ident = b"\x7fELF\x01\x01\x01" + bytes(9)
        header = ident + struct.pack("<HHIIIIIHHHHHH", 2, 40, 1, address | 1,
                                     52, 0, 0, 52, 32, 1, 40, 0, 0)
        program = struct.pack("<8I", 1, 0x100, address, address,
                              len(frame), len(frame), flags, 4)
        elf.write_bytes(header + program + bytes(0x100 - len(header) - len(program)) + frame)
        elf.with_suffix(".bin").write_bytes(bytes(address) + frame)
        xml = root / "full.xml"
        section = ElementTree.Element("object_component")
        ElementTree.SubElement(section, "name").text = ".text." + abi.SWAP
        ElementTree.SubElement(section, "run_address").text = hex(address)
        ElementTree.SubElement(section, "size").text = "0x28"
        ElementTree.ElementTree(section).write(xml)
        return xml, elf

    def test_full_linked_m4f_frame_relocated_in_actual_executable_load(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            xml, elf = self.full_frame_fixture(root, abi.M4F_SWAP_SECTION)
            result = abi.audit_linked_swap_bytes(xml, elf, full_nv4=True)
            self.assertEqual(result["address"], "0x239b4")
            self.assertEqual(result["size"], 40)
            self.assertEqual(result["app_ceiling_exclusive"], "0xa0000")
            self.assertEqual(result["executable_pt_load"]["flags"], 5)
            with self.assertRaisesRegex(ValueError, "SECTION_GEOMETRY"):
                abi.audit_linked_swap_bytes(xml, elf)  # diagnostic bound retained
            xml, elf = self.full_frame_fixture(root, abi.M4F_SWAP_SECTION, flags=4)
            with self.assertRaisesRegex(ValueError, "EXECUTABLE_FLASH_LOAD"):
                abi.audit_linked_swap_bytes(xml, elf, full_nv4=True)

    def test_full_relocated_prior_armv8m_machine_frame_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            # MRS r2,PSPLIM plus the shifted frame must never be accepted even
            # with consistent ELF/BIN bytes and a legal full-profile address.
            old_frame = bytes.fromhex("eff30b82") + abi.M4F_SWAP_SECTION[:-4]
            xml, elf = self.full_frame_fixture(Path(directory), old_frame)
            with self.assertRaisesRegex(ValueError, "MACHINE_BYTES_MISMATCH"):
                abi.audit_linked_swap_bytes(xml, elf, full_nv4=True)


if __name__ == "__main__":
    unittest.main()
