"""Offline proof that the disposable TI M4F build evaluates .s #if guards."""
import tempfile
import unittest
import importlib.util
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
        self.instructions[abi.HWI[2]] = ("msr psp, r1", "msr msp, r0")
        with self.assertRaisesRegex(ValueError, "HWI_PATH_INCOMPLETE"):
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


if __name__ == "__main__":
    unittest.main()
