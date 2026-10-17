"""Synthetic log negative controls; these do NOT replace the actual CCS P3 run."""
import unittest
from tools.b2_verify_p3_link import validate, P3ValidationError

INJECTION={
  "expected":"TI_LINKER_SRAM_OVERFLOW_NOT_CPP_OR_COMPILER_ERROR",
  "requested_bss_bytes":0x24000,
  "sram_region_bytes":0x24000,
  "sdk_sha":"3615ad5d3f4f271258d18a2f5ce1785064ff9a58",
  "source_inputs_modified_only_in_throwaway_sdk":True,
}
GOOD="""**** Build Started ****
Invoking: Arm Linker
\"tiarmclang\" -Wl,--xml_link_info=znp.xml
../cc13x2x7_cc26x2x7_tirtos7_ticlang.cmd, line 165: error #10099-D: program will not fit into available memory. placement with alignment fails for section \".bss\" size 0x24000 .
Available memory ranges:
SRAM size: 0x24000 unused: 0 max hole: 0
**** Build Finished **** 1 project has errors.
"""

class P3NativeLogOracle(unittest.TestCase):
    def test_realistic_link_overbudget_log(self):
        r=validate(GOOD,1,INJECTION)
        self.assertEqual(r["status"],"HOSTED_NATIVE_LINKER_OVERBUDGET_REJECTED")
        self.assertFalse(r["usable_firmware_produced"])
    def test_true_ti_linker_wraparound_error_allowed(self):
        actual=GOOD+'\n'+'tiarmclang: error: tiarmlnk command failed with exit code 1 (use -v to see invocation)'
        self.assertEqual(validate(actual,1,INJECTION)["status"],
                         "HOSTED_NATIVE_LINKER_OVERBUDGET_REJECTED")
    def test_wrapper_does_not_cover_unrelated_compile_error(self):
        actual=GOOD+'\n'+'tiarmclang: error: tiarmlnk command failed with exit code 1'+'\n'+'tiarmclang: error: no such file or directory: broken.c'
        with self.assertRaisesRegex(P3ValidationError,"non-memory"):
            validate(actual,1,INJECTION)
    def test_compiler_error_not_enough(self):
        with self.assertRaisesRegex(P3ValidationError,"linker never executed"):
            validate("tiarmclang: error: no such file or directory",1,INJECTION)
    def test_flash_overflow_is_not_a_sram_negative(self):
        with self.assertRaisesRegex(P3ValidationError,"SRAM placement"):
            validate(GOOD.replace("SRAM size:", "FLASH size:"),1,INJECTION)
    def test_wrong_linked_sram_geometry_rejected(self):
        with self.assertRaisesRegex(P3ValidationError,"SRAM placement"):
            validate(GOOD.replace("SRAM size: 0x24000", "SRAM size: 0x08000"),1,INJECTION)
    def test_wrong_error_10099_text_rejected(self):
        with self.assertRaisesRegex(P3ValidationError,"missing genuine TI memory"):
            validate(GOOD.replace("10099-D","10234-D"),1,INJECTION)
    def test_successful_build_not_negative(self):
        with self.assertRaisesRegex(P3ValidationError,"unexpectedly linked"):
            validate(GOOD,0,INJECTION)
    def test_unexpected_compiler_error_contaminates(self):
        with self.assertRaisesRegex(P3ValidationError,"non-memory compiler"):
            validate(GOOD+"\ntiarmclang: error: missing -D flag",1,INJECTION)
    def test_wrong_sdk_pin(self):
        d=dict(INJECTION,sdk_sha="0"*40)
        with self.assertRaisesRegex(P3ValidationError,"SDK pin"):
            validate(GOOD,1,d)
    def test_wrong_sram_size(self):
        d=dict(INJECTION,requested_bss_bytes=5000)
        with self.assertRaisesRegex(P3ValidationError,"counterexample"):
            validate(GOOD,1,d)

if __name__=="__main__":
    unittest.main()
