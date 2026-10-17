"""B1 status F1 vs B4 diagnostics F0/F2 negative guard."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"firmware"/"slzb-06p7u"/"r4"/"b4"))
from b4_v4_cross_phase_gate import inspect
B1_HDR = "#define B1_STATUS_COMMAND 0xF1u\n"
B1_SRC = "if(frame[2] == B1_STATUS_COMMAND) return B1_MT_STATUS;"
B4_SYS = "case 0xF0:\nbreak;\ncase 0xF2:\nbreak;\n"

class CrossPhase(unittest.TestCase):
    def test_b1_f1_b4_f0_f2_do_not_overlap(self):
        evidence=inspect(B1_HDR,B1_SRC,B4_SYS)
        self.assertFalse(evidence["command_collision"])
        self.assertFalse(evidence["b1_hold_allows_b4_v4_f2"])
        self.assertFalse(evidence["b1_b4_combined_source_ready"])
    def test_b1_opcode_drift_or_v4_collision_fails(self):
        for h,m in [(B1_HDR.replace("F1","F2"),B4_SYS),
                    (B1_HDR,B4_SYS.replace("0xF2","0xF1")),
                    (B1_HDR,B4_SYS.replace("0xF2","0xF0"))]:
            with self.subTest(h=h,m=m),self.assertRaises(ValueError):
                inspect(h,B1_SRC,m)
    def test_no_unverified_b1_hold_admission_is_claimed(self):
        with self.assertRaises(ValueError):
            inspect(B1_HDR,B1_SRC.replace("return B1_MT_STATUS","return B1_MT_CONTINUE"),B4_SYS)

if __name__=="__main__":
    unittest.main()
