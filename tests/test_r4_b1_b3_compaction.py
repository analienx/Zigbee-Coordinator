"""B1 owns NVOCMP; B3 contributes only destination-first journal ordering."""
import sys
from pathlib import Path
import unittest
TOOLS=Path(__file__).resolve().parents[1]/"firmware/slzb-06p7u/r4/b1/tools"
sys.path.insert(0,str(TOOLS))
from b1_b3_compaction_journal import OLD, NEW, patch

PREFIX = """/* B1 patched real TI source markers */
int b1_nv_runtime_hold_active(void);
void b1_nv_runtime_hold_latch(void);
uint8_t b1_nv_initializing;
"""

class Journal(unittest.TestCase):
    def test_safe_order_and_sticky_hold(self):
        actual=patch(PREFIX+OLD)
        self.assertEqual(actual.count(NEW),1)
        self.assertLess(actual.index("NVOCMP_writeByte(dstPg"),
                        actual.index("NVOCMP_erase(pNvHandle, srcPg)"))
        self.assertIn("NVOCMP_failW != NVINTF_SUCCESS",actual)
        self.assertIn("NVOCMP_read(dstPg, NVOCMP_COMPMODEOFS, &b1_journal_readback, 1u)",actual)
        self.assertIn("b1_journal_readback != NVOCMP_PGCDONE",actual)
        self.assertLess(actual.index("b1_journal_readback != NVOCMP_PGCDONE"),
                        actual.index("NVOCMP_erase(pNvHandle, srcPg)"))
        self.assertIn("b1_nv_runtime_hold_latch();",actual)
        with self.assertRaises(RuntimeError):patch(actual)

    def test_hostile_preimage_fails_closed(self):
        for x in (OLD+OLD, OLD.replace("NVOCMP_erase","NVOCMP_delete"),
                  OLD.replace("NVOCMP_PGCDONE","NVOCMP_PGX"),""):
            with self.subTest(source=x),self.assertRaises(RuntimeError):
                patch(PREFIX+x)

    def test_no_b1_authority_means_no_patch(self):
        for source in (OLD, "b1_nv_runtime_hold_active()\n"+OLD):
            with self.assertRaises(RuntimeError):patch(source)

    def test_mutant_reversing_commit_and_erase_is_detected(self):
        changed=patch(PREFIX+OLD)
        commit=changed.index("NVOCMP_writeByte(dstPg")
        erase=changed.index("NVOCMP_erase(pNvHandle, srcPg)")
        self.assertLess(commit,erase)
        broken=changed.replace(NEW,OLD)
        with self.assertRaises(AssertionError):
            self.assertLess(broken.index("NVOCMP_writeByte(dstPg"),
                            broken.index("NVOCMP_erase(pNvHandle, srcPg)"))

if __name__=="__main__": unittest.main()
