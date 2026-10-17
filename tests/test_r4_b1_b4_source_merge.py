"""Conservative 3-way source patch requires unique unmodified original context."""
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1] /
                   "firmware/slzb-06p7u/r4/b1/tools"))
from r4_b4_source_merge import merge_lines

class Merge(unittest.TestCase):
    def donor(self):
        return "".join(f"unique_{i:02d}();\n" for i in range(36))

    def test_nonoverlapping_insertions_survive(self):
        donor=self.donor()
        b1=donor.replace("unique_08();","b1_guard();\nunique_08();")
        b4=donor.replace("unique_25();","b4_metrics();\nunique_25();")
        merged,changes=merge_lines(donor,b1,b4)
        self.assertIn("b1_guard();",merged)
        self.assertIn("b4_metrics();",merged)
        self.assertTrue(changes)

    def test_actual_overlap_fails_closed(self):
        donor=self.donor()
        b1=donor.replace("unique_08();","b1_nv_hold();")
        b4=donor.replace("unique_08();","b4_record();")
        with self.assertRaises(ValueError):merge_lines(donor,b1,b4)

    def test_repeated_fragments_ambiguous_fail(self):
        donor="repeat();\n"*30
        b1=donor.replace("repeat();","b1();",1)
        b4=donor.replace("repeat();","b4();",1)
        with self.assertRaises(ValueError):merge_lines(donor,b1,b4)

    def test_disjoint_full_file_cases(self):
        d=self.donor()
        self.assertEqual(merge_lines(d,d,d.replace("unique_30","b4"))[0],
                         d.replace("unique_30","b4"))
        self.assertEqual(merge_lines(d,d.replace("unique_30","b1"),d)[0],
                         d.replace("unique_30","b1"))

if __name__=="__main__":unittest.main()
