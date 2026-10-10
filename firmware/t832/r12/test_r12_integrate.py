"""Bind R12 source bridges to exact R11 compile-time symbols."""
from pathlib import Path
import re
import unittest
from r12_integrate import patch_r11_header

R11 = Path(__file__).resolve().parents[1] / "r6" / "r11_startup.h"

class IntegrationHeaderTest(unittest.TestCase):
    def test_all_bridged_identifiers_exist_in_R11(self):
        pristine = R11.read_text(encoding="utf8")
        changed = patch_r11_header(pristine)
        self.assertEqual(changed.count("T832R12_mark("), 3)
        self.assertEqual(changed.count('#include "r12_target.h"'), 1)
        self.assertNotIn("T832_R11_PHASE_", changed)
        self.assertNotIn("T832_R11_SITE_", changed)
        declared = set(re.findall(r"^#define\s+(T832R11_\w+)\b",pristine,re.M))
        for marker in re.findall(r"T832R12_mark\([^,]+,\s*(T832R11_\w+)",changed):
            self.assertIn(marker, declared)
        self.assertIn("T832R11_PHASE_ENTRY",declared)
        self.assertIn("T832R11_PHASE_EXIT",declared)
        self.assertIn("T832R11_PHASE_CONFIRM",declared)
        self.assertIn("T832R11_SITE_FORM_CONFIRM",declared)

    def test_no_second_patch_or_drifted_function(self):
        src=R11.read_text(encoding="utf8")
        patched=patch_r11_header(src)
        with self.assertRaises(ValueError):
            patch_r11_header(patched)
        with self.assertRaises(ValueError):
            patch_r11_header(src.replace("static inline void T832R11_enter",
                                         "static inline void RENAMED_ENTER"))

if __name__ == "__main__":
    unittest.main()
