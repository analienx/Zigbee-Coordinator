"""Fail-closed native B1 comparison, including full NV4 observer image class."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "firmware/slzb-06p7u/r4/b1/tools/compare_native.py"
spec = importlib.util.spec_from_file_location("r4_compare_native", SCRIPT)
compare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compare)


def role(nv4=False):
    return {
        "classification": compare.LINKED_NV4 if nv4 else compare.LINKED_NV2,
        "full_b0_b4_sealed": False,
        "nv4_bridge_compiled": nv4,
        "linked_functions": {"r4_nv4_admit" if nv4 else "b1_nv_probe": {
            "address": 0x7000, "size": 256}},
    }


class CompareNativeNv4Tests(unittest.TestCase):
    def test_strict_nv4_mode_requirements(self):
        good = role(True)
        self.assertEqual(compare.validate_linked_mode(good), compare.LINKED_NV4)
        for field, mutated in (
                ("nv4_bridge_compiled", False),
                ("full_b0_b4_sealed", True),
                ("linked_functions", {"b1_nv_probe": {"address": 0, "size": 1}}),
                ("classification", "FULL_B0_B4")):
            broken = {**good, field: mutated}
            with self.subTest(field=field), self.assertRaises(ValueError):
                compare.validate_linked_mode(broken)

    def test_unmodified_nv2_role_remains_separate(self):
        self.assertEqual(compare.validate_linked_mode(role(False)), compare.LINKED_NV2)
        for altered in (
                {**role(False), "nv4_bridge_compiled": True},
                {**role(False), "linked_functions": {"r4_nv4_admit": {}}},
                {**role(True), "linked_functions": {**role(True)["linked_functions"],
                                                  "b1_nv_probe": {}}}):
            with self.assertRaises(ValueError):
                compare.validate_linked_mode(altered)


if __name__ == "__main__":
    unittest.main()
