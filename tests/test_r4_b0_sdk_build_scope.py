import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILE = ROOT / "firmware/slzb-06p7u/r4/b0/tools/b0_sdk_build_scope.py"
spec = importlib.util.spec_from_file_location("b0_scope", FILE)
scope = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scope)


class ScopeTests(unittest.TestCase):
    def test_only_generic_m4_removed_not_m4f(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            file = root / scope.RELATIVE
            file.parent.mkdir(parents=True)
            file.write_text("intro\n" + scope.BEFORE + "\nrest\n")
            receipt = scope.scope(root)
            result = file.read_text()
            self.assertIn(scope.AFTER, result)
            self.assertNotIn(scope.BEFORE, result)
            self.assertEqual(receipt["target_preserved"], "m4f")
            with self.assertRaisesRegex(ValueError, "refuse patch"):
                scope.scope(root)

    def test_unrecognized_sdk_source_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            file = root / scope.RELATIVE
            file.parent.mkdir(parents=True)
            file.write_text("set(TIRTOS_SUPPORTED_ARCHITECTURES m0p m4 m33f)")
            with self.assertRaisesRegex(ValueError, "refuse patch"):
                scope.scope(root)


if __name__ == "__main__":
    unittest.main()
