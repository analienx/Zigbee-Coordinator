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
            file.write_text("intro\n" + scope.BEFORE + "\n" +
                            scope.SOURCE_LIST + "\nrest\n")
            asm_dir = root / "kernel/tirtos7/packages/ti/sysbios/family/arm/m3"
            asm_dir.mkdir(parents=True)
            for name in scope.M4F_ASM:
                (asm_dir / name).write_bytes(b"#if defined(__ARM_FP)\nasm\n#endif\n")
            receipt = scope.scope(root)
            result = file.read_text()
            self.assertIn(scope.AFTER, result)
            self.assertNotIn(scope.BEFORE, result)
            self.assertIn(scope.PREPROCESS_M4F, result)
            self.assertEqual(receipt["target_preserved"], "m4f")
            self.assertEqual(len(receipt["m4f_preprocessed_asm_source_sha256"]), 3)
            for name in scope.M4F_ASM:
                self.assertEqual((asm_dir / name).read_bytes(),
                                 (asm_dir / name).with_suffix(".S").read_bytes())
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

    def test_missing_cmake_transform_or_asm_refused_without_partial_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            file = root / scope.RELATIVE
            file.parent.mkdir(parents=True)
            file.write_text(scope.BEFORE + "\n" + scope.SOURCE_LIST)
            asm_dir = root / "kernel/tirtos7/packages/ti/sysbios/family/arm/m3"
            asm_dir.mkdir(parents=True)
            for name in scope.M4F_ASM[:-1]:
                (asm_dir / name).write_bytes(b"synthetic ASM source")
            original = file.read_bytes()
            with self.assertRaisesRegex(ValueError, "Missing pinned M4F ASM"):
                scope.scope(root)
            self.assertEqual(file.read_bytes(), original)
            self.assertFalse(list(asm_dir.glob("*.S")))
            (asm_dir / scope.M4F_ASM[-1]).write_bytes(b"synthetic ASM source")
            file.write_text(scope.BEFORE + "\nwrong transform")
            with self.assertRaisesRegex(ValueError, "refuse patch"):
                scope.scope(root)


if __name__ == "__main__":
    unittest.main()
