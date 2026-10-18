"""Fail-closed, isolated fixture for the disposable pinned TI M4F SDK scope."""

import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILE = ROOT / "firmware/slzb-06p7u/r4/b0/tools/b0_sdk_build_scope.py"
spec = importlib.util.spec_from_file_location("b0_scope", FILE)
scope = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scope)

ASM_DIR = Path("kernel/tirtos7/packages/ti/sysbios/family/arm/m3")


def make_sdk(root: Path):
    """Provide both required CMake anchors and all three independent ASM inputs."""
    cmake = root / scope.RELATIVE
    cmake.parent.mkdir(parents=True)
    before = "intro\n" + scope.BEFORE + "\n" + scope.SOURCE_LIST + "\nrest\n"
    cmake.write_text(before, encoding="utf-8")
    asm_dir = root / ASM_DIR
    asm_dir.mkdir(parents=True)
    sources = {}
    for name in scope.M4F_ASM:
        data = ("/* preprocessor fixture: " + name + " */\n#if defined(__ARM_FP)\n#endif\n").encode()
        (asm_dir / name).write_bytes(data)
        sources[name] = data
    return cmake, before, sources


class ScopeTests(unittest.TestCase):
    def test_only_generic_m4_removed_not_m4f(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cmake, before, sources = make_sdk(root)
            receipt = scope.scope(root)
            result = cmake.read_text(encoding="utf-8")
            self.assertIn(scope.AFTER, result)
            self.assertNotIn(scope.BEFORE, result)
            self.assertEqual(result.count(scope.PREPROCESS_M4F), 1)
            self.assertEqual(receipt["target_preserved"], "m4f")
            self.assertEqual(receipt["scope"], "TEMPORARY_HOSTED_SDK_BUILD_ONLY")
            self.assertEqual(receipt["before_sha256"], hashlib.sha256(before.encode()).hexdigest())
            for name, data in sources.items():
                original = root / ASM_DIR / name
                promoted = original.with_suffix(".S")
                self.assertEqual(original.read_bytes(), data)
                self.assertEqual(promoted.read_bytes(), data)
                self.assertEqual(
                    receipt["m4f_preprocessed_asm_source_sha256"][name],
                    hashlib.sha256(data).hexdigest(),
                )
            self.assertEqual(receipt["after_sha256"], hashlib.sha256(cmake.read_bytes()).hexdigest())
            with self.assertRaisesRegex(ValueError, "refuse patch"):
                scope.scope(root)
            self.assertEqual(cmake.read_text(encoding="utf-8"), result)

    def test_unrecognized_sdk_source_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cmake, _, sources = make_sdk(root)
            corrupted = "set(TIRTOS_SUPPORTED_ARCHITECTURES m0p m4 m33f)"
            cmake.write_text(corrupted)
            with self.assertRaisesRegex(ValueError, "refuse patch"):
                scope.scope(root)
            self.assertEqual(cmake.read_text(), corrupted)
            for name, data in sources.items():
                self.assertEqual((root / ASM_DIR / name).read_bytes(), data)
                self.assertFalse((root / ASM_DIR / name).with_suffix(".S").exists())

    def test_missing_asm_fails_before_any_sdk_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cmake, before, sources = make_sdk(root)
            missing = root / ASM_DIR / scope.M4F_ASM[-1]
            missing.unlink()
            with self.assertRaisesRegex(ValueError, "Missing pinned M4F ASM"):
                scope.scope(root)
            self.assertEqual(cmake.read_text(), before)
            for name in sources:
                self.assertFalse((root / ASM_DIR / name).with_suffix(".S").exists())

    def test_existing_preprocessed_asm_fails_before_any_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cmake, before, sources = make_sdk(root)
            existing = (root / ASM_DIR / scope.M4F_ASM[-1]).with_suffix(".S")
            existing.write_bytes(b"must never overwrite")
            with self.assertRaisesRegex(ValueError, "Refuse to overwrite"):
                scope.scope(root)
            self.assertEqual(cmake.read_text(), before)
            self.assertEqual(existing.read_bytes(), b"must never overwrite")
            for name in sources:
                if name != scope.M4F_ASM[-1]:
                    self.assertFalse((root / ASM_DIR / name).with_suffix(".S").exists())


if __name__ == "__main__":
    unittest.main()
