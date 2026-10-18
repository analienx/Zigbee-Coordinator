"""R4-P2-05: pinned B4 disposable host overlays must not escape via symlinks."""
import importlib
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "host" / "r4-b4"))
from safe_checkout_files import validate_sources, write_source_text

CASES = (
    ("herdsman_overlay", "DEFINITION"),
    ("b4_v4_herdsman_overlay", "DEFINITION"),
    ("b4_z2m_ota_overlay", "OTA"),
    ("b4_v4_z2m_overlay", "CONTROLLER"),
)


class B4SymlinkContainment(unittest.TestCase):
    @staticmethod
    def root_and_external(folder, relative):
        root = folder / "checkout"
        root.mkdir()
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("original", encoding="utf-8")
        outside = folder / "outside"
        outside.write_text("PRIVATE_SENTINEL_UNCHANGED", encoding="utf-8")
        return root, target, outside

    def test_all_four_plan_entrypoints_deny_symlinked_leaf(self):
        for module_name, attribute in CASES:
            with self.subTest(overlay=module_name), tempfile.TemporaryDirectory(dir="/tmp") as d:
                module = importlib.import_module(module_name)
                relative = getattr(module, attribute)
                folder = Path(d)
                root, target, outside = self.root_and_external(folder, relative)
                target.unlink()
                target.symlink_to(outside)
                # Must fail before Git provenance reads or source anchor parsing.
                with self.assertRaisesRegex(ValueError, "symlink"):
                    module.plan(root)
                self.assertEqual(outside.read_text(), "PRIVATE_SENTINEL_UNCHANGED")

    def test_all_four_plan_entrypoints_deny_symlinked_ancestor(self):
        for module_name, attribute in CASES:
            with self.subTest(overlay=module_name), tempfile.TemporaryDirectory(dir="/tmp") as d:
                module = importlib.import_module(module_name)
                relative = getattr(module, attribute)
                folder = Path(d)
                root, target, outside = self.root_and_external(folder, relative)
                parent = target.parent
                shutil.rmtree(parent)
                external_dir = folder / "external_directory"
                external_dir.mkdir()
                (external_dir / target.name).write_text("PRIVATE_SENTINEL_UNCHANGED")
                parent.symlink_to(external_dir, target_is_directory=True)
                with self.assertRaisesRegex(ValueError, "symlink"):
                    module.plan(root)
                self.assertEqual((external_dir / target.name).read_text(),
                                 "PRIVATE_SENTINEL_UNCHANGED")

    def test_apply_revalidates_output_after_plan_even_if_source_was_swapped(self):
        for module_name, attribute in CASES:
            with self.subTest(overlay=module_name), tempfile.TemporaryDirectory(dir="/tmp") as d:
                module = importlib.import_module(module_name)
                relative = getattr(module, attribute)
                folder = Path(d)
                root, target, outside = self.root_and_external(folder, relative)
                target.unlink()
                target.symlink_to(outside)
                plan_result = (("original", "changed") if module_name == "b4_v4_z2m_overlay"
                               else {relative: ("original", "changed")})
                with patch.object(module, "plan", return_value=plan_result):
                    with self.assertRaisesRegex(ValueError, "symlink"):
                        module.apply(root)
                self.assertEqual(outside.read_text(), "PRIVATE_SENTINEL_UNCHANGED")

    def test_validation_and_nofollow_write_accept_regular_disposable_source(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as d:
            root, target, _ = self.root_and_external(Path(d), "deep/tree/source.ts")
            validate_sources(root, ("deep/tree/source.ts",))
            write_source_text(root, "deep/tree/source.ts", "new\n")
            self.assertEqual(target.read_bytes(), b"new\n")

    def test_hardlinked_source_cannot_modify_outside_file(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as d:
            folder = Path(d)
            root, target, outside = self.root_and_external(folder, "deep/source.ts")
            target.unlink()
            target.hardlink_to(outside)
            with self.assertRaisesRegex(ValueError, "unshared regular file"):
                write_source_text(root, "deep/source.ts", "changed")
            self.assertEqual(outside.read_text(), "PRIVATE_SENTINEL_UNCHANGED")

    def test_checkout_symlink_and_non_disposable_root_rejected(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as d:
            folder = Path(d)
            root, _, _ = self.root_and_external(folder, "source.ts")
            alias = folder / "alias"
            alias.symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "disposable"):
                validate_sources(alias, ("source.ts",))
            with self.assertRaises(ValueError):
                validate_sources(Path("/etc"), ("passwd",))


if __name__ == "__main__":
    unittest.main()
