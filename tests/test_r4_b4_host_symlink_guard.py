"""R4-P2-05: pinned B4 disposable host overlays must not escape via symlinks."""
import importlib
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "host" / "r4-b4"))
from safe_checkout_files import (read_source_bytes, read_source_text,
                                 validate_sources, write_source_text)

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
            self.assertEqual(read_source_bytes(root, "deep/tree/source.ts"), b"original")
            self.assertEqual(read_source_text(root, "deep/tree/source.ts"), "original")
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
            with self.assertRaisesRegex(ValueError, "unshared regular file"):
                read_source_bytes(root, "deep/source.ts")
            self.assertEqual(outside.read_text(), "PRIVATE_SENTINEL_UNCHANGED")

    def test_leaf_swap_after_validation_cannot_redirect_source_read(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as d:
            folder = Path(d)
            root, target, outside = self.root_and_external(folder, "deep/source.ts")
            validate_sources(root, ("deep/source.ts",))
            target.unlink()
            target.symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "symlink"):
                read_source_bytes(root, "deep/source.ts")
            self.assertEqual(outside.read_text(), "PRIVATE_SENTINEL_UNCHANGED")

    def test_special_file_read_cannot_stall_or_escape_source_gate(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as d:
            root = Path(d) / "checkout"
            root.mkdir()
            os.mkfifo(root / "source.ts")
            with self.assertRaisesRegex(ValueError, "unshared regular file"):
                read_source_bytes(root, "source.ts")
            with self.assertRaisesRegex(ValueError, "unsafe source"):
                write_source_text(root, "source.ts", "changed")

    def test_ancestor_swap_during_descriptor_walk_rejects_read_and_write(self):
        for mode in ("read", "write"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(dir="/tmp") as d:
                folder = Path(d)
                gate = folder / "gate"
                checkout = gate / "checkout"
                checkout.mkdir(parents=True)
                source = checkout / "source.ts"
                source.write_text("original")
                external = folder / "outside"
                (external / "checkout").mkdir(parents=True)
                outside = external / "checkout" / "source.ts"
                outside.write_text("PRIVATE_SENTINEL_UNCHANGED")
                original_open = os.open
                injected = False

                def swap_during_open(path, flags, *args, **kwargs):
                    nonlocal injected
                    if path == Path("/tmp") and not injected:
                        injected = True
                        gate.rename(folder / "old_gate")
                        gate.symlink_to(external, target_is_directory=True)
                    return original_open(path, flags, *args, **kwargs)

                validate_sources(checkout, ("source.ts",))
                with patch("safe_checkout_files.os.open", side_effect=swap_during_open):
                    with self.assertRaisesRegex(ValueError, "symlink"):
                        if mode == "read":
                            read_source_bytes(checkout, "source.ts")
                        else:
                            write_source_text(checkout, "source.ts", "changed")
                self.assertTrue(injected)
                self.assertEqual(outside.read_text(), "PRIVATE_SENTINEL_UNCHANGED")

    def test_all_four_planners_recheck_source_read_after_validation(self):
        for module_name, attribute in CASES:
            with self.subTest(overlay=module_name), tempfile.TemporaryDirectory(dir="/tmp") as d:
                module = importlib.import_module(module_name)
                relative = getattr(module, attribute)
                root, target, outside = self.root_and_external(Path(d), relative)
                original_validate = module.validate_sources

                def swap_after_validation(root_arg, paths):
                    original_validate(root_arg, (relative,))
                    target.unlink()
                    target.symlink_to(outside)

                # Admit the pinned HEAD, then demand a fresh FD-bound source
                # read instead of trusting the earlier pathname validation.
                git_accessor = "_git" if module_name == "herdsman_overlay" else "git"
                head = getattr(module, "SHA", getattr(module, "PIN", ""))
                with patch.object(module, "validate_sources", side_effect=swap_after_validation):
                    with patch.object(module, git_accessor, return_value=(head + "\n").encode()):
                        with self.assertRaisesRegex(ValueError, "symlink"):
                            module.plan(root)
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
