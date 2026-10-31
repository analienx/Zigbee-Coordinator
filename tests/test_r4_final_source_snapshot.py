"""Focused tests for the final real-source diff receipt; no TI SDK needed."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "r4_final_source_snapshot", ROOT / "tools/r4_final_source_snapshot.py")
snapshot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snapshot)


class FinalSourceSnapshotTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "sdk"
        self.root.mkdir()
        self.out = Path(self.temp.name) / "out"
        self.out.mkdir()
        self.tracked = "source/ti/zstack/stack/zdo/zd_sec_mgr.c"
        self.added = "source/ti/common/nv/b1_management.c"
        self.linker = "source/ti/zstack/boards/cc13x2x7_cc26x2x7/cc13x2x7_cc26x2x7_tirtos7_ticlang.cmd"
        tracked_path = self.root / self.tracked
        tracked_path.parent.mkdir(parents=True)
        tracked_path.write_text("int original(void) { return 1; }\n")
        linker_path = self.root / self.linker
        linker_path.parent.mkdir(parents=True)
        linker_path.write_text("MEMORY { FLASH : origin = 0x0, length = 0x1000 }\n")
        self.git("init", "-q")
        self.git("-c", "user.name=Audit", "-c", "user.email=audit@example.test",
                 "add", self.tracked, self.linker)
        self.git("-c", "user.name=Audit", "-c", "user.email=audit@example.test",
                 "commit", "-qm", "pinned TI test")
        self.pin = self.git("rev-parse", "HEAD").strip()
        tracked_path.write_text("int original(void) { return 2; }\n")
        linker_path.write_text("MEMORY { FLASH : origin = 0x0, length = 0x2000 }\n")
        added_path = self.root / self.added
        added_path.parent.mkdir(parents=True)
        added_path.write_text("int new_security_guard(void) { return 1; }\n")

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root), *args], text=True)

    def invoke(self, verify=None):
        return snapshot.run(self.root, self.out, "a" * 40, verify,
                            required={self.tracked, self.added, self.linker}, sdk_pin=self.pin)

    def test_capture_contains_tracked_and_new_source_and_stays_stable(self):
        result = self.invoke()
        patch = (self.out / snapshot.PATCH).read_text()
        self.assertIn("int new_security_guard", patch)
        self.assertIn("return 2", patch)
        self.assertIn("length = 0x2000", patch)
        self.assertEqual(result["source_changed_files_count"], 3)
        self.assertTrue(next(x for x in result["changed_files"]
                             if x["path"] == self.added)["new_file"])
        self.assertEqual(self.invoke(self.out / snapshot.MANIFEST), result)

    def test_post_link_source_mutation_is_denied(self):
        self.invoke()
        (self.root / self.added).write_text("int new_security_guard(void) { return 0; }\n")
        with self.assertRaisesRegex(ValueError, "SOURCE_CHANGED_SINCE_SNAPSHOT"):
            self.invoke(self.out / snapshot.MANIFEST)

    def test_removed_required_source_is_denied(self):
        (self.root / self.added).unlink()
        with self.assertRaisesRegex(ValueError, "EXPECTED_SOURCE_FILES_MISSING"):
            self.invoke()


if __name__ == "__main__":
    unittest.main()
