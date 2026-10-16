"""Native artifact collection is tested without claiming a real TI toolchain."""
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "firmware/slzb-06p7u/r4/b0/tools/b0_collect_native.py"
spec = importlib.util.spec_from_file_location("collector", TOOL)
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


class CollectorTests(unittest.TestCase):
    def test_requires_unique_outputs(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / "znp.out").write_bytes(b"native")
            (p / "znp_linkInfo.xml").write_text("<link_info/>")
            (p / "znp.hex").write_text(":00000001FF")
            (p / "build.log").write_text("not real")
            with self.assertRaisesRegex(RuntimeError, "missing TI tiarmobjcopy"):
                collector.collect(p, p / "output", p / "clang", p / "build.log")
            (p / "other_znp.out").write_bytes(b"duplicate")
            with self.assertRaisesRegex(RuntimeError, "exactly one ZNP"):
                collector.collect(p, p / "output", p / "clang", p / "build.log")

    @unittest.skipIf(os.name == "nt", "hosted Linux tool shim")
    def test_generated_manifest_binds_all_collected_files(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            ws, out, clang = p / "ws", p / "out", p / "clang"
            ws.mkdir()
            (ws / "znp.out").write_bytes(b"ELF TEST FIXTURE")
            (ws / "znp_linkInfo.xml").write_text("<link_info/>")
            (ws / "znp.hex").write_text(":00000001FF")
            (p / "build.log").write_text("stub: NOT NATIVE EVIDENCE")
            (clang / "bin").mkdir(parents=True)
            fake = clang / "bin" / "tiarmobjcopy"
            fake.write_text("#!/bin/sh\ncp \"$3\" \"$4\"\n")
            fake.chmod(0o755)
            result = collector.collect(ws, out, clang, p / "build.log")
            self.assertEqual(result["provenance"]["kind"], "NATIVE_DONOR_UNQUALIFIED")
            self.assertEqual(set(result["files"]), {"elf", "xml", "hex", "bin"})
            self.assertEqual(json.loads((out / "manifest.json").read_text())["schema"],
                             "r4-b0-artifact-manifest-v1")
            for item in result["files"].values():
                self.assertEqual(len(item["sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
