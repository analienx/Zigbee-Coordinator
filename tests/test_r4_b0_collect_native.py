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
    def test_preserves_native_ti_project_names(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws, out, clang = root / "ws", root / "out", root / "clang"
            ws.mkdir()
            out.mkdir()
            (ws / "znp_LP_CC1352P7_4_tirtos7_ticlang.out").write_bytes(b"ELF FIXTURE")
            (ws / "znp_LP_CC1352P7_4_tirtos7_ticlang_linkInfo.xml").write_text("<link_info/>")
            (ws / "znp_LP_CC1352P7_4_tirtos7_ticlang.hex").write_text(":00000001FF")
            (out / "build.log").write_text("mock, NOT native evidence")
            (clang / "bin").mkdir(parents=True)
            fake = clang / "bin" / "tiarmobjcopy"
            fake.write_text('#!/bin/sh\ncp "$3" "$4"\n')
            fake.chmod(0o755)
            manifest = collector.collect(ws, out, clang, out / "build.log")
            elf_name = manifest["files"]["elf"]["file"]
            xml_name = manifest["files"]["xml"]["file"]
            self.assertEqual(elf_name, "znp_LP_CC1352P7_4_tirtos7_ticlang.out")
            self.assertTrue(xml_name.endswith("_linkInfo.xml"))
            self.assertTrue((out / elf_name).is_file())

    @unittest.skipIf(os.name == "nt", "hosted Linux tool shim")
    def test_build_log_already_at_destination(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws, out, compiler = root / "workspace", root / "out", root / "compiler"
            ws.mkdir()
            out.mkdir()
            (ws / "znp.out").write_bytes(b"fixture")
            (ws / "znp_linkInfo.xml").write_text("<link_info/>")
            (ws / "znp.hex").write_text(":00000001FF")
            (out / "build.log").write_text("original log stays in place")
            (compiler / "bin").mkdir(parents=True)
            fake = compiler / "bin" / "tiarmobjcopy"
            fake.write_text('#!/bin/sh\ncp "$3" "$4"\n')
            fake.chmod(0o755)
            collector.collect(ws, out, compiler, out / "build.log")
            self.assertEqual((out / "build.log").read_text(), "original log stays in place")

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
