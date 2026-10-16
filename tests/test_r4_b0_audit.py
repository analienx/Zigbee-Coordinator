"""R4-B0 image audit tests (stdlib unittest only, offline).

Exercises the real b0_image_audit logic against the committed
unit-test vectors. The vectors are synthetic oracle sanity inputs,
NEVER native proof: a passing fixture audit proves only the
validator logic, never a genuine TI CCS build. If the audit logic
is removed or weakened (hash binding, linker-invocation evidence,
TI XML + ELF cross-check, HEX/BIN cross-binding to the XML memory
map, NV/CCFG separation, CCFG/vector presence, donor stack size,
traversal confinement), these tests fail. No hardware, no
network, no secrets.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
B0 = ROOT / "firmware" / "slzb-06p7u" / "r4" / "b0"
FIX = B0 / "fixtures"
TOOL = B0 / "tools" / "b0_image_audit.py"

spec = importlib.util.spec_from_file_location("b0_image_audit", TOOL)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def run_cli(func, argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = func(argv)
    return code, buf.getvalue()


def _refresh_manifest(artdir):
    """Recompute manifest sha256 digests from the files on disk."""
    manifest_path = artdir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for logical, entry in manifest["files"].items():
        target = artdir / entry["file"]
        entry["sha256"] = hashlib.sha256(
            target.read_bytes()).hexdigest()
    manifest_path.write_bytes(
        json.dumps(manifest, indent=2).encode("utf-8"))


@contextlib.contextmanager
def _patched_xml(old_block, new_block):
    """Yield a temp copy of artifacts-valid with one XML block swapped."""
    with tempfile.TemporaryDirectory() as tmp:
        art = Path(tmp) / "art"
        shutil.copytree(FIX / "artifacts-valid", art)
        xml_path = art / "znp_linkInfo.xml"
        xml = xml_path.read_text(encoding="utf-8")
        assert xml.count(old_block) == 1
        xml_path.write_text(xml.replace(old_block, new_block),
                            encoding="utf-8")
        _refresh_manifest(art)
        yield art


class B0ImageAuditTests(unittest.TestCase):
    def _audit(self, name):
        return audit.audit(B0, FIX / name)

    def test_valid_vector_passes_oracle_sanity(self):
        code, message = self._audit("artifacts-valid")
        self.assertEqual(code, 0)
        self.assertIn("R4-B0 image audit OK", message)

    def test_link_xml_rejects_forged_flash_extent(self):
        xml = (FIX / "artifacts-valid" / "znp_linkInfo.xml").read_text()
        xml = xml.replace("<length>0x000AA000</length>",
                          "<length>0x000A9000</length>", 1)
        evidence, error = audit._parse_link_xml(xml, "znp.out", 0)
        self.assertIsNone(evidence)
        self.assertIn("geometry mismatch", error)

    def test_link_xml_rejects_duplicate_region(self):
        xml = (FIX / "artifacts-valid" / "znp_linkInfo.xml").read_text()
        target = ("<memory_area><name>FLASH_NV</name><origin>0xAA000</origin>"
                  "<length>0x4000</length><used_space>0x0</used_space></memory_area>")
        self.assertIn(target, xml)
        xml = xml.replace(target, target + target, 1)
        evidence, error = audit._parse_link_xml(xml, "znp.out", 0)
        self.assertIsNone(evidence)
        self.assertIn("duplicate/invalid memory_area", error)

    def test_authentic_ti_logical_groups_are_parsed(self):
        # TI linker emits direct logical_group entries, not nested
        # synthetic <section> elements from the legacy test vectors.
        import xml.etree.ElementTree as ET
        root = ET.fromstring((FIX / "artifacts-valid" / "znp_linkInfo.xml").read_text())
        gl = root.find("./logical_group_list")
        old = list(gl)
        groups = list(old[0].findall("section"))
        for group in old:
            gl.remove(group)
        for idx, section in enumerate(groups):
            item = ET.SubElement(gl, "logical_group", id="lg-%d" % idx)
            for field in ("name", "load_address", "size"):
                ET.SubElement(item, field).text = section.findtext(field)
        evidence, error = audit._parse_link_xml(
            ET.tostring(root, encoding="unicode"), "znp.out", 0)
        self.assertIsNone(error)
        self.assertIn(".resetVecs", evidence["sections"])
        self.assertEqual(evidence["sections"][".ccfg"], (0xAE000, 0x88))
        # Genuine TI linker output repeats .resetVecs as an EMPTY
        # unallocated logical group (lg-1b) after its allocated lg-3.
        # This must not conceal the real programmed vector span.
        empty = ET.SubElement(gl, "logical_group", id="lg-1b")
        ET.SubElement(empty, "name").text = ".resetVecs"
        ET.SubElement(empty, "run_address").text = "0x0"
        ET.SubElement(empty, "size").text = "0x0"
        evidence, error = audit._parse_link_xml(
            ET.tostring(root, encoding="unicode"), "znp.out", 0)
        self.assertIsNone(error)
        self.assertEqual(evidence["sections"][".resetVecs"], (0, 0x40))
        # Likewise, this zero-size placeholder must be safe even if
        # it appears before the real allocated section.
        gl.remove(empty)
        gl.insert(0, empty)
        evidence, error = audit._parse_link_xml(
            ET.tostring(root, encoding="unicode"), "znp.out", 0)
        self.assertIsNone(error)
        gl.remove(empty)
        # A second real linker group with the same section name is
        # ambiguous, even when size and address agree.
        gl.append(ET.fromstring(ET.tostring(gl[0])))
        _, error = audit._parse_link_xml(
            ET.tostring(root, encoding="unicode"), "znp.out", 0)
        self.assertIn("duplicate linker output section", error)

    def test_elf_only_zero_alignment_holes_are_bounded_and_never_code(self):
        # Actual CI #38905120532 ELF PT_LOAD carries two 0x00 bytes
        # at 0x2ACD2/3 between .rodata and config_const; the real
        # TI ihex skips them. Unit-scale this exact semantic gap.
        evidence = {
            "areas": {"FLASH": (0, 8), "FLASH_NV": (10, 2),
                      "FLASH_LAST": (8, 2), "SRAM": (0x20000000, 32)},
            "sections": {".resetVecs": (0, 2), ".rodata": (2, 2),
                         "config_const": (6, 2), ".ccfg": (8, 2)},
        }
        payload = {0: 1, 1: 2, 2: 3, 3: 4,
                   6: 5, 7: 6, 8: 7, 9: 8}
        elf = dict(payload)
        elf[4] = 0
        elf[5] = 0
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "real-layout.bin"
            path.write_bytes(bytes([1, 2, 3, 4, 0, 0, 5, 6, 7, 8]))
            self.assertIsNone(audit._check_hex_bin_binding(
                payload, path, evidence, 1, elf))
            corrupt = dict(elf)
            corrupt[4] = 0x23
            message = audit._check_hex_bin_binding(
                payload, path, evidence, 1, corrupt)
            self.assertIn("image deletion", message)
            deleted_code = dict(payload)
            del deleted_code[2]
            message = audit._check_hex_bin_binding(
                deleted_code, path, evidence, 1, elf)
            self.assertIn("image deletion", message)
            outside = dict(payload)
            del outside[8]
            message = audit._check_hex_bin_binding(
                outside, path, evidence, 1, elf)
            self.assertIn("does not cover XML section .ccfg", message)

    def test_ti_flat_binary_padding_matches_sparse_intel_hex(self):
        # A real tiarmobjcopy -O binary retains erased address holes.
        # The synthetic fixture BIN is packed; accept both only when
        # every programmed byte remains cross-bound to ELF and HEX.
        with tempfile.TemporaryDirectory() as tmp:
            art = Path(tmp) / "art"
            shutil.copytree(FIX / "artifacts-valid", art)
            payload, error = audit._parse_intel_hex(art / "znp.hex")
            self.assertIsNone(error)
            base, last = min(payload), max(payload)
            flat = bytearray([0xFF]) * (last - base + 1)
            for addr, value in payload.items():
                flat[addr - base] = value
            (art / "znp.bin").write_bytes(flat)
            _refresh_manifest(art)
            code, message = audit.audit(B0, art)
            self.assertEqual((code, message.split(" (")[0]), (0, "R4-B0 image audit OK"))
            gaps = [i for i in range(len(flat)) if base + i not in payload]
            self.assertTrue(gaps)
            flat[gaps[len(gaps) // 2]] = 0xA5
            (art / "znp.bin").write_bytes(flat)
            _refresh_manifest(art)
            code, message = audit.audit(B0, art)
            self.assertEqual(code, 1)
            self.assertIn("gap fill", message)

    def test_corrupted_image_fails_hash(self):
        code, message = self._audit("artifacts-bad-hash")
        self.assertEqual(code, 1)
        self.assertIn("sha256 mismatch", message)

    def test_echo_pass_log_rejected(self):
        code, message = self._audit("artifacts-no-link")
        self.assertEqual(code, 1)
        self.assertIn("no actual linker invocation", message)

    def test_fabricated_single_line_log_rejected(self):
        # Log-provenance tripwire: one fabricated line carrying every
        # marker substring (with correct manifest digests, since the
        # log itself is unhashed) must fail at the log tripwire --
        # never reach content-binding, never pass.
        code, message = self._audit("artifacts-fake-log")
        self.assertEqual(code, 1)
        self.assertIn("no actual linker invocation", message)
        self.assertNotIn("content-binding", message)
        self.assertNotIn("R4-B0 image audit OK", message)

    def test_shuffled_pipeline_order_rejected(self):
        # Markers in implausible order (projectBuild before syscfg)
        # fail the pipeline-order tripwire even at full log length.
        with tempfile.TemporaryDirectory() as tmp:
            art = Path(tmp) / "art"
            shutil.copytree(FIX / "artifacts-valid", art)
            rows = (art / "build.log").read_text(
                encoding="utf-8").splitlines()
            syscfg_at = next(i for i, row in enumerate(rows)
                             if row.startswith("$ syscfg"))
            build_at = next(i for i, row in enumerate(rows)
                            if "projectBuild -ccs.projects" in row)
            block = rows[syscfg_at:build_at]
            rest = rows[:syscfg_at] + rows[build_at:]
            (art / "build.log").write_text(
                "\n".join(rest + block) + "\n", encoding="utf-8")
            code, message = audit.audit(B0, art)
            self.assertEqual(code, 1)
            self.assertIn("no actual linker invocation", message)
            self.assertIn("pipeline order", message)

    def test_fixture_text_vectors_pinned_to_lf(self):
        # CRLF-drift guard: fixture text vectors are hashed with LF
        # bytes, so the fixtures .gitattributes must pin eol=lf and
        # no text vector may carry CR bytes in the working tree.
        attrs = (FIX / ".gitattributes").read_text(encoding="utf-8")
        for ext in (".hex", ".json", ".log", ".map", ".txt", ".xml"):
            pinned = [line for line in attrs.splitlines()
                      if ext in line and "eol=lf" in line]
            self.assertTrue(pinned,
                            "missing eol=lf pin for *%s" % ext)
        for path in sorted(FIX.rglob("*")):
            if path.is_file() and path.suffix in (
                    ".hex", ".json", ".log", ".map", ".txt", ".xml"):
                self.assertNotIn(b"\r", path.read_bytes(),
                                 "CRLF drift in %s" % path.name)

    def test_fake_elf_rejected(self):
        code, message = self._audit("artifacts-fake-elf")
        self.assertEqual(code, 1)
        self.assertIn("ELF", message)

    def test_path_traversal_rejected(self):
        code, message = self._audit("artifacts-path-traversal")
        self.assertEqual(code, 1)
        self.assertIn("traversal", message)

    def test_synthetic_map_format_rejected(self):
        code, message = self._audit("artifacts-synthetic-map")
        self.assertEqual(code, 1)
        self.assertIn("synthetic", message)

    def test_nv_ccfg_overlap_rejected(self):
        code, message = self._audit("artifacts-overlap")
        self.assertEqual(code, 1)
        self.assertIn("NV/CCFG overlap", message)

    def test_missing_ccfg_rejected(self):
        code, message = self._audit("artifacts-no-ccfg")
        self.assertEqual(code, 1)
        self.assertIn("CCFG", message)

    def test_missing_vectors_rejected(self):
        code, message = self._audit("artifacts-no-vector")
        self.assertEqual(code, 1)
        self.assertIn("vector", message)

    def test_unproven_4096_stack_rejected(self):
        code, message = self._audit("artifacts-bad-stack")
        self.assertEqual(code, 1)
        self.assertIn("C/IRQ stack", message)

    def test_tampered_hexbin_with_updated_manifest_fails_cross_binding(self):
        # Content-tamper regression: HEX+BIN carry a mutually
        # consistent single-byte flip (addr 0x30) versus the ELF,
        # with manifest digests recomputed, so the weak BIN==HEX
        # path cannot catch it; rejection must name the
        # content-binding (ELF PT_LOAD byte match), never a hash.
        code, message = self._audit("artifacts-tampered-hexbin")
        self.assertEqual(code, 1)
        self.assertIn("content-binding", message)
        self.assertIn("cross-binding", message)
        self.assertNotIn("sha256 mismatch", message)

    def test_extra_bytes_fail_content_binding(self):
        # Injected-bytes regression: 16 extra bytes at SRAM
        # 0x20000000 (inside an XML-reported area, BIN consistent
        # with HEX, digests recomputed) have no covering ELF
        # PT_LOAD segment and must fail the content-binding.
        code, message = self._audit("artifacts-extra-bytes")
        self.assertEqual(code, 1)
        self.assertIn("content-binding", message)
        self.assertIn("no covering ELF PT_LOAD segment", message)
        self.assertNotIn("sha256 mismatch", message)

    def test_hexbin_disagreement_still_fails(self):
        # The BIN-vs-HEX disagreement control is kept: a BIN that
        # differs from a genuine HEX payload (digests current)
        # fails at the HEX/BIN cross-binding.
        code, message = self._audit("artifacts-hexbin-mismatch")
        self.assertEqual(code, 1)
        self.assertIn("cross-binding", message)
        self.assertIn("BIN content differs", message)
        self.assertNotIn("sha256 mismatch", message)

    def test_deletion_of_load_bytes_fails_content_binding(self):
        # Silent-deletion regression: the ELF gains a third PT_LOAD
        # segment (16 bytes at 0x40, inside FLASH but outside the
        # XML-checked .resetVecs/.ccfg extents) while HEX/BIN stay
        # unchanged with current digests, so ELF PT_LOAD bytes are
        # uncovered by the HEX payload and must fail closed.
        with tempfile.TemporaryDirectory() as tmp:
            art = Path(tmp) / "art"
            shutil.copytree(FIX / "artifacts-valid", art)
            old = (art / "znp.out").read_bytes()
            seg0 = old[116:116 + 0x40]
            seg1 = old[180:180 + 0x88]
            extra = bytes(range(0x50, 0x60))
            head = struct.pack(
                "<16sHHIIIIIHHHHHH",
                b"\x7fELF\x01\x01\x01" + b"\x00" * 9,
                2, 40, 1, 0, 52, 0, 0, 52, 32, 3, 0, 0, 0)
            base = 52 + 96
            phdrs = b"".join((
                struct.pack("<8I", 1, base, 0x0, 0x0, 0x40, 0x40, 5, 4),
                struct.pack("<8I", 1, base + 0x40, 0xAE000, 0xAE000,
                            0x88, 0x88, 4, 4),
                struct.pack("<8I", 1, base + 0x40 + 0x88, 0x40, 0x40,
                            0x10, 0x10, 5, 4),
            ))
            (art / "znp.out").write_bytes(head + phdrs + seg0 + seg1
                                          + extra)
            _refresh_manifest(art)
            code, message = audit.audit(B0, art)
            self.assertEqual(code, 1)
            self.assertIn("content-binding", message)
            self.assertIn("0x00000040", message)
            self.assertIn("missing", message)

    def test_bad_flash_geometry_rejected(self):
        code, message = self._audit("artifacts-bad-geometry")
        self.assertEqual(code, 1)
        self.assertIn("geometry mismatch", message)
        self.assertIn("FLASH", message)

    def test_flash_last_length_deviation_rejected(self):
        with _patched_xml(
                "<name>FLASH_LAST</name><origin>0xAE000</origin>"
                "<length>0x2000</length>",
                "<name>FLASH_LAST</name><origin>0xAE000</origin>"
                "<length>0x1000</length>") as art:
            code, message = audit.audit(B0, art)
            self.assertEqual(code, 1)
            self.assertIn("geometry mismatch", message)
            self.assertIn("FLASH_LAST", message)

    def test_sram_geometry_deviation_rejected(self):
        with _patched_xml(
                "<name>SRAM</name><origin>0x20000000</origin>"
                "<length>0x24000</length>",
                "<name>SRAM</name><origin>0x20001000</origin>"
                "<length>0x24000</length>") as art:
            code, message = audit.audit(B0, art)
            self.assertEqual(code, 1)
            self.assertIn("geometry mismatch", message)
            self.assertIn("SRAM", message)

    def test_odd_entry_normalized_to_thumb(self):
        # Thumb-bit rationale: Cortex-M Thumb-2 entry points carry
        # bit 0 set while Intel HEX holds the aligned address, so
        # the audit clears bit 0 before the HEX coverage check.
        # An ELF/XML pair with entry 0x1 over the same image must
        # therefore still pass; an entry outside the image must
        # still fail.
        with tempfile.TemporaryDirectory() as tmp:
            art = Path(tmp) / "art"
            shutil.copytree(FIX / "artifacts-valid", art)
            elf = bytearray((art / "znp.out").read_bytes())
            struct.pack_into("<I", elf, 24, 0x1)
            (art / "znp.out").write_bytes(bytes(elf))
            xml = (art / "znp_linkInfo.xml").read_text(encoding="utf-8")
            self.assertEqual(xml.count("<address>0x00000000</address>"), 1)
            (art / "znp_linkInfo.xml").write_text(
                xml.replace("<address>0x00000000</address>",
                            "<address>0x00000001</address>"),
                encoding="utf-8")
            _refresh_manifest(art)
            code, message = audit.audit(B0, art)
            self.assertEqual(code, 0)
            self.assertIn("R4-B0 image audit OK", message)

    def test_entry_outside_image_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            art = Path(tmp) / "art"
            shutil.copytree(FIX / "artifacts-valid", art)
            elf = bytearray((art / "znp.out").read_bytes())
            struct.pack_into("<I", elf, 24, 0x1000)
            (art / "znp.out").write_bytes(bytes(elf))
            xml = (art / "znp_linkInfo.xml").read_text(encoding="utf-8")
            (art / "znp_linkInfo.xml").write_text(
                xml.replace("<address>0x00000000</address>",
                            "<address>0x00001000</address>"),
                encoding="utf-8")
            _refresh_manifest(art)
            code, message = audit.audit(B0, art)
            self.assertEqual(code, 1)
            self.assertIn("not covered by HEX", message)

    def test_absent_artifacts_block_never_pass(self):
        code, message = audit.audit(B0, FIX / "artifacts-does-not-exist")
        self.assertEqual(code, 2)
        self.assertIn("B0-AUDIT-BLOCKED", message)

    def test_cli_valid_vector(self):
        code, out = run_cli(audit.main, ["audit", str(B0), "--artifacts",
                                         str(FIX / "artifacts-valid")])
        self.assertEqual(code, 0)
        self.assertIn("R4-B0 image audit OK", out)

    def test_cli_overlap_fails_without_traceback(self):
        code, out = run_cli(audit.main, ["audit", str(B0), "--artifacts",
                                         str(FIX / "artifacts-overlap")])
        self.assertEqual(code, 1)
        self.assertIn("NV/CCFG overlap", out)
        self.assertNotIn("Traceback", out)

    def test_cli_traversal_fails_without_traceback(self):
        code, out = run_cli(audit.main, ["audit", str(B0), "--artifacts",
                                         str(FIX / "artifacts-path-traversal")])
        self.assertEqual(code, 1)
        self.assertIn("traversal", out)
        self.assertNotIn("Traceback", out)

    def test_cli_tampered_hexbin_fails_without_traceback(self):
        code, out = run_cli(audit.main, ["audit", str(B0), "--artifacts",
                                         str(FIX / "artifacts-tampered-hexbin")])
        self.assertEqual(code, 1)
        self.assertIn("cross-binding", out)
        self.assertNotIn("Traceback", out)

    def test_cli_blocked_without_traceback(self):
        code, out = run_cli(audit.main, ["audit", str(B0), "--artifacts",
                                         str(FIX / "artifacts-does-not-exist")])
        self.assertEqual(code, 2)
        self.assertIn("B0-AUDIT-BLOCKED", out)
        self.assertNotIn("Traceback", out)


if __name__ == "__main__":
    unittest.main()
