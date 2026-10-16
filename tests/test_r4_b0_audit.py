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
import importlib.util
import io
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

    def test_corrupted_image_fails_hash(self):
        code, message = self._audit("artifacts-bad-hash")
        self.assertEqual(code, 1)
        self.assertIn("sha256 mismatch", message)

    def test_echo_pass_log_rejected(self):
        code, message = self._audit("artifacts-no-link")
        self.assertEqual(code, 1)
        self.assertIn("no actual linker invocation", message)

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
        # Blind-spot regression: HEX+BIN tampered (first payload bytes
        # on both sides) with manifest digests recomputed still fails,
        # naming the cross-binding rather than a hash mismatch.
        code, message = self._audit("artifacts-tampered-hexbin")
        self.assertEqual(code, 1)
        self.assertIn("cross-binding", message)
        self.assertNotIn("sha256 mismatch", message)

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
