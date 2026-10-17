"""Host-only regression for publication of failing native build artifacts.

This is a static workflow guard: actual success is still established only
by the exact-head GitHub-hosted build; it is never flash authorization.
"""
from pathlib import Path
import unittest


WORKFLOW = (Path(__file__).resolve().parents[1] /
            ".github/workflows/test-r4-b0-native.yml")


class ArtifactPublicationTests(unittest.TestCase):
    def test_failed_native_job_cannot_publish_elf_hex_bin(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        success = source.split("      - name: Upload audited nonproduction firmware and safety receipts\n", 1)[1]
        self.assertTrue(success.startswith("        if: success()\n"))
        failed = success.split("      - name: Upload FAILED native diagnostic receipts (NO FIRMWARE)\n", 1)[1]
        self.assertTrue(failed.startswith("        if: failure()\n"))
        self.assertIn("name: r4-b0-FAILED_DIAGNOSTICS_NO_FIRMWARE-", failed)
        self.assertIn("name: r4-b0-NOT_FLASH_QUALIFIED-", success)
        # The failure-only list must be narrowly allowlisted.
        banned = ("/tmp/b0out/\n", ".out\n", ".bin\n", ".hex\n",
                  ".xml\n", "manifest.json")
        for forbidden in banned:
            self.assertNotIn(forbidden, failed)
        self.assertIn("/tmp/b0out/build.log\n", failed)
        self.assertIn("/tmp/b0out/DO_NOT_FLASH_NV_BOUNDARY.json\n", failed)
        self.assertIn("if-no-files-found: warn", failed)

    def test_nv_boundary_must_run_before_success_publication(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        native = source.split("  r4-b0-native-build:", 1)[1]
        audit = native.index('b0_image_audit.py" audit')
        deny = native.index('b0_flash_boundary.py"')
        upload = native.index("      - name: Upload audited nonproduction")
        self.assertLess(audit, deny)
        self.assertLess(deny, upload)


if __name__ == "__main__":
    unittest.main()
