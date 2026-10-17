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

    def test_native_publication_depends_on_green_overlay_and_upstream_inventory(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        # Native success() by itself refers only to this job, not
        # failing parallel jobs in the same workflow. Both must be
        # explicit job dependencies so a red overlay cannot coexist
        # with a downloadable "success" candidate image.
        native = workflow.split("  r4-b0-native-build:\n", 1)[1]
        job_header = native.split("    steps:\n", 1)[0]
        self.assertIn("needs: [r4-b0-overlay, r4-b0-upstream-inventory]", job_header)
        self.assertNotIn("continue-on-error: true", job_header)

    def test_artifact_name_identifies_actual_checked_out_pr_head(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        # GitHub's github.sha on pull_request is a synthetic merge-ref
        # commit; this build checks out pull_request.head.sha instead.
        # Evidence artifact labels must identify that actual source.
        expected = "${{ github.event.pull_request.head.sha || github.sha }}"
        self.assertIn("ref: ${{ github.event.pull_request.head.sha }}", workflow)
        self.assertIn("name: r4-b0-NOT_FLASH_QUALIFIED-" + expected, workflow)
        self.assertIn("name: r4-b0-FAILED_DIAGNOSTICS_NO_FIRMWARE-" + expected, workflow)

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
