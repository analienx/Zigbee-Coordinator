"""Regression tests for the fail-closed R4 multi-stage operator CLI."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "firmware/slzb-06p7u/r4/release"))
import p7u_r4_operator as op


class OperatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.candidate = base / "artifacts"
        self.candidate.mkdir()
        self.private = base / "private"
        self.private.mkdir()
        self.source = "a" * 40
        raw = b"real-build-bytes"
        (self.candidate / "package.bin").write_bytes(raw)
        self.manifest = {
            "source_sha": self.source,
            "github_run_id": "1234",
            "flash_authorized": False,
            "hardware_boot_qualified": False,
            "files": {"package.bin": op.sha(raw)},
            "app_hex_sha256": "1" * 64,
            "handoff_sha256": "2" * 64,
            "replicas": [
                {"app_hex_sha256": "1" * 64, "handoff_sha256": "2" * 64},
                {"app_hex_sha256": "1" * 64, "handoff_sha256": "2" * 64},
            ],
        }
        self.json(self.candidate / "candidate.json", self.manifest)

    @staticmethod
    def json(path, data):
        path.write_text(json.dumps(data, sort_keys=True))

    def capture(self):
        root = self.private / "readback-1"
        root.mkdir()
        blob = b"\x7a" * op.FLASH_BYTES
        (root / "current-pass1.bin").write_bytes(blob)
        (root / "current-pass2.bin").write_bytes(blob)
        self.json(root / "capture-receipt.json", {
            "flash_bytes": op.FLASH_BYTES,
            "status": "DUPLICATE_READBACK_MATCH",
            "schema": "r4-p7u-capture-pair-v1",
            "capture_origin": "SUPPLIED_ROM_ADAPTER_REQUIRES_OPERATOR_PROVENANCE",
            "nv_compatibility_verified": False,
            "reset_issued": False,
            "flash_performed": False,
            "return_to_stock_verified": False,
            "pass1_sha256": op.sha(blob),
            "pass2_sha256": op.sha(blob),
        })
        return op.sha(blob)

    def prepare(self):
        cap = self.capture()
        self.json(self.private / "security-receipt-validated.json", {
            "status": "PASS_RETAINED_SECURITY_OFFLINE_ONLY",
            "flash_authorized": False,
            "capture_sha256": cap,
        })
        self.json(self.private / "frozen-plan.json", {
            "program_order": [8192, 0, op.BOOT],
            "plan_sha256": "3" * 64,
        })
        self.json(self.private / "admission-input.json", {
            "new_source_sha": self.source,
            "current_capture_sha256": cap,
            "plan_sha256": "3" * 64,
            "nv_touched": False,
        })

    def flash(self):
        self.prepare()
        self.json(self.private / "flash-result.json", {
            "status": "APP_AND_AC000_VERIFIED_STILL_IN_BSL",
            "nv_touched": False, "ccfg_touched": False,
            "reset_issued": False, "automatic_rollback": False,
            "written_sectors": [8192, 0, op.BOOT],
        })

    def test_package_tamper_is_blocked(self):
        self.assertEqual(op.candidate_verify(self.candidate, self.source)["github_run_id"], "1234")
        (self.candidate / "package.bin").write_bytes(b"tampered")
        with self.assertRaisesRegex(op.Stop, "ARTIFACT_HASH_CHANGED"):
            op.candidate_verify(self.candidate, self.source)

    def test_package_path_escape_blocked(self):
        self.manifest["files"] = {"../outside.bin": "1" * 64}
        self.json(self.candidate / "candidate.json", self.manifest)
        with self.assertRaisesRegex(op.Stop, "MISSING_OR_UNSAFE_ARTIFACT"):
            op.candidate_verify(self.candidate, self.source)

    def test_incomplete_capture_fails_closed(self):
        self.capture()
        (self.private / "readback-1/current-pass2.bin").write_bytes(b"x")
        with self.assertRaisesRegex(op.Stop, "CAPTURE_PASSES_DIFFER"):
            op.capture_verify(self.private)

    def test_prepare_and_flash_status(self):
        self.flash()
        self.assertEqual(op.stage_state(self.private, self.manifest)["capture"], "PASS")
        self.assertEqual(op.stage_state(self.private, self.manifest)["prepare"], "PASS")
        self.assertEqual(op.stage_state(self.private, self.manifest)["flash"], "PASS")

    def test_protected_sector_in_plan_is_denied(self):
        self.prepare()
        self.json(self.private / "frozen-plan.json", {
            "program_order": [0xA4000, 0, op.BOOT],
            "plan_sha256": "3" * 64,
        })
        with self.assertRaisesRegex(op.Stop, "UNSAFE_OR_CHANGED_SECTOR"):
            op.prepare_verify(self.private, self.manifest)

    def test_no_duplicate_flash_after_partial_journal(self):
        self.prepare()
        (self.private / "flash-journal.jsonl").write_text('{"event":"BEFORE_ERASE"}\n')
        with self.assertRaisesRegex(op.Stop, "STOP_INCOMPLETE_ONE_SHOT"):
            op.run_through(self.private, self.candidate, self.source, "flash",
                           allow_bsl=True, allow_flash=True, allow_boot=True)

    def test_failed_startup_is_not_retried(self):
        self.flash()
        (self.private / "app-boot-request.json").write_text("{}")
        self.json(self.private / "startup-result.json", {
            "source": self.source, "status": "FAILED_STOP_NO_RETRY",
            "attempts": 1,
        })
        result = op.stage_state(self.private, self.manifest)
        self.assertTrue(result["startup"].startswith("INCOMPLETE_NO_AUTOMATIC_RETRY"))
        with self.assertRaisesRegex(op.Stop, "STOP_INCOMPLETE_ONE_SHOT"):
            op.run_through(self.private, self.candidate, self.source, "startup",
                           allow_bsl=True, allow_flash=True, allow_boot=True)

    def test_approved_stages_do_not_rerun(self):
        self.flash()
        # The flash is completed, and no startup is requested.
        op.run_through(self.private, self.candidate, self.source, "flash",
                       allow_bsl=False, allow_flash=False, allow_boot=False)


if __name__ == "__main__":
    unittest.main()
