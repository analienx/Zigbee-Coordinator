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
            "board": "SLZB-06P7U-r1.73-CC2652P7",
            "boot_contract": "APP0_REQUIRES_SEPARATE_AC000_HANDOFF",
            "private_current_capture_and_security_preflight_required": True,
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
        plan = {
            "source_sha": self.source,
            "candidate_sha256": op.sha(op.canonical(self.manifest)),
            "program_order": [8192, 0, op.BOOT],
            "sector_sha256": {"8192": "1" * 64, "0": "3" * 64,
                              str(op.BOOT): "2" * 64},
        }
        plan["plan_sha256"] = op.sha(op.canonical(plan))
        self.json(self.private / "frozen-plan.json", plan)
        self.json(self.private / "admission-input.json", {
            "new_source_sha": self.source,
            "current_capture_sha256": cap,
            "plan_sha256": plan["plan_sha256"],
            "nv_touched": False,
        })

    def flash(self):
        self.prepare()
        plan = json.loads((self.private / "frozen-plan.json").read_bytes())
        capture = (self.private / "readback-1/current-pass1.bin").read_bytes()
        observed = {str(addr): op.sha(capture[addr:addr + 8192])
                    for addr in range(0, op.FLASH_BYTES, 8192)}
        admission = {"plan_sha256": plan["plan_sha256"],
                     "observed_sector_sha256": observed}
        admission["admission_sha256"] = op.sha(op.canonical({
            **admission, "observed_sector_sha256": {int(k): v for k, v in observed.items()}}))
        self.json(self.private / "admission.json", admission)
        self.json(self.private / "flash-result.json", {
            "status": "APP_AND_AC000_VERIFIED_STILL_IN_BSL",
            "nv_touched": False, "ccfg_touched": False,
            "reset_issued": False, "automatic_rollback": False,
            "written_sectors": [8192, 0, op.BOOT],
        })
        entries = []
        for addr in plan["program_order"]:
            entries.append({"event": "BEFORE_ERASE", "address": addr,
                "plan_sha256": plan["plan_sha256"],
                "before_sha256": observed[str(addr)],
                "after_sha256": plan["sector_sha256"][str(addr)]})
            if addr == op.BOOT:
                entries.append({"event": "BEFORE_BOOT_VECTOR_COMMIT",
                                "address": addr, "plan_sha256": plan["plan_sha256"]})
            entries.append({"event": "SECTOR_VERIFIED", "address": addr,
                            "sha256": plan["sector_sha256"][str(addr)]})
        (self.private / "flash-journal.jsonl").write_text(
            "".join(json.dumps(x) + "\n" for x in entries))

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
        with self.assertRaisesRegex(op.Stop, "FROZEN_PLAN_HASH_MISMATCH"):
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

    def test_journal_missing_hash_fails_closed(self):
        self.flash()
        (self.private / "flash-journal.jsonl").write_text("{}\n")
        self.assertIn("FLASH_JOURNAL_EVENTS_NOT_COMPLETE", op.stage_state(self.private, self.manifest)["flash"])

    def test_owner_approval_wrong_plan_never_starts_flash(self):
        self.prepare()
        self.json(self.private / "owner-request.json", {
            "reviewed_firmware_source": self.source,
            "plan_sha256": "0" * 64,
            "scope": "EXACT_R4_TO_R4_APP_AND_MATCHING_AC000_PRESERVE_NV_AND_CCFG",
        })
        with self.assertRaisesRegex(op.Stop, "FROZEN_OWNER_SOURCE_PLAN_OR_SCOPE_MISMATCH"):
            op.run_through(self.private, self.candidate, self.source, "flash",
                           allow_bsl=True, allow_flash=True, allow_boot=False)

    def test_second_operator_is_rejected_by_persistent_lock(self):
        self.flash()
        (self.private / ".r4-operator-one-shot-lock").write_text("previous attempt")
        args = ["--candidate", str(self.candidate), "--private", str(self.private),
                "--source", self.source, "run", "--through", "flash"]
        self.assertEqual(op.main(args), 2)

    def test_approved_stages_do_not_rerun(self):
        self.flash()
        # The flash is completed, and no startup is requested.
        op.run_through(self.private, self.candidate, self.source, "flash",
                       allow_bsl=False, allow_flash=False, allow_boot=False)


if __name__ == "__main__":
    unittest.main()
