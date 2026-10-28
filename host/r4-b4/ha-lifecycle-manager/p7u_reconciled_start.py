"""Explicit single continuation after a terminal ping-failed handover.

Never resets hardware or clears/replays an old intent. A private operator plan
binds the prior HOLD, stopped failed container, preserved logs and the existing
recovery executor's one-shot ESP acknowledgement. All gates are refreshed
under the same global lock before one additional managed owner start.
"""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import time

import p7u_lifecycle_main as main
from p7u_ha_readonly_inspector import inspect_docker
from p7u_lifecycle_core import Journal, guard
from p7u_lifecycle_machine import Manager, require_absent, zero_tty_three_times

FIELDS = {
    "previous_plan_path", "previous_plan_sha256", "previous_journal_sha256",
    "failed_container_id", "failed_log_path", "failed_log_sha256",
    "reset_attempt_path", "reset_attempt_sha256", "reset_result_path", "reset_result_sha256",
}


def private_bytes(path, digest, limit=4 * 1024 * 1024):
    path = Path(path)
    main.private_file(path)
    guard(main.SHA.fullmatch(digest or "") is not None, "RECONCILIATION_SHA_REQUIRED")
    raw = main.checked_file(path, limit)
    guard(hashlib.sha256(raw).hexdigest() == digest, "RECONCILIATION_FILE_CHANGED")
    return raw


def timestamp(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


def validate_reconciliation(plan, port):
    r = plan["reconciliation"]
    guard(type(r) is dict and set(r) == FIELDS, "RECONCILIATION_SCHEMA")
    old_path = Path(r["previous_plan_path"])
    guard(old_path.parent != port.artifact_directory, "RECONCILIATION_SAME_DIRECTORY")
    old = json.loads(private_bytes(old_path, r["previous_plan_sha256"], 65536))
    guard(type(old) is dict and set(old) == main.PLAN_FIELDS and
          old.get("schema") == "p7u-one-shot-plan-v1" and
          plan["operation_id"] == old["operation_id"] and
          plan["original_slot"] == old["original_slot"] == "official" and
          plan["target_slot"] == old["target_slot"] == "diagnostic" and
          plan["serial_by_id"] == old["serial_by_id"] and
          plan["original_owner"] == old["original_owner"], "RECONCILIATION_OPERATION_CHANGED")
    pointer_path = main.PRIVATE_ROOT / "active-operation.json"
    main.private_file(pointer_path)
    pointer = json.loads(main.checked_file(pointer_path, 65536))
    guard(pointer == {"schema": "p7u-active-operation-v1", "operation_id": old["operation_id"],
                      "source_sha": old["source_sha"], "plan_sha256": r["previous_plan_sha256"]},
          "RECONCILIATION_ACTIVE_POINTER_CHANGED")
    journal_path = old_path.parent / "journal" / "events.jsonl"
    raw = private_bytes(journal_path, r["previous_journal_sha256"])
    with Journal(journal_path.parent) as prior:
        guard(prior.phase == "HOLD", "RECONCILIATION_PRIOR_NOT_TERMINAL_HOLD")
        head = prior.head
    events = [json.loads(line) for line in raw.splitlines()]
    phases = [e["phase"] for e in events if e["phase"] not in ("STOP_ACK_UNKNOWN", "START_ACK_UNKNOWN")]
    guard(phases == ["PREFLIGHT", "STOP_INTENT", "OWNER_ABSENT", "DB_APPROVED", "START_INTENT", "HOLD"]
          and events[-1]["hash"] == head and
          events[-1]["evidence"].get("reason") == "post-start evidence incomplete",
          "RECONCILIATION_PRIOR_PHASES")
    guard(not (old_path.parent / "reconciled-start.intent.json").exists() and
          not (old_path.parent / "reconciled-start.intent.json").is_symlink(),
          "RECONCILIATION_ALREADY_ATTEMPTED")
    prior_approval = next(e["evidence"] for e in events if e["phase"] == "DB_APPROVED")
    cold = prior_approval["cold_backup"]
    archive = old_path.parent / cold["archive"]
    guard(archive.parent == old_path.parent and main.sha_file(archive) == cold["sha256"],
          "RECONCILIATION_PRIOR_COLD_BACKUP_CHANGED")
    failed = inspect_docker("diagnostic")
    guard(type(failed) is dict and failed.get("Id") == r["failed_container_id"] and
          failed.get("Image") == "sha256:" + old["diagnostic_image_sha256"] and
          failed.get("State", {}).get("Status") == "exited" and
          failed["State"].get("Running") is False and failed["State"].get("ExitCode") != 0,
          "RECONCILIATION_FAILED_CONTAINER_CHANGED")
    log = private_bytes(r["failed_log_path"], r["failed_log_sha256"])
    guard(b"P7U HOLD_EXISTING_NV: ping unavailable; no bootloader magic or line toggles" in log,
          "RECONCILIATION_PING_FAILURE_NOT_PRESERVED")
    attempt = json.loads(private_bytes(r["reset_attempt_path"], r["reset_attempt_sha256"], 65536))
    result = json.loads(private_bytes(r["reset_result_path"], r["reset_result_sha256"], 65536))
    incident = old["operation_id"].replace("-", "")
    key = incident + ":ESP_RESET_PENDING:RESTART_ESP"
    for doc in (attempt, result):
        guard(doc.get("incident_id") == incident and doc.get("action_key") == key and
              doc.get("phase") == "ESP_RESET_PENDING" and doc.get("action") == "RESTART_ESP",
              "RECONCILIATION_RESET_IDENTITY")
    guard(attempt.get("schema") == "p7u-shared-recovery-attempt-v2" and
          attempt.get("sent_after_receipt") is True and
          result.get("schema") == "p7u-shared-recovery-result-v2" and
          result.get("status") == "COMMAND_ACCEPTED_NOT_YET_VERIFIED",
          "RECONCILIATION_RESET_NOT_ACKNOWLEDGED")
    sent = timestamp(attempt["recorded_utc"])
    done = timestamp(result["recorded_utc"])
    guard(timestamp(failed["State"]["FinishedAt"]) <= sent <= done <= time.time() and
          time.time() - done <= 600, "RECONCILIATION_RESET_STALE_OR_BEFORE_FAILURE")
    port.validate_profiles(original_slot="official", target_slot="diagnostic")
    for slot in ("official", "diagnostic", "fallback"):
        require_absent(port.inspect(slot), slot)
    zero_tty_three_times(port)
    main.validate_service_bundle(port, plan)
    baseline = port.preflight_database()
    guard(baseline.get("existing_approval", {}).get("generation") == prior_approval["generation"] and
          baseline["inventory_sha256"] == prior_approval["inventory_sha256"],
          "RECONCILIATION_DATABASE_GENERATION_CHANGED")
    # Detect a change while this multi-part read-only admission ran.
    private_bytes(journal_path, r["previous_journal_sha256"])
    return {"prior_hold_verified": True, "previous_journal_head": head,
            "previous_journal_sha256": r["previous_journal_sha256"],
            "reset_result_sha256": r["reset_result_sha256"],
            "failed_container_id": r["failed_container_id"]}


def claim_continuation(plan, digest, evidence):
    old = Path(plan["reconciliation"]["previous_plan_path"]).parent
    path = old / "reconciled-start.intent.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump({"source_sha": plan["source_sha"], "operation_id": plan["operation_id"],
                   "plan_sha256": digest, "one_request_only": True, **evidence}, stream, sort_keys=True)
        stream.flush(); os.fsync(stream.fileno())
    main.fsync_directory(old)


def run_reconciled(options, plan, port):
    # The old active pointer is retained. Both preflight and execution exclude
    # other managers while inspecting the old journal/current host state.
    with main.global_operation_lock():
        evidence = validate_reconciliation(plan, port)
        result = {"schema": "p7u-one-shot-result-v1", "source_sha": plan["source_sha"],
                  "operation_id": plan["operation_id"], "plan_sha256": options["plan_sha256"],
                  "original": "quiescent_after_reconciled_hold", "target": "diagnostic",
                  "serial_opened": False, "physical_reset": False}
        if not options["execute"]:
            return {**result, "status": "PREFLIGHT_PASS", "service_mutated": False}
        directory = port.artifact_directory / "journal"
        directory.mkdir(mode=0o700, exist_ok=True)
        with Journal(directory) as journal:
            guard(journal.phase is None, "RECONCILIATION_JOURNAL_NOT_FRESH")
            claim_continuation(plan, options["plan_sha256"], evidence)
            # Clean only the proven stopped failed generation using Supervisor.
            failed = inspect_docker("diagnostic")
            guard(failed is not None and failed["Id"] == evidence["failed_container_id"] and
                  failed["State"]["Running"] is False, "RECONCILIATION_CLEANUP_IDENTITY_CHANGED")
            port.client.call(method="POST", slot="diagnostic", action="stop", timeout_seconds=30)
            guard(inspect_docker("diagnostic") is None, "RECONCILIATION_CLEANUP_NOT_CONFIRMED")
            cap = {"diagnostic_profile_sha": plan["diagnostic_image_sha256"],
                   "fallback_profile_sha": plan["fallback_image_sha256"],
                   "identity_inspection": True, "tty_fd_inspection": True,
                   "source_database_gate": True, "save_before_adapter_close": True}
            status = Manager(journal, port, cap).start_quiescent_once(
                target_slot="diagnostic", reconciliation=evidence)
            return {**result, "status": status, "journal_head": journal.head,
                    "cold_backup": port.cold_receipt, "service_mutated": True}
