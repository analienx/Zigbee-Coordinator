"""Exact-source, one-shot HA ownership handover entry point.

Root supplies a private hash-pinned plan after inspecting issue #144 and the
exact hosted artifacts. Default execution is inspection only. The only live
service mutations are the existing narrow Supervisor port's single stop and
single start. There is no installer, generic command API, forced termination,
automatic rollback, serial open, firmware write, or NV replay in this image.
"""
from __future__ import annotations

import hashlib
import fcntl
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import uuid

from p7u_host_integrity import checked_file, AdmissionHold
from p7u_lifecycle_core import Journal, LifecycleHold, Owner, guard, SHA
from p7u_lifecycle_machine import Manager, require_running
from p7u_ha_supervisor_port import HaSupervisorPort
from p7u_serving_mqtt import Config, FreshMqttEvidence
from p7u_db_quiesced import renewal_baseline, seal_quiesced

DATABASE = Path("/config/zigbee2mqtt/database.db")
PRIVATE_ROOT = Path("/share/p7u-lifecycle/private")
MAX_BACKUP = 2 * 1024**3
MAX_FILES = 50000
ALLOWED_LINKS = {
    "external_converters/node_modules": "/app/node_modules",
    "external_extensions/node_modules": "/app/node_modules",
    "external_converters.pre-divisor-fix-20260924/node_modules": "/app/node_modules",
}
SOURCE = Path(__file__).with_name("SOURCE_SHA")
PLAN_FIELDS = {
    "schema", "source_sha", "operation_id", "serial_by_id", "original_slot",
    "target_slot", "original_owner", "diagnostic_image_sha256",
    "fallback_image_sha256", "preserved_backup_path", "preserved_backup_sha256",
    "mqtt", "expected_topics", "ha_entity_id",
    "image_references",
}


def sha_file(path: Path, *, limit: int = MAX_BACKUP) -> str:
    guard(not path.is_symlink(), "BACKUP_SYMLINK")
    before = path.stat()
    guard(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= limit,
          "BACKUP_TYPE_OR_SIZE")
    h = hashlib.sha256()
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        guard((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino),
              "BACKUP_REPLACED")
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(part)
        final_fd = os.fstat(stream.fileno())
    after = path.stat()
    key = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
    guard(key(before) == key(after) == key(final_fd), "BACKUP_CHANGED")
    return h.hexdigest()


def private_file(path: Path) -> None:
    guard(path.is_absolute() and path.is_relative_to(PRIVATE_ROOT) and
          ".." not in path.parts and path.resolve(strict=True) == path,
          "PRIVATE_PLAN_PATH")
    current = path.parent
    while current != PRIVATE_ROOT.parent:
        s = current.lstat()
        guard(stat.S_ISDIR(s.st_mode) and not stat.S_ISLNK(s.st_mode)
              and s.st_mode & 0o077 == 0, "PRIVATE_DIRECTORY_PERMISSIONS")
        current = current.parent
    s = path.lstat()
    guard(stat.S_ISREG(s.st_mode) and s.st_mode & 0o077 == 0,
          "PRIVATE_PLAN_PERMISSIONS")


def load_plan(path: Path, expected_sha: str) -> dict:
    guard(type(expected_sha) is str and SHA.fullmatch(expected_sha) is not None,
          "PLAN_SHA_REQUIRED")
    private_file(path)
    raw = checked_file(path, 64 * 1024)
    guard(hashlib.sha256(raw).hexdigest() == expected_sha, "PLAN_SHA_MISMATCH")
    try:
        plan = json.loads(raw)
    except ValueError as exc:
        raise LifecycleHold("P7U_HOLD_PLAN_JSON") from exc
    guard(type(plan) is dict and set(plan) in (PLAN_FIELDS, PLAN_FIELDS | {"reconciliation"},
          PLAN_FIELDS | {"previous_approval_sha256"}) and
          plan.get("schema") == "p7u-one-shot-plan-v1", "PLAN_SCHEMA")
    if "previous_approval_sha256" in plan:
        guard(plan.get("original_slot") == "official" and
              type(plan["previous_approval_sha256"]) is str and
              SHA.fullmatch(plan["previous_approval_sha256"]) is not None,
              "PLAN_DB_RENEWAL_SCOPE")
    source = SOURCE.read_text().strip()
    guard(re.fullmatch(r"[a-f0-9]{40}", source) is not None and
          plan["source_sha"] == source, "MANAGER_SOURCE_SHA")
    guard(type(plan["operation_id"]) is str and
          str(uuid.UUID(plan["operation_id"])) == plan["operation_id"], "OPERATION_ID")
    guard(plan["original_slot"] in ("official", "fallback", "diagnostic") and
          plan["target_slot"] in ("fallback", "diagnostic") and
          plan["original_slot"] != plan["target_slot"], "PLAN_SLOT")
    for field in ("diagnostic_image_sha256", "fallback_image_sha256", "preserved_backup_sha256"):
        guard(type(plan[field]) is str and SHA.fullmatch(plan[field]) is not None,
              "PLAN_IMAGE_OR_BACKUP_SHA")
    guard(plan["diagnostic_image_sha256"] != plan["fallback_image_sha256"],
          "FALLBACK_NOT_INDEPENDENT")
    refs = plan["image_references"]
    guard(type(refs) is dict and set(refs) == {"diagnostic", "fallback"},
          "PLAN_IMAGE_REFERENCES")
    for slot in ("diagnostic", "fallback"):
        expected = "localhost:50144/p7u-r4-" + slot + ":0.2.1-" + source[:12]
        guard(refs[slot] == expected, "PLAN_SOURCE_IMAGE_REFERENCE")
    guard(type(plan["original_owner"]) is dict and
          set(plan["original_owner"]) == {"container_id", "pid", "started_at", "image_digest"},
          "PLAN_ORIGINAL_OWNER")
    mqtt = plan["mqtt"]
    guard(type(mqtt) is dict and set(mqtt) == {"host", "port", "username", "password"},
          "PLAN_MQTT")
    guard(all(type(mqtt[x]) is str for x in ("host", "username", "password")),
          "PLAN_MQTT_TYPES")
    guard(type(plan["expected_topics"]) is list, "PLAN_TOPICS")
    Config(**mqtt, expected_topics=tuple(plan["expected_topics"]),
           ha_entity_id=plan["ha_entity_id"]).validate()
    return plan


def data_files() -> list[Path]:
    directory = DATABASE.parent
    guard(not directory.is_symlink(), "HOST_DATA_SYMLINK")
    files = sorted(directory.rglob("*"))
    guard(len(files) <= MAX_FILES, "HOST_DATA_TOO_MANY_FILES")
    total = 0
    for item in files:
        s = item.lstat()
        if stat.S_ISLNK(s.st_mode):
            relative = item.relative_to(directory).as_posix()
            guard(relative in ALLOWED_LINKS and os.readlink(item) == ALLOWED_LINKS[relative],
                  "HOST_DATA_UNAPPROVED_SYMLINK")
            continue
        guard(stat.S_ISREG(s.st_mode) or stat.S_ISDIR(s.st_mode),
              "HOST_DATA_SPECIAL_OR_SYMLINK")
        if stat.S_ISREG(s.st_mode):
            total += s.st_size
    guard(total <= MAX_BACKUP, "HOST_DATA_BACKUP_TOO_LARGE")
    return files


def cold_backup(directory: Path) -> dict:
    """Preserve latest quiesced host files without restoring any radio state."""
    files = data_files()
    target = directory / "cold-host-data.tar"
    pending = directory / "cold-host-data.tar.pending"
    guard(not target.exists() and not pending.exists(), "COLD_BACKUP_ALREADY_EXISTS")
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        with tarfile.open(fileobj=output, mode="w") as archive:
            for item in files:
                s = item.lstat()
                name = str(Path("zigbee2mqtt") / item.relative_to(DATABASE.parent))
                header = tarfile.TarInfo(name)
                header.mode, header.uid, header.gid = s.st_mode & 0o777, s.st_uid, s.st_gid
                header.mtime = int(s.st_mtime)
                if stat.S_ISLNK(s.st_mode):
                    relative = item.relative_to(DATABASE.parent).as_posix()
                    guard(relative in ALLOWED_LINKS and os.readlink(item) == ALLOWED_LINKS[relative],
                          "COLD_BACKUP_UNAPPROVED_SYMLINK")
                    header.type = tarfile.SYMTYPE
                    header.linkname = ALLOWED_LINKS[relative]
                    archive.addfile(header)
                elif stat.S_ISDIR(s.st_mode):
                    header.type = tarfile.DIRTYPE
                    archive.addfile(header)
                else:
                    guard(stat.S_ISREG(s.st_mode), "COLD_BACKUP_SPECIAL_FILE")
                    header.size = s.st_size
                    source_fd = os.open(item, os.O_RDONLY | os.O_NOFOLLOW)
                    with os.fdopen(source_fd, "rb") as source:
                        before = os.fstat(source.fileno())
                        guard((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                              (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns), "COLD_BACKUP_CHANGED")
                        archive.addfile(header, source)
                        after = os.fstat(source.fileno())
                        guard((before.st_size, before.st_mtime_ns) ==
                              (after.st_size, after.st_mtime_ns), "COLD_BACKUP_CHANGED")
        output.flush()
        os.fsync(output.fileno())
    guard(data_files() == files, "HOST_DATA_INVENTORY_CHANGED_DURING_BACKUP")
    os.rename(pending, target)
    fsync_directory(directory)
    # Read the finished archive and ensure its committed DB bytes are included.
    with tarfile.open(target) as archive:
        stream = archive.extractfile("zigbee2mqtt/database.db")
        guard(stream is not None and stream.read() == checked_file(DATABASE, 64 * 1024**2),
              "COLD_BACKUP_DATABASE_MISMATCH")
    return {"archive": target.name, "sha256": sha_file(target, limit=MAX_BACKUP + 64 * 1024**2),
            "files": len(files)}


def fsync_directory(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextmanager
def global_operation_lock():
    """One manager across ALL private plan directories, including new plans."""
    path = PRIVATE_ROOT / "exclusive-manager.lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        state = os.fstat(fd)
        guard(stat.S_ISREG(state.st_mode) and state.st_mode & 0o077 == 0,
              "GLOBAL_LOCK_PERMISSIONS")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise LifecycleHold("P7U_HOLD_ANOTHER_MANAGER_RUNNING") from exc
        yield
    finally:
        os.close(fd)


def claim_operation(plan: dict, plan_sha256: str) -> None:
    """Retain an exclusive intent pointer until explicit operator reconciliation.

    A fresh plan directory cannot hide another run's interrupted stop/start.
    Even a completed pointer is retained as evidence, never cleared on exit.
    """
    path = PRIVATE_ROOT / "active-operation.json"
    guard(not path.exists() and not path.is_symlink(),
          "PRIOR_GLOBAL_OPERATION_REQUIRES_RECONCILIATION")
    raw = (json.dumps({"schema": "p7u-active-operation-v1",
        "operation_id": plan["operation_id"], "source_sha": plan["source_sha"],
        "plan_sha256": plan_sha256}, sort_keys=True) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        guard(os.write(fd, raw) == len(raw), "GLOBAL_INTENT_SHORT_WRITE")
        os.fsync(fd)
    finally:
        os.close(fd)
    fsync_directory(PRIVATE_ROOT)


class PreservingPort(HaSupervisorPort):
    def __init__(self, *args, artifact_directory: Path,
                 previous_approval_sha256: str | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.artifact_directory = artifact_directory
        self.cold_receipt: dict | None = None
        self.previous_approval_sha256 = previous_approval_sha256

    def preflight_database(self) -> dict:
        if self.previous_approval_sha256 is not None:
            return renewal_baseline(self._database_path(), self.previous_approval_sha256)
        return super().preflight_database()

    def approve_quiesced_database(self, baseline: dict) -> dict:
        # Parent admission performs fresh, spaced /proc checks again. No file
        # archive or admission is made while a known owner is still running.
        guard(all(not self.inspect(slot).running for slot in ("official", "diagnostic", "fallback")),
              "COLD_BACKUP_OWNER_STILL_RUNNING")
        from p7u_lifecycle_machine import zero_tty_three_times
        zero_tty_three_times(self)
        self.cold_receipt = cold_backup(self.artifact_directory)
        if self.previous_approval_sha256 is not None:
            self._require_manual_profiles()
            guard(all(not self.inspect(slot).running for slot in ("official", "diagnostic", "fallback")),
                  "DB_APPROVAL_COMPETING_CONTAINER")
            zero_tty_three_times(self)
            result = seal_quiesced(database=self._database_path(), baseline=baseline,
                all_slots_stopped=True, no_tty_holders=True,
                previous_approval_sha256=self.previous_approval_sha256,
                previous_approval_archive=self.artifact_directory / "previous-db-approval.json")
            guard(all(not self.inspect(slot).running for slot in ("official", "diagnostic", "fallback")),
                  "DB_APPROVAL_OWNER_APPEARED")
            zero_tty_three_times(self)
            self.database_receipt = result
        else:
            result = super().approve_quiesced_database(baseline)
        return {**result, "cold_backup": self.cold_receipt}


def validate_live_plan(port: HaSupervisorPort, plan: dict) -> None:
    original = plan["original_slot"]
    actual = require_running(port.inspect(original), original)
    guard(actual == Owner(**plan["original_owner"]), "PLAN_ORIGINAL_EPOCH_CHANGED")
    port.validate_profiles(original_slot=original, target_slot=plan["target_slot"])
    port.prove_owner_holders(actual, port.tty_holders())
    validate_service_bundle(port, plan)


def validate_service_bundle(port: HaSupervisorPort, plan: dict) -> None:
    # The fixed profile and exact same service options are checked separately
    # from image identity. Passwords and network keys never enter the receipt.
    options = []
    for slot in ("official", "diagnostic", "fallback"):
        info = port.client.call(method="GET", slot=slot, action="info")["data"]
        guard(type(info.get("options")) is dict, "SUPERVISOR_OPTIONS_MISSING")
        options.append(info["options"])
    guard(options[0] == options[1] == options[2], "HOST_OPTIONS_DIFFER")
    effective = options[0]
    guard(effective.get("data_path") == str(DATABASE.parent) and
          effective.get("serial", {}).get("port") == plan["serial_by_id"] and
          effective.get("serial", {}).get("adapter") == "zstack" and
          effective.get("socat", {}).get("enabled") is False and
          effective.get("mqtt", {}).get("base_topic", "zigbee2mqtt") == "zigbee2mqtt",
          "HOST_OPTIONS_PROFILE")
    for slot, key in (("diagnostic", "diagnostic_image_sha256"), ("fallback", "fallback_image_sha256")):
        port.qualify_image(slot, expected_image_sha=plan[key])
    preserved = Path(plan["preserved_backup_path"])
    guard(preserved.is_absolute(), "PRESERVED_BACKUP_PATH")
    guard(sha_file(preserved) == plan["preserved_backup_sha256"], "PRESERVED_BACKUP_SHA")
    data_files()  # Reject an unarchivable data tree while original still serves.
    port.preflight_database()


def run(options: dict) -> dict:
    guard(type(options) is dict and set(options) == {"plan_path", "plan_sha256", "execute"}
          and type(options["execute"]) is bool, "MANAGER_OPTIONS")
    plan_path = Path(options["plan_path"])
    plan = load_plan(plan_path, options["plan_sha256"])
    config = Config(**plan["mqtt"], expected_topics=tuple(plan["expected_topics"]),
                    ha_entity_id=plan["ha_entity_id"])
    # A fresh MQTT monitor is created only after the target has started.
    probe = lambda slot, seconds: FreshMqttEvidence(config).collect(seconds)
    port = PreservingPort(plan["serial_by_id"], database=DATABASE,
                          serving_probe=probe, artifact_directory=plan_path.parent,
                          previous_approval_sha256=plan.get("previous_approval_sha256"),
                          image_references=plan["image_references"])
    if "reconciliation" in plan:
        from p7u_reconciled_start import run_reconciled
        return run_reconciled(options, plan, port)
    validate_live_plan(port, plan)
    result = {"schema": "p7u-one-shot-result-v1", "source_sha": plan["source_sha"],
              "operation_id": plan["operation_id"], "plan_sha256": options["plan_sha256"],
              "original": plan["original_slot"], "target": plan["target_slot"],
              "serial_opened": False, "physical_reset": False}
    if not options["execute"]:
        return {**result, "status": "PREFLIGHT_PASS", "service_mutated": False}
    journal_directory = plan_path.parent / "journal"
    journal_directory.mkdir(mode=0o700, exist_ok=True)
    with global_operation_lock(), Journal(journal_directory) as journal:
        guard(journal.phase is None, "PRIOR_OPERATION_REQUIRES_RECONCILIATION")
        claim_operation(plan, options["plan_sha256"])
        # Recheck exact epoch while holding the exclusive operation journal.
        validate_live_plan(port, plan)
        capabilities = {
            "diagnostic_profile_sha": plan["diagnostic_image_sha256"],
            "fallback_profile_sha": plan["fallback_image_sha256"],
            "identity_inspection": True, "tty_fd_inspection": True,
            "source_database_gate": True, "save_before_adapter_close": True,
        }
        manager = Manager(journal, port, capabilities)
        status = manager.switch_once(original_slot=plan["original_slot"],
            target_slot=plan["target_slot"], database_approved=True, guard_passive=True)
        return {**result, "status": status, "journal_head": journal.head,
                "cold_backup": port.cold_receipt, "service_mutated": True}


def main() -> int:
    try:
        options = json.loads(Path("/data/options.json").read_text())
        result = run(options)
        print(json.dumps(result, sort_keys=True), flush=True)
        return 0
    except (LifecycleHold, AdmissionHold) as exc:
        reason = str(exc)
        if re.fullmatch(r"P7U[_ A-Z0-9]+", reason) is None:
            reason = "P7U_HOLD_REVIEW_PRIVATE_JOURNAL"
        print(json.dumps({"schema": "p7u-one-shot-result-v1", "status": "HOLD",
                          "reason": reason}), flush=True)
        return 2
    except (OSError, ValueError, KeyError, TypeError):
        # Never stringify arbitrary network/parser exceptions: they can contain
        # secrets from private service options. Durable journal is the receipt.
        print(json.dumps({"schema": "p7u-one-shot-result-v1", "status": "HOLD",
                          "reason": "inspect durable journal and private plan; no automatic retry"}), flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
