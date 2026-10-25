"""Quiesced retained-network DB admission receipt, generated AFTER owner exit.

No firmware/NV access. Refuses to create an approval while ANY UART holder
or Zigbee add-on remains running. Preserves incomplete *.pending files.
Requires an exact pre-stop inventory fingerprint; no silent loss of devices,
old DB promotion, backup restore or speculative database repair.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

from p7u_lifecycle_core import LifecycleHold, guard
from p7u_host_integrity import (
    inspect_database, checked_file, verify_committed, DB_LIMIT, AdmissionHold,
)


def inventory_baseline(database: Path) -> dict:
    raw=checked_file(database,DB_LIMIT)
    info=inspect_database(raw)
    return {**info,"database_sha256":hashlib.sha256(raw).hexdigest()}


def renewal_baseline(database: Path, previous_approval_sha256: str) -> dict:
    """Explicit operator-pinned renewal; no write and no stale-DB admission."""
    guard(type(previous_approval_sha256) is str and
          re.fullmatch(r"[a-f0-9]{64}", previous_approval_sha256) is not None,
          "DB_RENEWAL_PIN")
    for name in ("database.db.tmp", ".p7u-approved.json.pending"):
        path = database.with_name(name)
        guard(not path.exists() and not path.is_symlink(), "DB_RENEWAL_UNRESOLVED_TEMP")
    raw = checked_file(database.with_name(".p7u-approved.json"), 16 * 1024)
    guard(hashlib.sha256(raw).hexdigest() == previous_approval_sha256,
          "DB_RENEWAL_PRIOR_CHANGED")
    try:
        previous = json.loads(raw)
    except ValueError as exc:
        raise LifecycleHold("P7U_HOLD_DB_RENEWAL_PRIOR_JSON") from exc
    guard(type(previous) is dict and previous.get("schema") == "p7u-db-admission-v1" and
          type(previous.get("generation")) is str and
          re.fullmatch(r"[a-zA-Z0-9_-]{12,100}", previous["generation"]) is not None and
          type(previous.get("database_sha256")) is str and
          re.fullmatch(r"[a-f0-9]{64}", previous["database_sha256"]) is not None,
          "DB_RENEWAL_PRIOR_SCHEMA")
    baseline = inventory_baseline(database)
    for key in ("inventory_sha256", "rows", "devices"):
        guard(type(previous.get(key)) is type(baseline[key]) and
              previous[key] == baseline[key], "DB_RENEWAL_INVENTORY_CHANGED")
    return {**baseline, "previous_approval_sha256": previous_approval_sha256}


def seal_quiesced(*, database: Path, baseline: dict,
                  all_slots_stopped: bool, no_tty_holders: bool,
                  previous_approval_sha256: str | None = None,
                  previous_approval_archive: Path | None = None) -> dict:
    guard(all_slots_stopped is True and no_tty_holders is True,
          "DB_APPROVAL_BEFORE_EXCLUSIVE_RELEASE")
    guard(database.name=="database.db" and database.is_absolute() and
          "/zigbee2mqtt/" in str(database), "DB_APPROVAL_LOCATION")
    directory=database.parent
    manifest=directory/".p7u-approved.json"
    pending=directory/".p7u-approved.json.pending"
    guard(not pending.exists() and not pending.is_symlink() and
          (previous_approval_sha256 is not None or
           (not manifest.exists() and not manifest.is_symlink())),
          "DB_APPROVAL_ALREADY_EXISTS_OR_PENDING")
    guard(not database.with_name("database.db.tmp").exists(),
          "DB_UNRESOLVED_TEMP")
    raw=checked_file(database,DB_LIMIT)
    info=inspect_database(raw)
    for key in ("inventory_sha256","devices","rows","groups"):
        guard(info[key]==baseline.get(key),"DB_CHANGED_SINCE_PRESTOP_"+key.upper())
    previous_raw = None
    if previous_approval_sha256 is not None:
        guard(baseline.get("previous_approval_sha256") == previous_approval_sha256,
              "DB_RENEWAL_NOT_PREFLIGHTED")
        current = renewal_baseline(database, previous_approval_sha256)
        guard(all(current[k] == baseline[k] for k in
                  ("inventory_sha256", "rows", "devices", "groups")),
              "DB_RENEWAL_INVENTORY_CHANGED")
        archive = previous_approval_archive
        guard(isinstance(archive, Path) and archive.is_absolute() and
              archive.name == "previous-db-approval.json" and
              archive.parent.resolve(strict=True) == archive.parent and
              archive.parent.is_dir() and not archive.exists() and not archive.is_symlink(),
              "DB_RENEWAL_ARCHIVE_PATH")
        previous_raw = checked_file(manifest, 16 * 1024)
        guard(hashlib.sha256(previous_raw).hexdigest() == previous_approval_sha256,
              "DB_RENEWAL_PRIOR_CHANGED")
        fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            guard(os.write(fd, previous_raw) == len(previous_raw), "DB_RENEWAL_ARCHIVE_SHORT_WRITE")
            os.fsync(fd)
        finally:
            os.close(fd)
        folder = os.open(archive.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(folder)
        finally: os.close(folder)
    else:
        guard(previous_approval_archive is None, "DB_RENEWAL_ARCHIVE_WITHOUT_PIN")
    gen="owner-quiesced-"+uuid.uuid4().hex
    data={
        "schema":"p7u-db-admission-v1",
        "database_sha256":hashlib.sha256(raw).hexdigest(),
        "inventory_sha256":info["inventory_sha256"],
        "rows":info["rows"],"devices":info["devices"],"generation":gen,
    }
    serialized=(json.dumps(data,sort_keys=True,separators=(",",":"))+"\n").encode()
    # O_EXCL prevents overriding a previous receipt/gap. Never truncate.
    fd=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|os.O_NOFOLLOW,0o600)
    try:
        os.fchmod(fd,0o600)
        count=os.write(fd,serialized)
        guard(count==len(serialized),"DB_APPROVAL_SHORT_WRITE")
        os.fsync(fd)
    finally:
        os.close(fd)
    # Detect original DB being changed by a process we did not observe:
    # never issue a receipt for a different file or inventory.
    fresh=checked_file(database,DB_LIMIT)
    guard(fresh==raw,"DB_CHANGED_WHILE_SEALING")
    if previous_raw is not None:
        guard(checked_file(manifest, 16 * 1024) == previous_raw, "DB_RENEWAL_PRIOR_CHANGED")
        os.replace(pending, manifest)
    else:
        os.rename(pending,manifest)
    folder_fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(folder_fd)
    finally:os.close(folder_fd)
    try:
        verified=verify_committed(database,manifest)
    except AdmissionHold as exc:
        raise LifecycleHold("P7U_HOLD_DB_VERIFICATION_FAILED") from exc
    return {
        "schema":"p7u-quiesced-approval-v1",
        "database_sha256":verified.database_sha256,
        "inventory_sha256":verified.inventory_sha256,
        "approved_rows":verified.rows,
        "approved_devices":verified.devices,
        "generation":verified.approval_generation,
        **({"previous_approval_sha256": previous_approval_sha256,
            "previous_approval_archive": str(previous_approval_archive)} if previous_raw is not None else {}),
    }
