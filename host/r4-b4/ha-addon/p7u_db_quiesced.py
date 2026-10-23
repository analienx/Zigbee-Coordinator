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


def seal_quiesced(*, database: Path, baseline: dict,
                  all_slots_stopped: bool, no_tty_holders: bool) -> dict:
    guard(all_slots_stopped is True and no_tty_holders is True,
          "DB_APPROVAL_BEFORE_EXCLUSIVE_RELEASE")
    guard(database.name=="database.db" and database.is_absolute() and
          "/zigbee2mqtt/" in str(database), "DB_APPROVAL_LOCATION")
    directory=database.parent
    manifest=directory/".p7u-approved.json"
    pending=directory/".p7u-approved.json.pending"
    guard(not manifest.exists() and not pending.exists(),
          "DB_APPROVAL_ALREADY_EXISTS_OR_PENDING")
    guard(not database.with_name("database.db.tmp").exists(),
          "DB_UNRESOLVED_TEMP")
    raw=checked_file(database,DB_LIMIT)
    info=inspect_database(raw)
    for key in ("inventory_sha256","devices","rows","groups"):
        guard(info[key]==baseline.get(key),"DB_CHANGED_SINCE_PRESTOP_"+key.upper())
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
    }
