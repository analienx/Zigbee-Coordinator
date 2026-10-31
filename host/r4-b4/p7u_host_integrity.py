#!/usr/bin/env python3
"""Read-only P7U retained-network database admission, before any UART open.

Neither creates nor repairs a DB. An operator-approved, freshly sealed
snapshot is a prerequisite; older backups or *.tmp are never promoted.
All errors HOLD. This is a source-only component, not a qualified HA service.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
import re
import stat

DB_LIMIT = 64 * 1024 * 1024
VALID_TYPES = frozenset(("Coordinator", "Router", "EndDevice", "Unknown", "GreenPower", "Group"))
IEEE = re.compile(r"^0x[0-9a-fA-F]{16}$")
HEX_SHA = re.compile(r"^[0-9a-f]{64}$")


class AdmissionHold(RuntimeError):
    """Must never trigger fallback formation, NV restore, or a serial open."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise AdmissionHold("P7U_HOLD_" + reason)


def checked_file(path: Path, max_size: int) -> bytes:
    """Reject symlinks, non-files and in-place change while reading."""
    require(not path.is_symlink(), "SYMLINK")
    try:
        before = path.stat()
        require(stat.S_ISREG(before.st_mode), "NOT_REGULAR")
        require(0 < before.st_size <= max_size, "SIZE")
        with path.open("rb") as stream:
            fd_before = os.fstat(stream.fileno())
            require((fd_before.st_dev, fd_before.st_ino) == (before.st_dev, before.st_ino),
                    "REPLACED_BEFORE_OPEN")
            value = stream.read(max_size + 1)
            fd_after = os.fstat(stream.fileno())
        after = path.stat()
    except (OSError, ValueError) as e:
        raise AdmissionHold("P7U_HOLD_READ_ERROR") from e
    require(len(value) == before.st_size <= max_size, "READ_LENGTH")
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), "READ_CHANGED")
    require((fd_before.st_size, fd_before.st_mtime_ns) ==
            (fd_after.st_size, fd_after.st_mtime_ns), "OPEN_FILE_CHANGED")
    return value


def inspect_database(raw: bytes) -> dict:
    try:
        content = raw.decode("utf-8", "strict")
    except UnicodeError as exc:
        raise AdmissionHold("P7U_HOLD_DB_UTF8") from exc
    require(bool(content) and "\0" not in content, "DB_EMPTY_OR_NUL")
    ids: set[int] = set()
    devices: set[str] = set()
    coordinator = 0
    groups = 0
    rows = 0
    for line in content.splitlines():
        require(bool(line.strip()), "DB_BLANK_LINE")
        try:
            row = json.loads(line)
        except (ValueError, TypeError) as exc:
            raise AdmissionHold("P7U_HOLD_DB_INVALID_JSONL") from exc
        require(isinstance(row, dict), "DB_ROW_SHAPE")
        rid = row.get("id")
        require(type(rid) is int and 0 <= rid < 2**53 and rid not in ids, "DB_DUPLICATE_OR_BAD_ID")
        ids.add(rid)
        kind = row.get("type")
        require(kind in VALID_TYPES, "DB_ENTITY_TYPE")
        if kind == "Group":
            groups += 1
            group_id = row.get("groupID")
            require(type(group_id) is int and 0 <= group_id <= 0xffff, "DB_GROUP_ID")
        else:
            if kind == "Coordinator":
                coordinator += 1
            ieee = row.get("ieeeAddr")
            # GreenPower can identify by sourceID rather than IEEE.
            if kind != "GreenPower":
                require(isinstance(ieee, str) and IEEE.fullmatch(ieee) is not None, "DB_IEEE")
            if ieee is not None:
                require(isinstance(ieee, str) and IEEE.fullmatch(ieee) is not None, "DB_IEEE")
                norm = ieee.lower()
                require(norm not in devices, "DB_DUPLICATE_IEEE")
                devices.add(norm)
        rows += 1
    require(rows > 0 and coordinator == 1, "DB_COORDINATOR")
    return {
        "rows": rows,
        "devices": len(devices),
        "groups": groups,
        "coordinators": coordinator,
        "inventory_sha256": hashlib.sha256(
            ("\n".join(sorted(devices)) + "\n").encode("ascii")
        ).hexdigest(),
    }


@dataclass(frozen=True)
class Admission:
    database_sha256: str
    inventory_sha256: str
    rows: int
    devices: int
    approval_generation: str


def verify_committed(database: Path, approval_file: Path) -> Admission:
    # Approval is operator-sealed from the latest committed DB, not from an
    # earlier backup and not created by this code. It must be updated on
    # legitimate inventory changes before a controlled later host start.
    require(database.name == "database.db", "UNEXPECTED_DATABASE_NAME")
    require(not database.with_name("database.db.tmp").exists(), "UNRESOLVED_TEMP_DATABASE")
    raw = checked_file(database, DB_LIMIT)
    summary = inspect_database(raw)
    digest = hashlib.sha256(raw).hexdigest()
    try:
        manifest = json.loads(checked_file(approval_file, 16 * 1024))
    except (ValueError, TypeError) as exc:
        raise AdmissionHold("P7U_HOLD_APPROVAL_INVALID_JSON") from exc
    require(type(manifest) is dict and manifest.get("schema") == "p7u-db-admission-v1",
            "APPROVAL_SCHEMA")
    approved = manifest.get("database_sha256")
    inventory = manifest.get("inventory_sha256")
    generation = manifest.get("generation")
    require(isinstance(approved, str) and HEX_SHA.fullmatch(approved) is not None,
            "APPROVAL_DB_DIGEST")
    require(isinstance(inventory, str) and HEX_SHA.fullmatch(inventory) is not None,
            "APPROVAL_INVENTORY_DIGEST")
    require(isinstance(generation, str) and
            re.fullmatch(r"[a-zA-Z0-9_-]{12,100}", generation) is not None,
            "APPROVAL_GENERATION")
    require(approved == digest, "COMMITTED_DATABASE_CHANGED")
    require(inventory == summary["inventory_sha256"], "INVENTORY_CHANGED")
    require(type(manifest.get("rows")) is int and manifest["rows"] == summary["rows"],
            "ROW_COUNT_CHANGED")
    require(type(manifest.get("devices")) is int and manifest["devices"] == summary["devices"],
            "DEVICE_COUNT_CHANGED")
    return Admission(digest, inventory, summary["rows"], summary["devices"], generation)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--approval", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = verify_committed(args.database, args.approval)
    except AdmissionHold as exc:
        print("HOLD:", exc)
        return 2
    print("P7U_DB_ADMISSION_VERIFIED", json.dumps(result.__dict__, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
