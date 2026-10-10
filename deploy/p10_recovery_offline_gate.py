#!/usr/bin/env python3
"""Offline recovery readiness check for an already-captured private P10 cold bundle.

Does not connect to HA or radios, never displays secrets and never writes data.
Exit 0 = integrity/shape passes. This does NOT prove fresh backup or live restore.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import zipfile
from p10_data_bundle import verify as verify_bundle
from p10_migration_backup import inventory

VENDOR_SHA = "633f79058c39e2fc9335bb11f816ad6a045438515da11c36b30a46b7c8d1b7d9"
VENDOR_BYTES = 182840


def sha_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def audit(bundle: Path, firmware: Path | None = None, min_keys: int = 103) -> dict:
    bundle = bundle.resolve(strict=True)
    result = verify_bundle(bundle)
    if not result["integrity_pass"] or not result["cold_consistent"]:
        raise ValueError("Cold bundle failed integrity/quiescence checks")
    with zipfile.ZipFile(bundle) as archive:
        raw_backup = archive.read("data/coordinator_backup.json")
        backup = json.loads(raw_backup)
        db = inventory(archive.read("data/database.db"))
        manifest = json.loads(archive.read("meta/manifest.private.json"))
    devices = backup.get("devices")
    if not isinstance(devices, list):
        raise ValueError("Missing coordinator backup devices")
    key_rows = [d for d in devices if isinstance(d, dict) and isinstance(d.get("link_key"), dict)]
    keyed_ieees = [d.get("ieee_address") for d in key_rows]
    if len(key_rows) < min_keys or len(keyed_ieees) != len(set(keyed_ieees)):
        raise ValueError("Insufficient/duplicate trust-center link keys")
    if len(devices) < len(key_rows):
        raise ValueError("Invalid device/key count")
    nwk = backup.get("network_key")
    if not isinstance(nwk, dict) or not isinstance(nwk.get("frame_counter"), int):
        raise ValueError("Backup lacks network security transmit frame counter")
    if not (0 <= nwk["frame_counter"] <= 0xFFFFFFFF):
        raise ValueError("Invalid network frame counter")
    for dev in key_rows:
        key = dev["link_key"]
        if not isinstance(key.get("tx_counter"), int) or not (0 <= key["tx_counter"] <= 0xFFFFFFFF):
            raise ValueError("Malformed per-device link key TX counter")
    missing = [k for k in ("coordinator_ieee", "pan_id", "extended_pan_id", "channel")
               if backup.get(k) is None]
    if missing:
        raise ValueError("Incomplete network identity fields: " + ",".join(missing))
    if not isinstance(backup.get("network_key", {}).get("key"), str):
        raise ValueError("Missing backed-up network key")
    captured = manifest.get("captured_utc")
    age_days = None
    if captured:
        age_days = round((datetime.now(timezone.utc) - datetime.fromisoformat(captured.replace("Z","+00:00"))).total_seconds()/86400, 2)
    out = {
        "status": "RECOVERY_ARCHIVE_VERIFIED_OFFLINE_NOT_LIVE",
        "archive_path": str(bundle),
        "archive_bytes": bundle.stat().st_size,
        "archive_sha256": sha_file(bundle),
        "archive_capture_utc": captured,
        "age_days": age_days,
        "cold_consistent": True,
        "verified_files": result["application_file_count"],
        "addon_options_present": result["addon_options_included"],
        "symlink_dependencies_present": result["symlink_dependencies_present"],
        "coordinator_backup_entries": len(devices),
        "trust_center_key_records": len(key_rows),
        "z2m_database": db,
        "backup_network_counter_present": True,
        "per_key_transmit_counters_present": True,
        "restore_proven_by_this_check": False,
    }
    if firmware is not None:
        firmware = firmware.resolve(strict=True)
        size, digest = firmware.stat().st_size, sha_file(firmware)
        if size != VENDOR_BYTES or digest != VENDOR_SHA:
            raise ValueError("Vendor rollback firmware size/digest mismatch")
        out["vendor_rollback"] = {
            "path": str(firmware), "bytes": size, "sha256": digest, "verified": True,
        }
    else:
        out["vendor_rollback"] = {"verified": False, "reason": "Known-good .slzb.bin path not supplied"}
    return out


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--cold-bundle", type=Path, required=True)
    p.add_argument("--vendor-firmware", type=Path)
    p.add_argument("--min-keys", type=int, default=103)
    args = p.parse_args(argv)
    try:
        print(json.dumps(audit(args.cold_bundle, args.vendor_firmware, args.min_keys), indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as exc:
        print(json.dumps({"status": "BLOCKED", "error_type": type(exc).__name__,
                          "reason": str(exc)[:200]}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
