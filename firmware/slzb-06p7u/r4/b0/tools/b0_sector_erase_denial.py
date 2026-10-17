#!/usr/bin/env python3
"""R4 P7U 8KiB-sector erase boundary auditor; NEVER a flash planner.

HEX data bytes alone do not encode erase semantics. The sector containing CCFG
must not be implicitly erased merely because a HEX includes CCFG records.
This program issues a denial receipt only and performs no device/flash I/O.
"""
import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path

from b0_image_audit import _parse_intel_hex

FLASH_END = 0xB0000
SECTOR_SIZE = 0x2000  # 8KiB CC2652P7 flash sector, TI SWRS252A
PROTECTED_RANGES = (
    (0xA4000, 0xAE000, "NV2_AND_HISTORICAL_NV5_CONSERVATIVE_UNION"),
    (0xAE000, 0xB0000, "BOOT_CCFG_TOP_SECTOR"),
)

def evaluate(hex_file: Path):
    if hex_file.is_symlink() or not hex_file.is_file():
        raise ValueError("SECTOR_DENY_MISSING_OR_SYMLINK_HEX")
    payload, error = _parse_intel_hex(hex_file)
    if error or not payload:
        raise ValueError("SECTOR_DENY_INVALID_OR_EMPTY_HEX: " + str(error))
    if any(addr < 0 or addr >= FLASH_END for addr in payload):
        raise ValueError("SECTOR_DENY_FLASH_ADDRESS_OUT_OF_RANGE")
    image_sha = hashlib.sha256(hex_file.read_bytes()).hexdigest()
    erase_candidates = sorted({addr // SECTOR_SIZE * SECTOR_SIZE for addr in payload})
    impacted = [
        {"begin": f"0x{sector:05X}", "end_exclusive": f"0x{sector+SECTOR_SIZE:05X}",
         "reason": reason}
        for sector in erase_candidates
        for start, end, reason in PROTECTED_RANGES
        if sector < end and sector + SECTOR_SIZE > start
    ]
    return {
        "schema": "r4-b0-read-only-sector-erase-denial-v1",
        "source_hex_sha256": image_sha,
        "flash_sector_bytes": SECTOR_SIZE,
        "candidate_sectors": [f"0x{x:05X}" for x in erase_candidates],
        "protected_sector_collisions": impacted,
        "no_erase_or_program_was_attempted": True,
        "production_flash_authorized": False,
        "flash_authorized": False,
        "status": "BLOCKED_PROTECTED_SECTOR_ERASE" if impacted
                  else "BLOCKED_NO_BACKUP_OR_HARDWARE_PROOF",
        "mandatory_independent_gates": [
            "independent same-device full flash and per-NV/CCFG backup verification",
            "actual sector writer identity and erase policy independently qualified",
            "CCFG sector preservation and recovery/BSL proof",
            "dedicated disposable-board successful rollback",
            "cold-boot and security counter continuity before network test",
            "explicit new live-hardware authorization",
        ],
    }

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--hex",type=Path,required=True)
    p.add_argument("--receipt",type=Path,required=True)
    a = p.parse_args()
    try:
        data = evaluate(a.hex)
    except (OSError,ValueError) as exc:
        data = {"schema":"r4-b0-read-only-sector-erase-denial-v1",
                "status":"BLOCKED_INVALID_IMAGE", "error":str(exc)[:250],
                "flash_authorized":False,"production_flash_authorized":False,
                "no_erase_or_program_was_attempted":True}
    if a.receipt.parent.is_symlink() or a.receipt.is_symlink():
        raise SystemExit("REFUSED_SYMLINK_RECEIPT")
    a.receipt.parent.mkdir(parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix="." + a.receipt.name + ".",dir=a.receipt.parent)
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as f:
            json.dump(data,f,sort_keys=True,indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(name,a.receipt)
    finally:
        Path(name).unlink(missing_ok=True)
    print(data["status"]+" — NO FLASH")
    # Standalone audit records a blocker but it is not a release decision.
    return 0 if data["status"] == "BLOCKED_PROTECTED_SECTOR_ERASE" else 1

if __name__=="__main__":
    raise SystemExit(main())
