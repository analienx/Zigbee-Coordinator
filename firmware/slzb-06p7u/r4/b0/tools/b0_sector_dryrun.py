#!/usr/bin/env python3
"""Read-only, conservative B0 TI flash-sector denial: NEVER authorizes programming.

Use source-derived 0x2000 page hypothesis solely to FIND collisions. A true
erase/program plan additionally needs board erase-block proof, same-device
stock CCFG/NV backup, and independently authorized physical verification.
"""
import argparse
import hashlib
import json
from pathlib import Path
from b0_image_audit import _parse_intel_hex, _safe_artifact, loads_strict
from b0_flash_boundary import (
    inspect, CONSERVATIVE_NV_BEGIN, NV_END, CCFG_BEGIN, IMAGE_LEN,
)

CANDIDATE_SECTOR_BYTES = 0x2000
# All sectors 0xA4000..0xAFFFF are withheld. 0xAE000..0xAFFFF
# contains CCFG, requiring separate board-specific safe programming proof.
DENY_FROM = CONSERVATIVE_NV_BEGIN
DENY_END = IMAGE_LEN

def classify_payload(payload):
    if not isinstance(payload, dict) or not payload:
        raise ValueError("B0_SECTOR_MISSING_PROGRAMMED_RECORDS")
    app = set()
    blocked = set()
    ccfg = False
    for addr, byte in payload.items():
        if type(addr) is not int or type(byte) is not int or not (
                0 <= addr < IMAGE_LEN and 0 <= byte <= 255):
            raise ValueError("B0_SECTOR_INVALID_HEX_RECORD")
        if CONSERVATIVE_NV_BEGIN <= addr < NV_END:
            raise ValueError("B0_SECTOR_HEX_INTERSECTS_NV5_NV2_UNION")
        sector = (addr // CANDIDATE_SECTOR_BYTES) * CANDIDATE_SECTOR_BYTES
        if sector >= DENY_FROM:
            blocked.add(sector)
        else:
            app.add(sector)
        if addr >= CCFG_BEGIN:
            ccfg = True
    if not ccfg or not app:
        raise ValueError("B0_SECTOR_MISSING_CCFG_OR_APPLICATION")
    deny_sectors = list(range(DENY_FROM, DENY_END, CANDIDATE_SECTOR_BYTES))
    return {
        "schema": "r4-b0-sector-denial-source-v1",
        "status": "NO_SAFE_FULL_IMAGE_SECTOR_PLAN",
        "flash_authorized": False, "programmer_commands": None,
        "production_release_authorized": False,
        "hardware_erase_geometry_verified": False,
        "sector_size_source_hypothesis_bytes": CANDIDATE_SECTOR_BYTES,
        "protected_nv_union": ["0xA4000", "0xAE000"],
        "reserved_ccfg_erase_sector": "0xAE000",
        "app_candidate_sector_starts": [hex(i) for i in sorted(app)],
        "blocked_record_sector_starts": [hex(i) for i in sorted(blocked)],
        "all_excluded_sector_starts": [hex(i) for i in deny_sectors],
        "ccfg_program_records_present": ccfg,
        "reason": "CCFG_FINAL_SECTOR_UNQUALIFIED_AND_NV5_NV2_UNION_PROTECTED",
        "future_required": [
            "independently confirmed actual erase-block geometry",
            "same-device stock CCFG BSL and NV5/NV2 backed-up and byte-hashed",
            "sector/byte erase policy independently tested on disposable board",
            "write/readback with exact firmware and stock rollback",
            "separate owner authorization; NO network or key mutation",
        ],
    }

def inspect_image(directory):
    audit = inspect(directory)  # independent SHA, HEX/BIN and NV checks
    manifest=loads_strict((directory/"manifest.json").read_text())
    entry=manifest["files"]["hex"]
    hex_file, err=_safe_artifact(directory,entry["file"])
    if err or not hex_file.is_file() or hex_file.is_symlink():
        raise ValueError("B0_SECTOR_UNSAFE_HEX_PATH")
    if hashlib.sha256(hex_file.read_bytes()).hexdigest()!=entry["sha256"]:
        raise ValueError("B0_SECTOR_HEX_DIGEST_CHANGED_AFTER_PARENT_AUDIT")
    payload, error=_parse_intel_hex(hex_file)
    if error: raise ValueError("B0_SECTOR_HEX_INVALID: "+error)
    result=classify_payload(payload)
    result["input_hex_sha256"]=hashlib.sha256(hex_file.read_bytes()).hexdigest()
    result["parent_flash_boundary_schema"]=audit["schema"]
    result["parent_flash_authorized"]=False
    return result

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--artifacts",type=Path,required=True)
    p.add_argument("--receipt",type=Path,required=True)
    a=p.parse_args()
    if a.receipt.is_symlink() or a.receipt.parent.is_symlink():
        raise SystemExit("B0_SECTOR_REFUSED_SYMLINK_OUTPUT")
    data=inspect_image(a.artifacts)
    if data["flash_authorized"] or data["status"] != "NO_SAFE_FULL_IMAGE_SECTOR_PLAN":
        raise SystemExit("B0_SECTOR_POSITIVE_FLASH_PLAN_FORBIDDEN")
    a.receipt.parent.mkdir(parents=True,exist_ok=True)
    a.receipt.write_text(json.dumps(data,indent=2,sort_keys=True)+"\n")
    print("B0_SECTOR_DENIAL_PROVEN_NO_FLASH_NO_ERASE_NO_DEVICE")
if __name__=="__main__":main()
