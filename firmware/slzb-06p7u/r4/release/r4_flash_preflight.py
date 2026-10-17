#!/usr/bin/env python3
"""Read-only P7U application boundary and private backup eligibility assessment.

DOES NOT provide a programmer, a flash-ready image, or physical approval.
A sparse HEX must not induce an erase of any protected 8KiB sector.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "b0" / "tools"))
from b0_image_audit import _parse_intel_hex

FLASH = 0xB0000           # 704 KiB fitted CHIP capacity hypothesis
ERASE = 0x2000           # 8 KiB donor sector
SAFE_APP_END = 0xA4000   # earliest historical NV5; NV2 starts 0xAA000
NV_END = 0xAE000
CCFG = 0xAFFA8           # donor .ccfg: final 88 bytes of top sector


def block(reason):
    raise ValueError("R4_PREP_BLOCKED: " + reason)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def image_check(artifacts, *, resident_vectors=False):
    root = Path(artifacts).resolve()
    mp = root / "manifest.json"
    if mp.is_symlink() or not mp.is_file():
        block("no native manifest")
    manifest = json.loads(mp.read_text())
    if manifest.get("schema") != "r4-b0-artifact-manifest-v1":
        block("unknown native artifact schema")
    meta = manifest.get("files", {}).get("hex", {})
    name = meta.get("file")
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name):
        block("unsafe HEX basename")
    p = root / name
    if p.is_symlink() or not p.is_file() or p.resolve().parent != root:
        block("missing or symlinked native HEX")
    if not re.fullmatch(r"[0-9a-f]{64}", str(meta.get("sha256", ""))) or digest(p) != meta["sha256"]:
        block("native HEX not hash bound to manifest")
    data, err = _parse_intel_hex(p)
    if err or not data:
        block("malformed HEX")
    if min(data) < 0 or max(data) >= FLASH:
        block("HEX address outside chip capacity")
    vector_start = 0x80 if resident_vectors else 0
    if not set(range(vector_start, vector_start+0x3c)).issubset(data):
        block("incomplete reset vectors")
    if resident_vectors and any(a < 0x80 for a in data):
        block("native R4 relocated candidate must not secretly supply an unverified header")
    bad_nv = [a for a in data if SAFE_APP_END <= a < NV_END]
    if bad_nv:
        block("HEX contains data in protected NV2/NV5 union")
    bad_top = [a for a in data if NV_END <= a < CCFG]
    if bad_top:
        block("HEX contains data outside exact CCFG in top erase sector")
    if not set(range(CCFG, FLASH)).issubset(data):
        block("missing one or more installed-stock CCFG comparison bytes")
    app = {a for a in data if a < SAFE_APP_END}
    if not app:
        block("no application payload")
    sectors = sorted({a // ERASE * ERASE for a in app})
    if any(s + ERASE > SAFE_APP_END for s in sectors):
        block("application sector intersects protected NV")
    return {
        "schema": "r4-p7u-offline-preflight-v1",
        "status": "APP_ONLY_SECTORS_VALIDATED_NOT_FLASH_READY",
        "expected_vector_offset": hex(vector_start),
        "resident_loader_header_missing_in_native": resident_vectors,
        "native_hex_sha256": meta["sha256"],
        "last_application_byte_exclusive": hex(max(app) + 1),
        "application_data_bytes": len(app),
        "application_sectors": [hex(s) for s in sectors],
        "protected_nv_union": ["0xA4000", "0xAE000"],
        "protected_ccfg_sector": ["0xAE000", "0xB0000"],
        "whole_image_erase_allowed": False,
        "nv_sector_erase_allowed": False,
        "ccfg_sector_erase_allowed": False,
        "actual_hardware_backup_verified": False,
        "real_programmer_erase_policy_verified": False,
        "stock_rollback_rehearsed": False,
        "flash_authorized": False,
    }, bytes(data[a] for a in range(CCFG, FLASH))


def private_readbacks(first, second, candidate_ccfg):
    """Two PRIVATE offline full-flash files. Equality is not physical attestation."""
    paths = (Path(first), Path(second))
    for p in paths:
        if p.is_symlink() or not p.is_file() or p.stat().st_size != FLASH:
            block("full readback must be a non-symlinked 704KiB file")
    if digest(paths[0]) != digest(paths[1]):
        block("independent full readbacks are not byte-identical")
    with paths[0].open("rb") as f:
        f.seek(CCFG)
        stock_ccfg = f.read(88)
    if stock_ccfg in (b"\xff" * 88, b"\x00" * 88):
        block("fitted CCFG uninitialized")
    if stock_ccfg != candidate_ccfg:
        block("candidate CCFG differs from fitted board readback")
    return {
        "schema": "r4-p7u-private-duplicate-readback-v1",
        "input_files_identical": True,
        "ccfg_bytes_identical": True,
        "actual_hardware_origin_attested": False,
        "same_device_serial_independently_verified": False,
        "key_counter_compatibility_tested": False,
        "sector_safe_writer_proven": False,
        "rollback_boot_tested": False,
        "flash_authorized": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--private-readback-1", type=Path)
    parser.add_argument("--private-readback-2", type=Path)
    parser.add_argument("--resident-vectors", action="store_true",
                        help="For linker-shifted native image only; still NOT FLASH READY")
    a = parser.parse_args()
    if bool(a.private_readback_1) != bool(a.private_readback_2):
        block("two separate private readbacks required")
    report, ccfg = image_check(a.artifacts, resident_vectors=a.resident_vectors)
    if a.private_readback_1:
        if os.environ.get("GITHUB_ACTIONS") == "true":
            block("actual private NV/keys must never be uploaded to public GitHub Actions")
        report["private_comparison"] = private_readbacks(
            a.private_readback_1, a.private_readback_2, ccfg)
    if a.receipt.is_symlink() or a.receipt.parent.is_symlink():
        block("symlink receipt")
    a.receipt.parent.mkdir(parents=True, exist_ok=True)
    a.receipt.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
