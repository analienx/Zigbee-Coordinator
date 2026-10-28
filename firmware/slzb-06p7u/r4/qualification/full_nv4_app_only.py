#!/usr/bin/env python3
"""Frozen-profile offline APP HEX extractor for *unsealed* full NV4 native builds.

Inputs must pass genuine ELF/XML/HEX/BIN cross-binding with four 8KiB NV4
pages at A6000..ADFFF and a linked 4096-byte C/IRQ stack. Every programmed
APP sector is explicitly padded with FF; the vector sector is ordered last
for any later, independently authorized ROM transaction. This creates no
writer, flash permission, B0-B4 release seal or hardware action.
"""
from __future__ import annotations

import argparse
import binascii
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "b0/tools"))
sys.path.insert(0, str(ROOT / "release"))
from b0_image_audit import _parse_intel_hex, audit
from nv4_native_gate import STOCK_20240716_CCFG_SHA256
from r4_native_bundle import BundleError, capture_native

APP_CEILING = 0xA0000
NV_START = 0xA6000
NV_END = 0xAE000
CCFG_START = 0xAFFA8
CHIP_END = 0xB0000
SECTOR = 0x2000
OUTPUT = "R4-FULL-NV4-APP-ONLY-UNSEALED-NOT-FLASH.hex"
RECEIPT = "r4-full-nv4-app-only-receipt.json"


def deny(message):
    raise ValueError("R4_FULL_NV4_APP_ONLY_BLOCKED_" + message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def record(kind, addr, data):
    if not 0 <= kind <= 5 or not 0 <= addr < 0x10000 or len(data) > 255:
        deny("RECORD_ARGUMENT_INVALID")
    body = bytes((len(data), addr >> 8, addr & 0xFF, kind)) + data
    return ":" + (body + bytes(((-sum(body)) & 0xFF,))).hex().upper()


def serialize(padded):
    if not padded:
        deny("NO_APP_SECTORS")
    addresses = sorted(padded)
    result = []
    active_hi = None
    idx = 0
    while idx < len(addresses):
        address = addresses[idx]
        hi = address >> 16
        if hi != active_hi:
            result.append(record(4, 0, hi.to_bytes(2, "big")))
            active_hi = hi
        part = [padded[address]]
        idx += 1
        while (idx < len(addresses) and len(part) < 16 and
               addresses[idx] == address + len(part) and
               addresses[idx] >> 16 == hi):
            part.append(padded[addresses[idx]])
            idx += 1
        result.append(record(0, address & 0xFFFF, bytes(part)))
    result.append(record(1, 0, b""))
    return ("\n".join(result) + "\n").encode("ascii")


def isolate(native, *, stock20260311=False):
    if not native or min(native) != 0 or max(native) >= CHIP_END:
        deny("NATIVE_CHIP_ADDRESS_INVALID")
    if not set(range(CCFG_START, CHIP_END)).issubset(native):
        deny("STOCK_CCFG_MISSING")
    ccfg = bytes(native[x] for x in range(CCFG_START, CHIP_END))
    if stock20260311:
        import full_nv4_profile as full
        full.validate_profile(full.STOCK_20260311_PROFILE)
        expected_ccfg = full.STOCK_20260311_CCFG_SHA
    else:
        expected_ccfg = STOCK_20240716_CCFG_SHA256
    if sha(ccfg) != expected_ccfg:
        deny("LINKED_CCFG_DIFFERS_FROM_" + ("20260311" if stock20260311 else "20240716"))
    if any(APP_CEILING <= a < CCFG_START for a in native):
        deny("NATIVE_NV4_GAP_OR_CCFG_SECTOR_WRITTEN")
    app = {a: v for a, v in native.items() if a < APP_CEILING}
    if not set(range(0, 0x3C)).issubset(app):
        deny("DIRECT_VECTOR_INCOMPLETE")
    sp = int.from_bytes(bytes(app[a] for a in range(4)), "little")
    reset = int.from_bytes(bytes(app[a] for a in range(4, 8)), "little")
    if sp % 8 or not 0x20000000 <= sp <= 0x20024000:
        deny("CORTEX_STACK_INVALID")
    if not (reset & 1 and 0 < (reset & ~1) < APP_CEILING):
        deny("CORTEX_RESET_INVALID")
    sectors = sorted({a // SECTOR * SECTOR for a in app})
    if not sectors or sectors[0] != 0 or any(s + SECTOR > APP_CEILING for s in sectors):
        deny("APP_SECTOR_OUTSIDE_CONSERVATIVE_LIMIT")
    padded = {}
    crc = {}
    for start in sectors:
        block = bytes(app.get(a, 0xFF) for a in range(start, start + SECTOR))
        padded.update((start + offset, val) for offset, val in enumerate(block))
        crc[f"0x{start:05X}"] = f"{binascii.crc32(block)&0xFFFFFFFF:08x}"
    payload = serialize(padded)
    with tempfile.TemporaryDirectory(prefix="r4-nv4-hex-selfcheck-") as tmp:
        path = Path(tmp) / "padded.hex"
        path.write_bytes(payload)
        check, error = _parse_intel_hex(path)
        if error or check != padded:
            deny("FULL_SECTOR_HEX_ROUNDTRIP")
    order = [x for x in sectors if x != 0] + [0]
    return payload, {
        "schema": "r4-full-p7u-nv4-app-only-unsealed-v1",
        "image_class": ("STOCK20260311_APP_VECTOR_ZERO_UNBOOTABLE_UNTIL_SEPARATE_BOOT_HANDOFF"
                        if stock20260311 else "FULL_NV4_NATIVE_ENVELOPE_ONLY_UNSEALED_NOT_FLASH_READY"),
        "app_limit_exclusive": "0xA0000",
        "protected_nv4": ["0xA4000", "0xAC000"] if stock20260311 else ["0xA6000", "0xAE000"],
        "resident_boot": ["0xAC000", "0xAE000"] if stock20260311 else None,
        "app_vector_zero_bootable": False,
        "protected_ccfg": ["0xAE000", "0xB0000"],
        "linked_stock_ccfg_sha256": sha(ccfg),
        "application_sectors": [f"0x{x:05X}" for x in sectors],
        "sectors_to_program": len(sectors),
        "vector_last_program_order": [f"0x{x:05X}" for x in order],
        "sector_crc32_ff_padded": crc,
        "padded_hex_sha256": sha(payload),
        "requires_full_b0_b4_release_seal": True,
        "full_b0_b4_sealed": False,
        "nv_erases_allowed": False,
        "ccfg_erases_allowed": False,
        "chip_erase_allowed": False,
        "flash_authorized": False,
    }


def prepare(artifacts: Path, out: Path, *, expected_manifest_sha256: str, stock20260311=False):
    """Audit and extract one externally pinned snapshot, never reopened inputs."""
    if out.exists() or out.is_symlink() or artifacts.is_symlink():
        deny("INPUT_OR_OUTPUT_UNTRUSTED")
    root = artifacts.resolve()
    base = ROOT / "b0"
    with tempfile.TemporaryDirectory(prefix="r4-full-nv4-frozen-native-") as tmp:
        frozen = Path(tmp)
        try:
            manifest = capture_native(root, frozen, expected_manifest_sha256)
        except BundleError as exc:
            deny(str(exc))
        # Both the full geometry/content audit and HEX extraction read only
        # this exclusively owned snapshot, after all original digests pass.
        layout = {"stock20260311": True} if stock20260311 else {"full_nv4": True}
        status, message = audit(base, frozen, **layout)
        if status != 0:
            deny("REAL_ELF_XML_HEX_BIN_AUDIT_" + re.sub(r"[^A-Z0-9]", "_", message.upper())[:80])
        raw_name = manifest["files"]["hex"]["file"]
        native, error = _parse_intel_hex(frozen / raw_name)
        if error:
            deny("NATIVE_HEX_UNREADABLE")
        payload, receipt = isolate(native, stock20260311=stock20260311)
    receipt["source_native_manifest_sha256"] = expected_manifest_sha256
    receipt["source_native_artifact_sha256"] = {
        kind: manifest["files"][kind]["sha256"] for kind in ("elf", "hex", "bin", "xml")}
    receipt["source_native_hex_sha256"] = manifest["files"]["hex"]["sha256"]
    receipt["native_elf_xml_hex_bin_audit"] = "PASS_FULL_NV4_GEOMETRY_AND_CIRQ4096_ONLY"
    receipt["output_hex"] = OUTPUT
    out.mkdir(parents=True)
    (out / OUTPUT).write_bytes(payload)
    (out / RECEIPT).write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--stock20260311", action="store_true")
    parser.add_argument("--manifest-sha256", required=True,
                        help="Externally pinned native manifest SHA-256; never inferred from the input")
    args = parser.parse_args()
    receipt = prepare(args.artifacts, args.out_dir,
                      expected_manifest_sha256=args.manifest_sha256,
                      stock20260311=args.stock20260311)
    print(json.dumps({"status": receipt["image_class"],
                      "sectors": receipt["sectors_to_program"],
                      "flash_authorized": False}))


if __name__ == "__main__":
    main()
