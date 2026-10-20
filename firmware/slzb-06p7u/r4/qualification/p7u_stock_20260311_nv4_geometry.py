#!/usr/bin/env python3
"""Offline 20260311 P7U R4 NV geometry correction. Source-only, never flash.

The earlier R4 NV4 A6000..ADFFF contract overlaps the resident boot manager
at AC000. This module consumes a PRIVATE captured image only to prove which
geometry is installed, and transforms throwaway TI source text. No network
secrets, flash data, identity, or per-record contents are output.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

import full_nv4_profile as base

CAPTURE_SHA256 = "ecf1e46b56f0640dede870a2b1cc56604fb9aa454c7e40c984e09d8a8a712299"
FLASH_SIZE = 0xB0000
NV_BASE = 0xA4000
NV_END = 0xAC000
BOOT_BASE = 0xAC000
CCFG_BASE = 0xAE000
PAGE_SIZE = 0x2000
NV_STATES = (0x78, 0x78, 0x7C, 0xFE)
NV_MODES = (0xF8, 0xF8, 0xFC, 0xFF)


def reject(reason: str) -> None:
    raise ValueError("P7U_20260311_NV4_BLOCKED_" + reason)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def check_capture(raw: bytes) -> dict:
    """Check known same-board geometry only; do not validate network security."""
    if len(raw) != FLASH_SIZE or sha(raw) != CAPTURE_SHA256:
        reject("CAPTURE_HASH_OR_LENGTH")
    u32 = lambda address: struct.unpack_from("<I", raw, address)[0]
    if (u32(0) != 0x96F3B83D or u32(0xAFFEC) != BOOT_BASE or
            u32(0xAFFD8) != 0xC5FE0FC5 or
            u32(0xAFFDC) != 0xFFFFFFFF or
            any(u32(a) != 0xFFFFFFFF for a in
                (0xAFFF0, 0xAFFF4, 0xAFFF8, 0xAFFFC))):
        reject("BOOT_OR_CCFG_GEOMETRY")
    if raw[0xA0000:NV_BASE] != bytes((0xFF,)) * (NV_BASE - 0xA0000):
        reject("LOW_RESERVED_PAGES_NOT_EMPTY")
    for i, address in enumerate(range(NV_BASE, NV_END, PAGE_SIZE)):
        header = raw[address:address + 16]
        if (len(header) != 16 or header[0] != NV_STATES[i] or
                header[6] != NV_MODES[i] or header[1] in (0, 0xFF) or
                header[2] >> 2 != 3 or
                any(header[j] != 0x96 for j in (3, 7, 11, 15))):
            reject("NVOCMP_PAGE_HEADER_" + str(i))
    sp, pc = struct.unpack_from("<II", raw, BOOT_BASE)
    if not (0x20000000 < sp <= 0x20024000 and sp % 8 == 0 and
            pc & 1 and BOOT_BASE <= (pc & ~1) < FLASH_SIZE):
        reject("RESIDENT_BOOT_VECTOR")
    return {
        "schema": "p7u-stock-20260311-nv4-geometry-v1",
        "capture_sha256": CAPTURE_SHA256,
        "nv_region": [hex(NV_BASE), hex(NV_END)],
        "nv_pages": 4,
        "nvocmp_version": 3,
        "page_states": ["FULL", "FULL", "ACTIVE", "DESTINATION"],
        "resident_boot_sector": hex(BOOT_BASE),
        "ccfg_sector": hex(CCFG_BASE),
        "ccfg_sector_write_protection_bits_clear": True,
        "native_nv_parser_passed": False,
        "keys_and_counters_verified": False,
        "flash_authorized": False,
    }


def _once(text: str, before: str, after: str, label: str) -> str:
    if text.count(before) != 1 or after in text:
        reject("SOURCE_ANCHOR_" + label)
    return text.replace(before, after, 1)


def remap_composed(syscfg: str, linker: str, project: str) -> tuple[str, str, str]:
    """Consume the existing pinned full-B0/B4 source composition."""
    if not all(isinstance(value, str) for value in (syscfg, linker, project)):
        reject("SOURCE_TYPES")
    if not all(marker in linker for marker in
               ("#define FLASH_SIZE              0xA0000",
                "#define FLASH_NV_SIZE           0x8000",
                "#define FLASH_LAST_BASE         0xAE000")):
        reject("APP_OR_CCFG_SOURCE_CONTRACT")
    if "-DNVOCMP_NVPAGES=4" not in project or "--define=NVOCMP_NVPAGES=4" not in project:
        reject("COMPILER_NV4_PAGE_COUNT")
    sc = _once(syscfg, "NVS1.internalFlash.regionBase = 0xA6000;",
               "NVS1.internalFlash.regionBase = 0xA4000;", "SYSCFG")
    ld = _once(linker, "#define FLASH_NV_BASE           0xA6000",
               "#define FLASH_NV_BASE           0xA4000", "LINKER")
    if ("NVS1.internalFlash.regionSize = 0x8000;" not in sc or
            "#define FLASH_NV_SIZE           0x8000" not in ld):
        reject("NV4_REGION_SIZE")
    return sc, ld, project


def compose(syscfg: str, linker: str, project: str) -> tuple[str, str, str]:
    """Exact pinned donor -> legacy full composition -> corrected source."""
    return remap_composed(*base.transform_pinned(syscfg, linker, project))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    if args.receipt.exists() or args.receipt.is_symlink():
        reject("RECEIPT_ALREADY_EXISTS")
    report = check_capture(args.capture.read_bytes())
    args.receipt.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
