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


def remap_stock_overlay(syscfg: str, linker: str, project: str) -> tuple[str, str, str]:
    """Existing pinned overlay v1 -> conservative A0000 app -> A4000 NV4."""
    if ("#define FLASH_SIZE              0xA6000" not in linker or
            "#define FLASH_NV_BASE           0xA6000" not in linker or
            "#define FLASH_LAST_BASE         0xAE000" not in linker):
        reject("LEGACY_OVERLAY_LINKER_GEOMETRY")
    bounded = _once(linker, "#define FLASH_SIZE              0xA6000",
                    "#define FLASH_SIZE              0xA0000",
                    "CONSERVATIVE_APP_CEILING")
    return remap_composed(syscfg, bounded, project)


def remap_pinned_paths(syscfg: Path, linker: Path, project: Path,
                       prior_receipt: Path, receipt: Path) -> dict:
    """Apply to disposable, already-pinned TI source only; never a ROM image."""
    paths = [syscfg, linker, project, prior_receipt, receipt]
    if len({p.resolve() for p in paths}) != len(paths):
        reject("SOURCE_PATH_ALIAS")
    if (receipt.exists() or any(p.is_symlink() or not p.is_file()
                                for p in paths[:-1])):
        reject("SOURCE_MISSING_OR_UNTRUSTED")
    prior = json.loads(prior_receipt.read_bytes())
    originals = [p.read_bytes() for p in paths[:3]]
    if (prior.get("schema") != "r4-stock-p7u-nv4-source-overlay-v1" or
            prior.get("flash_authorized") is not False or
            prior.get("source_after_sha256") != [sha(x) for x in originals]):
        reject("UNBOUND_PINNED_SOURCE_RECEIPT")
    changed = remap_stock_overlay(*(x.decode("utf-8") for x in originals))
    report = {
        "schema": "p7u-stock-20260311-source-remap-v1",
        "prior_source_receipt_sha256": sha(prior_receipt.read_bytes()),
        "input_source_sha256": [sha(x) for x in originals],
        "upstream_overlay_schema": prior["schema"],
        "output_source_sha256": [sha(x.encode()) for x in changed],
        "nv_region": [hex(NV_BASE), hex(NV_END)],
        "app_ceiling": "0xa0000",
        "resident_boot_unchanged": True,
        "ccfg_unchanged": True,
        "native_compiled": False,
        "same_board_capture_required_before_hardware": True,
        "flash_authorized": False,
    }
    # The source copies are disposable SDK staging material, not user files.
    for path, value in zip(paths[:3], changed):
        path.write_text(value, encoding="utf-8", newline="\n")
    receipt.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--capture", type=Path)
    group.add_argument("--syscfg", type=Path)
    parser.add_argument("--linker", type=Path)
    parser.add_argument("--projectspec", type=Path)
    parser.add_argument("--prior-receipt", type=Path)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    if args.receipt.exists() or args.receipt.is_symlink():
        reject("RECEIPT_ALREADY_EXISTS")
    if args.capture is not None:
        if any(p is not None for p in
               (args.linker, args.projectspec, args.prior_receipt)):
            reject("MIXED_CAPTURE_AND_SOURCE_ARGS")
        report = check_capture(args.capture.read_bytes())
        args.receipt.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    else:
        if any(p is None for p in
               (args.linker, args.projectspec, args.prior_receipt)):
            reject("SOURCE_ARGS_INCOMPLETE")
        report = remap_pinned_paths(args.syscfg, args.linker,
                                    args.projectspec, args.prior_receipt,
                                    args.receipt)
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
