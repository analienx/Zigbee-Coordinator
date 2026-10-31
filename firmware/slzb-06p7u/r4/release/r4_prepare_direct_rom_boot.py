#!/usr/bin/env python3
"""Source-only P7U R4 direct-ROM-boot linker/NVS layout.

Separately opt-in fallback to MCUboot-signing route: link raw R4 vector table
at 0x00000000 and preserve relocated internal NVS 0xA0000..0xA3FFF.
Does not change device CCFG, does not flash, and never authorizes flashing.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import r4_preserve_resident_boot_nvs as preserve

REPLACEMENTS = (
    ("#define FLASH_BASE              0x00000080",
     "#define FLASH_BASE              0x00000000"),
    ("#define FLASH_SIZE              0x9FF80",
     "#define FLASH_SIZE              0xA0000"),
    ("    .resetVecs: load > 0x80\n",
     "    .resetVecs: load > 0\n"),
)


def transform(syscfg: str, linker: str) -> tuple[str, str]:
    sc, ld = preserve.transform(syscfg, linker)
    for i, (before, after) in enumerate(REPLACEMENTS):
        ld = preserve.replace_once(ld, before, after, "DIRECT_ROM_LINKER_%d" % i)
    if "#define FLASH_NV_BASE           0xA0000" not in ld:
        raise ValueError("R4_DIRECT_ROM_NVS_BASE_MISMATCH")
    if "#define FLASH_LAST_BASE         0xAE000" not in ld:
        raise ValueError("R4_DIRECT_ROM_TOP_SECTOR_MISMATCH")
    if "#define FLASH_BASE              0x00000080" in ld:
        raise ValueError("R4_DIRECT_ROM_STILL_MCUBOOT_RELOCATED")
    return sc, ld


def apply(syscfg_path: Path, linker_path: Path, receipt_path: Path) -> dict:
    if syscfg_path.resolve() == linker_path.resolve():
        raise ValueError("R4_DIRECT_ROM_INPUT_ALIAS")
    a, b = syscfg_path.read_bytes(), linker_path.read_bytes()
    sc, ld = transform(a.decode("utf8"), b.decode("utf8"))
    report = {
        "schema": "r4-p7u-direct-rom-source-v1",
        "mode": "SOURCE_ONLY_UNQUALIFIED",
        "original_syscfg_sha256": hashlib.sha256(a).hexdigest(),
        "original_linker_sha256": hashlib.sha256(b).hexdigest(),
        "result_syscfg_sha256": hashlib.sha256(sc.encode()).hexdigest(),
        "result_linker_sha256": hashlib.sha256(ld.encode()).hexdigest(),
        "vector_table": "0x00000000",
        "app_range": ["0x00000000", "0x000A0000"],
        "nvs_range": ["0x000A0000", "0x000A4000"],
        "unchanged_resident_boot_sector": "0x000AC000",
        "unchanged_factory_ccfg_sector": "0x000AE000",
        "ccfg_boot_address_needed": "0x00000000",
        "current_fitted_ccfg_boot_address": "0x000AC000",
        "ccfg_change_prepared_only": True,
        "ccfg_recovery_qualified": False,
        "native_image_verified": False,
        "flash_performed": False,
        "flash_authorized": False,
    }
    # Perform both input checks and processing before changing any source.
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    if receipt_path.exists() or receipt_path.is_symlink():
        raise ValueError("R4_DIRECT_ROM_RECEIPT_ALREADY_EXISTS")
    syscfg_path.write_text(sc)
    linker_path.write_text(ld)
    receipt_path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return report


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--syscfg", type=Path, required=True)
    p.add_argument("--linker", type=Path, required=True)
    p.add_argument("--receipt", type=Path, required=True)
    a = p.parse_args()
    print(json.dumps(apply(a.syscfg, a.linker, a.receipt), sort_keys=True))


if __name__ == "__main__":
    main()
