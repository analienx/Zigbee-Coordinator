#!/usr/bin/env python3
"""R4 isolated P7U ONLY: reserve resident 0xAC000 bootstrap and relocate NVS.

Source-only exact-anchor rewrite of disposable pinned TI 8.33 SDK/project.
No private P7U material, programmer, secret, CCFG patch or flash permission.
"""
import argparse
import hashlib
import json
from pathlib import Path

APP_HEADER_BYTES = 0x80
APP_END = 0xA0000
NVS_BEGIN = 0xA0000
NVS_END = 0xA4000
RESERVED_FROM = 0xA4000
FLASH_END = 0xB0000

NVS_OLD = "    NVS1.internalFlash.regionBase = 0xAA000;\n    NVS1.internalFlash.regionSize = 0x4000;"
NVS_NEW = "    NVS1.internalFlash.regionBase = 0xA0000;\n    NVS1.internalFlash.regionSize = 0x4000;"
LINKER_REPLACEMENTS = (
    ("#define FLASH_BASE              0x00000000", "#define FLASH_BASE              0x00000080"),
    ("#define FLASH_SIZE              0xAA000", "#define FLASH_SIZE              0x9FF80"),
    ("#define FLASH_NV_BASE           0xAA000", "#define FLASH_NV_BASE           0xA0000"),
    ("    .resetVecs: load > 0", "    .resetVecs: load > 0x80"),
)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def replace_once(text, before, after, label):
    if text.count(before) != 1 or after in text:
        raise ValueError("R4_BOOT_PRESERVE_" + label + "_SOURCE_DRIFT")
    return text.replace(before, after, 1)

def transform(syscfg, linker):
    """Validate BOTH original files before changing either one."""
    if not isinstance(syscfg, str) or not isinstance(linker, str):
        raise ValueError("R4_BOOT_PRESERVE_TEXT_REQUIRED")
    sc = syscfg.replace("\r\n", "\n")
    ld = linker.replace("\r\n", "\n")
    if "P7U_R4_BOOT_PRESERVE_NVS" in sc:
        raise ValueError("R4_BOOT_PRESERVE_ALREADY_APPLIED")
    if "if (deviceName.includes(\"R7\") || deviceName.includes(\"P7\"))" not in sc:
        raise ValueError("R4_BOOT_PRESERVE_TARGET_NOT_P7")
    sc = replace_once(sc, NVS_OLD, NVS_NEW, "SYSCFG_NVS")
    sc = sc.replace(NVS_NEW, "// P7U_R4_BOOT_PRESERVE_NVS: 0xA4000+ retained, not writable\n" + NVS_NEW, 1)
    for idx, (before, after) in enumerate(LINKER_REPLACEMENTS):
        ld = replace_once(ld, before, after, "LINKER_" + str(idx))
    if "#define FLASH_NV_SIZE           0x4000" not in ld:
        raise ValueError("R4_BOOT_PRESERVE_NV_SIZE_DRIFT")
    if "#define FLASH_LAST_BASE         0xAE000" not in ld:
        raise ValueError("R4_BOOT_PRESERVE_CCFG_SECTOR_DRIFT")
    if "#define FLASH_BASE              0x00000080" not in ld:
        raise ValueError("R4_BOOT_PRESERVE_APP_VECTOR_DRIFT")
    return sc, ld

def apply(syscfg_path, linker_path, receipt_path):
    if syscfg_path.resolve() == linker_path.resolve():
        raise ValueError("R4_BOOT_PRESERVE_INPUT_ALIAS")
    before_sc = syscfg_path.read_bytes()
    before_ld = linker_path.read_bytes()
    new_sc, new_ld = transform(before_sc.decode("utf8"), before_ld.decode("utf8"))
    syscfg_path.write_bytes(new_sc.encode("utf8"))
    linker_path.write_bytes(new_ld.encode("utf8"))
    report = {
        "schema": "r4-p7u-preserve-boot-nvs-source-v1",
        "mode": "SOURCE_ONLY_UNQUALIFIED",
        "project_syscfg_before_sha256": sha(before_sc),
        "project_syscfg_after_sha256": sha(new_sc.encode()),
        "sdk_linker_before_sha256": sha(before_ld),
        "sdk_linker_after_sha256": sha(new_ld.encode()),
        "app_range": ["0x00080", "0xA0000"],
        "app_header_range": ["0x00000", "0x00080"],
        "linker_vectors_expected": "0x00080",
        "header_schema": "fitted-20260311-first-stage-v1",
        "relocated_nvs_range": ["0xA0000", "0xA4000"],
        "reserved_existing_region": ["0xA4000", "0xB0000"],
        "resident_boot_stage": "0xAC000_PRESERVED_NOT_QUALIFIED",
        "installed_ccfg_to_be_written": False,
        "resident_stage_handoff_proven": False,
        "native_image_qualified": False,
        "flash_authorized": False,
    }
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return report

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--syscfg", required=True, type=Path)
    p.add_argument("--linker", required=True, type=Path)
    p.add_argument("--receipt", required=True, type=Path)
    args = p.parse_args()
    print(json.dumps(apply(args.syscfg, args.linker, args.receipt), sort_keys=True))

if __name__ == "__main__":
    main()
