#!/usr/bin/env python3
"""The ONE full B0-B4 P7U candidate geometry and board-power source compositor.

Strictly a source-only operation on disposable hosted TI SDK/project copies.
It is *not* a native acceptance seal or an authorization to flash, format,
start a network or restore private NV. Other diagnostic profiles remain
separate and may not be promoted as FULL_B0_B4.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import board_profile
import nv4_source_overlay as nv4

DEFAULT_PROFILE = Path(__file__).resolve().parents[1] / "profiles/p7u-r4-full-nv4.json"
SDK_SHA = "3615ad5d3f4f271258d18a2f5ce1785064ff9a58"
CCFG_SHA = "fa750d46003f4cc059140ac75a83282ec61543b0d898c50cd2add61988c08b47"
APP_END = 0xA0000
NV_START, NV_END = 0xA6000, 0xAE000
CCFG_SECTOR_END = 0xB0000
CAPACITIES = {
    "source_routes": 192, "neighbors": 64, "nwk_routes": 128,
    "direct_children": 96, "associated_devices_slots": 97,
    "trust_center_devices": 300, "aps_table_entries": 3,
    "c_irq_stack_bytes": 4096,
}


def block(reason):
    raise ValueError("P7U_FULL_NV4_PROFILE_BLOCKED_" + reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def validate_profile(path: Path):
    if path.is_symlink() or not path.is_file():
        block("PROFILE_FILE_UNTRUSTED")
    try:
        profile = json.loads(path.read_bytes())
    except (ValueError, UnicodeDecodeError):
        block("PROFILE_JSON_INVALID")
    if not isinstance(profile, dict):
        block("PROFILE_MUST_BE_OBJECT")
    expected = {
        "schema": "p7u-r4-full-nv4-profile-v1",
        "profile_id": "P7U_R4_FULL_NV4",
        "board": "SLZB-06P7U-r1.73-CC2652P7",
        "source_sdk_sha": SDK_SHA,
        "boot": {"mode": "DIRECT_ROM", "vector_address": "0x00000"},
        "flash": {
            "sector_bytes": 0x2000, "app_start": "0x00000",
            "conservative_app_ceiling_exclusive": "0xA0000",
            "stock_nv4_start": "0xA6000",
            "stock_nv4_end_exclusive": "0xAE000",
            "nvocmp_pages": 4, "ccfg_sector_start": "0xAE000",
            "chip_end_exclusive": "0xB0000",
            "stock_20240716_ccfg_sha256": CCFG_SHA,
        },
        "board_power_reference": "vendor-20240716",
        "uart": {
            "owner": "TI_NPI_MT_ONLY", "peripheral": "UART0",
            "rx": "DIO12", "tx": "DIO13", "baud": 115200,
            "flow_control": False,
        },
        "capacities": CAPACITIES,
        "policies": {
            "b5_mto": False, "network_forming_by_default": False,
            "auto_nv_format": False, "auto_flash": False,
            "physical_flash_authorized": False, "full_b0_b4_sealed": False,
        },
    }
    if profile != expected:
        block("EXACT_PROFILE_SEMANTICS_DRIFT")
    return profile


def transform_pinned(syscfg: str, linker: str, projectspec: str):
    sc, ld, project = nv4.transform(syscfg, linker, projectspec)
    # The fitted NV4 pages start at A6000. Deliberately stop app at A0000,
    # leaving three unused sectors as a conservative linked size margin.
    before = "#define FLASH_SIZE              0xA6000"
    after = "#define FLASH_SIZE              0xA0000"
    if ld.count(before) != 1 or after in ld:
        block("CONSERVATIVE_LINKER_APP_CEILING_DRIFT")
    ld = ld.replace(before, after, 1)
    # The pinned TI P7 linker explicitly requests a 1024-byte C stack.
    # Qualify 4096 only if the real link XML confirms exactly 4096.
    if ld.count("--stack_size=1024") != 1 or "--stack_size=4096" in ld:
        block("CIRQ_LINKER_STACK_SOURCE_DRIFT")
    ld = ld.replace("--stack_size=1024", "--stack_size=4096", 1)
    if not all(part in ld for part in (
            "#define FLASH_NV_BASE           0xA6000",
            "#define FLASH_NV_SIZE           0x8000",
            "#define FLASH_LAST_BASE         0xAE000",
            "#define FLASH_LAST_SIZE         0x2000",
            "#define FLASH_BASE              0x00000000",
            "#define FLASH_SIZE              0xA0000",
            "--stack_size=4096")):
        block("LINKER_NV4_APP_OR_CCFG_DRIFT")
    if (sc.count("NVS1.internalFlash.regionBase = 0xA6000;") != 1 or
            sc.count("NVS1.internalFlash.regionSize = 0x8000;") != 1 or
            "-DNVOCMP_NVPAGES=4" not in project or
            "--define=NVOCMP_NVPAGES=4" not in project):
        block("SYSCFG_OR_PROJECT_NV4_DRIFT")
    return sc, ld, project


def apply_pinned(syscfg: Path, linker: Path, projectspec: Path,
                 receipt: Path, profile: Path = DEFAULT_PROFILE):
    validate_profile(profile)
    paths = (syscfg, linker, projectspec)
    resolved = [path.resolve() for path in (*paths, receipt, profile)]
    if len(set(resolved)) != len(resolved) or receipt.exists() or receipt.is_symlink():
        block("SOURCE_ALIAS_OR_RECEIPT_OVERWRITE")
    if any(path.is_symlink() or not path.is_file() for path in paths):
        block("SOURCE_FILE_UNTRUSTED")
    original = [path.read_bytes() for path in paths]
    if tuple(nv4.git_blob(raw) for raw in original) != nv4.UPSTREAM_GIT_BLOBS:
        block("PINNED_TI_SOURCE_BLOB_DRIFT")
    changed = transform_pinned(*(raw.decode("utf-8") for raw in original))
    report = {
        "schema": "p7u-r4-full-nv4-source-composition-v1",
        "profile_sha256": sha(profile.read_bytes()),
        "sdk_commit": SDK_SHA,
        "original_git_blobs": list(nv4.UPSTREAM_GIT_BLOBS),
        "original_source_sha256": [sha(raw) for raw in original],
        "composed_source_sha256": [sha(text.encode()) for text in changed],
        "app_link_end_exclusive": "0xA0000",
        "stock_nv4_range": ["0xA6000", "0xAE000"],
        "ccfg_erase_sector": ["0xAE000", "0xB0000"],
        "nvocmp_pages": 4,
        "native_compiled": False, "full_b0_b4_sealed": False,
        "flash_authorized": False,
    }
    for path, text in zip(paths, changed):
        path.write_text(text, encoding="utf-8", newline="\n")
    receipt.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def apply_imported(syscfg: Path, pinned_receipt: Path, receipt: Path,
                   profile: Path = DEFAULT_PROFILE):
    validate_profile(profile)
    if any(path.is_symlink() for path in (syscfg, pinned_receipt, receipt, profile)):
        block("IMPORTED_SOURCE_SYMLINK")
    if receipt.exists() or not syscfg.is_file() or not pinned_receipt.is_file():
        block("IMPORTED_INPUT_OR_RECEIPT_INVALID")
    prior = json.loads(pinned_receipt.read_bytes())
    if (prior.get("schema") != "p7u-r4-full-nv4-source-composition-v1" or
            prior.get("profile_sha256") != sha(profile.read_bytes()) or
            prior.get("sdk_commit") != SDK_SHA or
            prior.get("full_b0_b4_sealed") is not False):
        block("PINNED_SOURCE_RECEIPT_UNBOUND")
    source = syscfg.read_bytes()
    normalized = source.replace(b"\r\n", b"\n")
    if sha(normalized) != prior["composed_source_sha256"][0]:
        block("CCS_IMPORT_SOURCE_DIFFERS_FROM_PINNED_NV4")
    power = board_profile.settings(reference="vendor-20240716")
    result = board_profile.transform(normalized.decode(), power, transport_only=False)
    if (result.count("device.forceVddr = true;") != 1 or
            result.count("device.enableDCDC = true;") != 1 or
            result.count("NVS1.internalFlash.regionBase = 0xA6000;") != 1 or
            result.count("NVS1.internalFlash.regionSize = 0x8000;") != 1):
        block("CURRENT_BOARD_NV4_POWER_COMPOSITION_DRIFT")
    report = {
        "schema": "p7u-r4-full-nv4-imported-board-v1",
        "source_pin_receipt_sha256": sha(pinned_receipt.read_bytes()),
        "reference_power": "vendor-20240716",
        "ccfg_expected_sha256": CCFG_SHA,
        "input_sha256": sha(source),
        "output_sha256": sha(result.encode()),
        "source_only": True, "native_verified": False,
        "full_b0_b4_sealed": False, "flash_authorized": False,
    }
    syscfg.write_text(result, encoding="utf-8", newline="\n")
    receipt.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", choices=("pinned-sources", "imported-board"), required=True)
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--syscfg", type=Path, required=True)
    parser.add_argument("--linker", type=Path)
    parser.add_argument("--projectspec", type=Path)
    parser.add_argument("--pinned-receipt", type=Path)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    if args.stage == "pinned-sources":
        if args.linker is None or args.projectspec is None or args.pinned_receipt:
            parser.error("pinned-sources needs linker and projectspec only")
        result = apply_pinned(args.syscfg, args.linker, args.projectspec,
                              args.receipt, args.profile)
    else:
        if not args.pinned_receipt or args.linker or args.projectspec:
            parser.error("imported-board needs pinned-receipt only")
        result = apply_imported(args.syscfg, args.pinned_receipt,
                                args.receipt, args.profile)
    print(json.dumps({"schema": result["schema"], "flash_authorized": False}))


if __name__ == "__main__":
    main()
