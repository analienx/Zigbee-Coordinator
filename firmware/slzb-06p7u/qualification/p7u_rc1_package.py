#!/usr/bin/env python3
"""Offline first-release engineering candidate and stock rollback kit.

Exports validated custom APP-only HEX, stock APP-only HEX, exact sector plan,
hashes and one manifest. NEVER talks to USB, LAN, a radio, HA or Z2M.
Do not interpret first-release SOFTWARE_RC as hardware flash authorization.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import p7u_strict_sector_writer as core
import p7u_stock_rollback as stock
import p7u_rc1_native_provenance as native

VERSION = "0.1.0-rc1"
PROFILES = ("p7u-f07-stock", "p7u-cap192-f07")


def require(condition, error):
    if not condition:
        raise ValueError(error)


def build(full_hex: bytes, official_vendor: bytes, profile: str, git_sha: str) -> tuple[dict, dict[str, bytes]]:
    require(profile in PROFILES, "RC1_WRONG_PROFILE")
    require(len(git_sha) == 40 and all(ch in "0123456789abcdef" for ch in git_sha),
            "RC1_INVALID_SOURCE_COMMIT")
    data = core.gate.parse_hex(full_hex)
    qualified = core.gate.candidate_audit(data,profile)
    custom = core.gate.application_only_hex(data,profile)
    qualified["derived_app_only_hex_sha256"] = core.sha(custom)
    qualified["derived_app_only_never_flash_with_bank_erase"] = True
    qualified["qualification"] = "SOURCE_HEX_BSL_GEOMETRY_PASS_NOT_FLASHABLE"
    custom_plan = core.sector.plan(custom,qualified)
    custom_bundle=core.load_bundle(custom,qualified,custom_plan)

    fallback,source,stock_plan,receipt = stock.extract(official_vendor,profile)
    stock_bundle=core.load_bundle(fallback,source,stock_plan)
    require(custom_bundle.hex_sha256 != stock_bundle.hex_sha256,
            "RC1_CANDIDATE_EQUALS_STOCK")
    require(len(custom_bundle.sectors) == 23 and len(stock_bundle.sectors) == 23,
            "RC1_NOT_EXACTLY_23_SECTORS")
    require([a for a,_ in custom_bundle.sectors] ==
            [a for a,_ in stock_bundle.sectors] ==
            list(range(0,23*core.gate.SECTOR,core.gate.SECTOR)),
            "RC1_STOCK_CUSTOM_SECTOR_SET_MISMATCH")
    require(stock_bundle.sectors[-1] == (0x2C000, b"\xff"*core.gate.SECTOR),
            "RC1_STOCK_TAIL_NOT_CLEARED_TO_FF")
    require(max(a for a,_ in custom_bundle.sectors)+core.gate.SECTOR <= core.gate.NV5_BASE,
            "RC1_SECTOR_TOUCHES_NV5")
    require(qualified["ccfg_sha256"] == core.gate.VENDOR_CCFG_SHA256,
            "RC1_CCFG_NOT_VENDOR_MATCH")
    require(qualified["bootloader_enabled"] and qualified["rom_backdoor_enabled"],
            "RC1_LOST_ROM_BSL_BACKDOOR")
    require(custom_plan["flash_authorized"] is False and
            stock_plan["flash_authorized"] is False,
            "RC1_UNEXPECTED_FLASH_PERMISSION")

    items={
        "candidate.APP-ONLY-NOT-FLASHABLE.hex": custom,
        "candidate.source.json": (json.dumps(qualified,sort_keys=True,indent=2)+"\n").encode(),
        "candidate.plan.json": (json.dumps(custom_plan,sort_keys=True,indent=2)+"\n").encode(),
        "stock-20240710.APP-ONLY-ROLLBACK-NOT-FLASHABLE.hex":fallback,
        "stock-20240710.source.json":(json.dumps(source,sort_keys=True,indent=2)+"\n").encode(),
        "stock-20240710.plan.json":(json.dumps(stock_plan,sort_keys=True,indent=2)+"\n").encode(),
        "stock-20240710.receipt.json":(json.dumps(receipt,sort_keys=True,indent=2)+"\n").encode(),
    }
    files={name:{"sha256":core.sha(blob),"size":len(blob)} for name,blob in items.items()}
    manifest={
        "schema":"slzb-06p7u-internal-software-first-release-rc1-v1",
        "release":VERSION,
        "model":"SMLIGHT_SLZB_06P7U",
        "radio":"CC2652P7",
        "profile":profile,
        "git_commit":git_sha,
        "vendor_original_SHA256":stock.VENDOR_SHA,
        "vendor_20240710_verified_and_extracted":True,
        "release_custom_app_hex_sha256":core.sha(custom),
        "release_stock_restore_app_hex_sha256":core.sha(fallback),
        "fully_covered_application_sectors":23,
        "stock_extra_tail_sector_erased": "0x2C000",
        "configured_4KiB_or_8KiB_flash_sector":"8KiB_P7U_ONLY",
        "never_program_ccfg_or_nv":True,
        "rom_backdoor_code_checked":True,
        "isolated_p7u_rom_bsl_entered_in_hardware":False,
        "physical_firmware_write_performed":False,
        "physical_stock_restore_verified":False,
        "production_network_migration_qualified":False,
        "flash_authorized":False,
        "qualification":"SOFTWARE_RELEASE_CANDIDATE_READY_FOR_SPARE_P7U_HARDWARE_QUALIFICATION_ONLY",
        "files":files,
    }
    return manifest,items


def verify_directory(directory: Path) -> dict:
    manifest=json.loads((directory/"RC1-MANIFEST.json").read_text())
    require(manifest["flash_authorized"] is False,"RC1_PACKAGE_FLASH_PERMISSION")
    require(manifest["qualification"] ==
            "SOFTWARE_RELEASE_CANDIDATE_READY_FOR_SPARE_P7U_HARDWARE_QUALIFICATION_ONLY",
            "RC1_NOT_SOFTWARE_ONLY")
    file_names=set(manifest["files"])
    require(file_names == {p.name for p in directory.iterdir()}-{"RC1-MANIFEST.json","SHA256SUMS"},
            "RC1_DIRECTORY_CONTAINS_UNDECLARED_FILE")
    for name, entry in manifest["files"].items():
        data=(directory/name).read_bytes()
        require(core.sha(data)==entry["sha256"] and len(data)==entry["size"],
                "RC1_PACKAGE_HASH_MISMATCH")
    expected="".join(f"{manifest['files'][name]['sha256']}  {name}\n"
                     for name in sorted(file_names))
    require((directory/"SHA256SUMS").read_text()==expected,
            "RC1_SHA256SUMS_MISMATCH")
    # Fail if a manifest from another radio, build, or profile is substituted.
    require(manifest["model"]=="SMLIGHT_SLZB_06P7U" and
            manifest["profile"] in PROFILES and manifest["release"]==VERSION,
            "RC1_PACKAGE_IDENTITY_CHANGED")
    return {"status":"RC1_PACKAGE_SELF_VERIFIED_SOFTWARE_ONLY",
            "profile":manifest["profile"],"files":len(file_names),
            "flash_authorized":False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--native-full-hex",type=Path,required=True)
    p.add_argument("--official-stock-bin",type=Path,required=True)
    p.add_argument("--profile",choices=PROFILES,required=True)
    p.add_argument("--git-commit",required=True)
    p.add_argument("--native-evidence-dir",type=Path,required=True,
                   help="Exact CCS run BASE-VS-DIAG-EVIDENCE directory containing candidate-sha.txt")
    p.add_argument("--output-dir",type=Path,required=True)
    args=p.parse_args()
    require(not args.output_dir.exists(),"RC1_OUTPUT_DIRECTORY_MUST_BE_NEW")
    native_full_hex=args.native_full_hex.read_bytes()
    m,items=build(native_full_hex,args.official_stock_bin.read_bytes(),
                  args.profile,args.git_commit.lower())
    m["native_ccs_provenance"]=native.qualify(args.native_evidence_dir,native_full_hex,
                                              args.profile,args.git_commit)
    args.output_dir.mkdir(parents=True)
    for name,blob in items.items():
        (args.output_dir/name).write_bytes(blob)
    (args.output_dir/"RC1-MANIFEST.json").write_text(json.dumps(m,sort_keys=True,indent=2)+"\n")
    (args.output_dir/"SHA256SUMS").write_text("".join(
        f"{m['files'][name]['sha256']}  {name}\n" for name in sorted(items)))
    print(json.dumps(verify_directory(args.output_dir),sort_keys=True))


if __name__=="__main__":
    main()
