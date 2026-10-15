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
KIT_FILES = frozenset((
    "candidate.APP-ONLY-NOT-FLASHABLE.hex", "candidate.source.json", "candidate.plan.json",
    "stock-20240710.APP-ONLY-ROLLBACK-NOT-FLASHABLE.hex", "stock-20240710.source.json",
    "stock-20240710.plan.json", "stock-20240710.receipt.json",
))


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
    require(type(manifest) is dict and type(manifest.get("files")) is dict,
            "RC1_MANIFEST_SCHEMA_INVALID")
    require(manifest["flash_authorized"] is False,"RC1_PACKAGE_FLASH_PERMISSION")
    require(manifest["qualification"] ==
            "SOFTWARE_RELEASE_CANDIDATE_READY_FOR_SPARE_P7U_HARDWARE_QUALIFICATION_ONLY",
            "RC1_NOT_SOFTWARE_ONLY")
    file_names=set(manifest["files"])
    require(file_names == KIT_FILES,"RC1_REQUIRED_FILE_SET_CHANGED")
    require(file_names == {p.name for p in directory.iterdir()}-{"RC1-MANIFEST.json","SHA256SUMS"},
            "RC1_DIRECTORY_CONTAINS_UNDECLARED_FILE")
    for name, entry in manifest["files"].items():
        require((directory/name).is_file() and not (directory/name).is_symlink(),
                "RC1_PACKAGE_FILE_NOT_REGULAR")
        data=(directory/name).read_bytes()
        require(type(entry) is dict and core.sha(data)==entry.get("sha256")
                and len(data)==entry.get("size"),
                "RC1_PACKAGE_HASH_MISMATCH")
    expected="".join(f"{manifest['files'][name]['sha256']}  {name}\n"
                     for name in sorted(file_names))
    require((directory/"SHA256SUMS").read_text()==expected,
            "RC1_SHA256SUMS_MISMATCH")
    # Fail if a manifest from another radio, build, or profile is substituted.
    require(manifest["model"]=="SMLIGHT_SLZB_06P7U" and
            manifest["profile"] in PROFILES and manifest["release"]==VERSION
            and manifest.get("radio")=="CC2652P7"
            and manifest.get("schema")=="slzb-06p7u-internal-software-first-release-rc1-v1",
            "RC1_PACKAGE_IDENTITY_CHANGED")
    require(all(manifest.get(key) is False for key in (
        "isolated_p7u_rom_bsl_entered_in_hardware", "physical_firmware_write_performed",
        "physical_stock_restore_verified", "production_network_migration_qualified")),
        "RC1_UNSUPPORTED_HARDWARE_QUALIFICATION_CLAIM")
    candidate = core.load_bundle(
        (directory/"candidate.APP-ONLY-NOT-FLASHABLE.hex").read_bytes(),
        core.load_json(directory/"candidate.source.json"),
        core.load_json(directory/"candidate.plan.json"))
    fallback = core.load_bundle(
        (directory/"stock-20240710.APP-ONLY-ROLLBACK-NOT-FLASHABLE.hex").read_bytes(),
        core.load_json(directory/"stock-20240710.source.json"),
        core.load_json(directory/"stock-20240710.plan.json"))
    require(candidate.profile == fallback.profile == manifest["profile"],
            "RC1_PACKAGE_PROFILE_MISMATCH")
    require([addr for addr, _ in candidate.sectors] ==
            [addr for addr, _ in fallback.sectors] == list(range(0,23*core.gate.SECTOR,core.gate.SECTOR))
            and manifest.get("fully_covered_application_sectors")==23,
            "RC1_NOT_EXACTLY_23_SECTORS")
    require(fallback.hex_sha256 == stock.ROLLBACK_APP_SHA256
            and manifest.get("vendor_original_SHA256") == stock.VENDOR_SHA,
            "RC1_STOCK_ROLLBACK_NOT_PINNED")
    require(manifest.get("release_custom_app_hex_sha256") == candidate.hex_sha256
            and manifest.get("release_stock_restore_app_hex_sha256") == fallback.hex_sha256,
            "RC1_MANIFEST_IMAGE_HASH_MISMATCH")
    receipt = core.load_json(directory/"stock-20240710.receipt.json")
    require(receipt.get("profile")==manifest["profile"]
            and receipt.get("manufacturer_container_sha256")==stock.VENDOR_SHA
            and receipt.get("rollback_app_only_hex_sha256")==fallback.hex_sha256
            and receipt.get("sector_plan_sha256")==fallback.plan_sha256
            and receipt.get("custom_tail_cleanup_sector_start")=="0x2C000"
            and receipt.get("custom_tail_cleanup_erased_to_all_ff") is True
            and receipt.get("rom_rollback_physically_tested") is False
            and receipt.get("flash_authorized") is False,
            "RC1_STOCK_RECEIPT_MISMATCH")
    provenance = manifest.get("native_ccs_provenance")
    require(type(provenance) is dict
            and provenance.get("native_build_commit")==manifest.get("git_commit")
            and type(manifest.get("git_commit")) is str and len(manifest["git_commit"])==40
            and all(c in "0123456789abcdef" for c in manifest["git_commit"])
            and provenance.get("native_app_hex_sha256")==candidate.hex_sha256
            and provenance.get("native_sector_plan_sha256")==candidate.plan_sha256
            and provenance.get("candidate_origin_exact_ccs_native") is True
            and provenance.get("native_g7_f07_guards_verified") is True
            and provenance.get("ccfg_and_bsl_exact_native") is True
            and provenance.get("hardware_qualification") is False
            and provenance.get("flash_authorized") is False,
            "RC1_NATIVE_PROVENANCE_MISMATCH")
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
