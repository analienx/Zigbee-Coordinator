"""Export security NV layouts from the actual ARM build, without running firmware.

Stage after all overlays and before the final source snapshot. The one retained
constant is compiled in zd_sec_mgr.c, where the private ZDSecMgrEntry_t exists.
Audit reads that constant from the real linked ARM ELF. This is ABI evidence,
not evidence that any private capture has passed the security preflight.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

SDK_SHA = "3615ad5d3f4f271258d18a2f5ce1785064ff9a58"
SOURCE = "source/ti/zstack/stack/zdo/zd_sec_mgr.c"
SYMBOL = "r4_stock20260311_security_abi"
MAGIC = 0x52345341
FIELDS = {
    "nwkIB_t": ("nwkDevAddress", "nwkLogicalChannel", "nwkCoordAddress",
                "nwkPanId", "nwkState", "extendedPANID", "nwkKeyLoaded",
                "nwkCoordExtAddress", "SecurityLevel", "channelList",
                "nwkManagerAddr", "nwkUpdateId", "nwkProtocolVersion"),
    "nwkKeyDesc": ("keySeqNum", "key"),
    "nwkActiveKeyItems": ("active", "frameCounter"),
    "nwkSecMaterialDesc_t": ("FrameCounter", "extendedPanID"),
    "APSME_TCLinkKeyNVEntry_t": ("txFrmCntr", "rxFrmCntr", "extAddr",
                               "keyAttributes", "keyType", "SeedShift", "IcIndex"),
    "APSME_ApsLinkKeyNVEntry_t": ("key", "txFrmCntr", "rxFrmCntr"),
    "nvDeviceListHdr_t": ("numRecs",),
    "ZDSecMgrEntry_t": ("ami", "keyNvId", "authenticateOption"),
    "AddrMgrEntry_t": ("user", "nwkAddr", "extAddr"),
}
CONSTANTS = ("NWK_ROUTER", "ZDSECMGR_TC_DEVICE_MAX", "ZDSECMGR_ENTRY_MAX",
             "MAX_NWK_SEC_MATERIAL_TABLE_ENTRIES", "MAX_APS_FRAMECOUNTER_CHANGES",
             "MAX_TCLK_FRAMECOUNTER_CHANGES", "NWK_MAX_ADDRESSES", "ADDRMGR_USER_SECURITY")
# AddrMgr's final index is an API lookup result, never serialized in NV.
SERIALIZED_SIZES = {"AddrMgrEntry_t": "offsetof(AddrMgrEntry_t, index)"}


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def pin(value: str, length: int = 64) -> str:
    if not isinstance(value, str) or re.fullmatch("[0-9a-f]{%d}" % length, value) is None:
        raise ValueError("SECURITY_ABI_PIN_INVALID")
    return value


def check_profile(raw: bytes) -> dict:
    profile = json.loads(raw)
    flash = profile.get("flash", {})
    if (profile.get("profile_id") != "P7U_R4_STOCK_20260311_NV4" or
            profile.get("source_sdk_sha") != SDK_SHA or
            flash.get("stock_nv4_start") != "0xA4000" or
            flash.get("stock_nv4_end_exclusive") != "0xAC000" or
            profile.get("capacities", {}).get("trust_center_devices") != 300 or
            profile.get("capacities", {}).get("aps_table_entries") != 3):
        raise ValueError("SECURITY_ABI_PROFILE_MISMATCH")
    return profile


def declaration() -> str:
    expressions = ["0x%08Xu" % MAGIC, "1u"]
    for name, fields in FIELDS.items():
        expressions.append(SERIALIZED_SIZES.get(name, "sizeof(%s)" % name))
        for field in fields:
            expressions.extend(("offsetof(%s, %s)" % (name, field),
                                "sizeof(((%s *)0)->%s)" % (name, field)))
    expressions.extend(CONSTANTS)
    return ("\n/* Read-only native ABI witness; no runtime initialization. */\n"
            "#include <stddef.h>\n#include \"nwk_globals.h\"\n#include \"addr_mgr.h\"\n"
            "const uint32_t " + SYMBOL + "[] __attribute__((used, retain)) = {\n  " +
            ",\n  ".join(expressions) + "\n};\n")


def decode_words(raw: bytes) -> dict:
    count = 2 + sum(1 + 2 * len(fields) for fields in FIELDS.values()) + len(CONSTANTS)
    if len(raw) != count * 4:
        raise ValueError("SECURITY_ABI_NATIVE_SYMBOL_LENGTH")
    values = iter(struct.unpack("<%dI" % count, raw))
    if (next(values), next(values)) != (MAGIC, 1):
        raise ValueError("SECURITY_ABI_NATIVE_SYMBOL_VERSION")
    layouts = {}
    for name, fields in FIELDS.items():
        size = next(values)
        if not 1 <= size <= 1024:
            raise ValueError("SECURITY_ABI_NATIVE_STRUCT_SIZE")
        layout = {field: [next(values), next(values)] for field in fields}
        for offset, width in layout.values():
            if not 1 <= width <= size or offset + width > size:
                raise ValueError("SECURITY_ABI_NATIVE_FIELD_RANGE")
        layouts[name] = {"size": size, "fields": layout}
    constants = {name: next(values) for name in CONSTANTS}
    if (constants["ZDSECMGR_TC_DEVICE_MAX"] != 300 or
            constants["ZDSECMGR_ENTRY_MAX"] != 3 or
            constants["MAX_NWK_SEC_MATERIAL_TABLE_ENTRIES"] != 5 or
            constants["NWK_MAX_ADDRESSES"] != 406 or
            constants["ADDRMGR_USER_SECURITY"] != 2):
        raise ValueError("SECURITY_ABI_NATIVE_CAPACITY_MISMATCH")
    return {"structs": layouts, "constants": constants}


def stage(sdk: Path, overlay_path: Path, profile_path: Path, receipt: Path,
          source_sha: str) -> dict:
    pin(source_sha, 40)
    profile_raw = profile_path.read_bytes()
    check_profile(profile_raw)
    source = sdk / SOURCE
    if any(path.is_symlink() for path in (source, overlay_path, profile_path, receipt)):
        raise ValueError("SECURITY_ABI_SYMLINK_BLOCKED")
    if receipt.exists():
        raise ValueError("SECURITY_ABI_OUTPUT_EXISTS")
    original = source.read_bytes()
    prior_raw = overlay_path.read_bytes()
    prior = json.loads(prior_raw)
    if (prior.get("schema") != "r4-b1-admission-overlay-v2" or
            prior.get("modified_security_sha256") != sha(original) or
            prior.get("additional_source_bindings", {}).get("modified_security_sha256") != SOURCE or
            SYMBOL.encode() in original):
        raise ValueError("SECURITY_ABI_STAGE_PREIMAGE_MISMATCH")
    appended = original + declaration().encode()
    prior["modified_security_sha256"] = sha(appended)
    prior["stock20260311_security_native_abi"] = SYMBOL
    result = {"schema": "p7u-security-native-abi-stage-v1", "source_sha": source_sha,
              "sdk_sha": SDK_SHA, "profile_sha256": sha(profile_raw),
              "source_before_sha256": sha(original), "source_after_sha256": sha(appended),
              "b1_overlay_before_sha256": sha(prior_raw),
              "b1_overlay_after_sha256": sha(canonical(prior)),
              "declaration_sha256": sha(declaration().encode()),
              "symbol": SYMBOL, "flash_authorized": False}
    source.write_bytes(appended)
    overlay_path.write_bytes(canonical(prior))
    receipt.parent.mkdir(parents=True, exist_ok=True)
    receipt.write_bytes(canonical(result))
    return result


def audit(artifacts: Path, stage_path: Path, profile_path: Path, receipt: Path) -> dict:
    import native_profile_audit
    if receipt.exists() or receipt.is_symlink():
        raise ValueError("SECURITY_ABI_OUTPUT_EXISTS")
    staged = json.loads(stage_path.read_bytes())
    profile_raw = profile_path.read_bytes()
    check_profile(profile_raw)
    if (staged.get("schema") != "p7u-security-native-abi-stage-v1" or
            staged.get("sdk_sha") != SDK_SHA or
            staged.get("profile_sha256") != sha(profile_raw) or
            staged.get("declaration_sha256") != sha(declaration().encode()) or
            staged.get("symbol") != SYMBOL or staged.get("flash_authorized") is not False):
        raise ValueError("SECURITY_ABI_STAGE_RECEIPT_MISMATCH")
    pin(staged.get("source_sha"), 40)
    manifest_raw = (artifacts / "manifest.json").read_bytes()
    manifest = json.loads(manifest_raw)
    info = manifest["files"]["elf"]
    filename = info["file"]
    if not isinstance(filename, str) or Path(filename).name != filename or "\\" in filename:
        raise ValueError("SECURITY_ABI_ELF_PATH_INVALID")
    elf = artifacts / filename
    if elf.is_symlink() or sha(elf.read_bytes()) != info["sha256"]:
        raise ValueError("SECURITY_ABI_ELF_MANIFEST_MISMATCH")
    symbols = native_profile_audit.elf_symbols(elf)
    selected = symbols.get(SYMBOL)
    if (not selected or selected["function"] or
            any(name.startswith(SYMBOL + "@") for name in symbols)):
        raise ValueError("SECURITY_ABI_NATIVE_SYMBOL_MISSING_OR_AMBIGUOUS")
    result = {"schema": "p7u-security-native-abi-v1",
              "status": "ACTUAL_ARM_ELF_SERIALIZED_LAYOUTS_EXTRACTED",
              "source_sha": staged["source_sha"], "sdk_sha": SDK_SHA,
              "profile_sha256": sha(profile_raw), "byte_order": "little",
              "native_manifest_sha256": sha(manifest_raw), "native_elf_sha256": info["sha256"],
              "stage_receipt_sha256": sha(stage_path.read_bytes()),
              **decode_words(selected["bytes"]), "flash_authorized": False}
    receipt.parent.mkdir(parents=True, exist_ok=True)
    receipt.write_bytes(canonical(result))
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    first = sub.add_parser("stage")
    first.add_argument("--sdk", type=Path, required=True)
    first.add_argument("--b1-overlay-receipt", type=Path, required=True)
    first.add_argument("--source-sha", required=True)
    second = sub.add_parser("audit")
    second.add_argument("--artifacts", type=Path, required=True)
    second.add_argument("--stage-receipt", type=Path, required=True)
    for command in (first, second):
        command.add_argument("--profile", type=Path, required=True)
        command.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "stage":
        stage(args.sdk, args.b1_overlay_receipt, args.profile, args.receipt, args.source_sha)
    else:
        audit(args.artifacts, args.stage_receipt, args.profile, args.receipt)
    print("SECURITY_NATIVE_ABI_" + args.command.upper() + "_COMPLETE_NO_PRIVATE_EVIDENCE")


if __name__ == "__main__":
    main()
