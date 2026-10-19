#!/usr/bin/env python3
"""R4 T6 fail-closed guard for pinned TI legacy TC table migration.

The full P7U NV4 TC300 profile cannot compile TI's optional 5.30 NV
migration: its 8-bit index wraps above 255 and deletes security records
before checking new write durability. This source-only guard prevents that
unsafe path from entering a native build; it does NOT perform migration or
prove TC300 live table capacity.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

PIN = "3615ad5d3f4f271258d18a2f5ce1785064ff9a58"
REL = "source/ti/zstack/stack/sys/zglobals.c"
GUARD = (
    "#if defined(ZSTACK_5_30_NV_MIGRATION)\n"
    "#error R4_TC300_LEGACY_MIGRATION_FORBIDDEN_REQUIRE_OFFLINE_TRANSACTIONAL_QUALIFICATION\n"
    "#endif\n"
)
UNSAFE_LOOP = "uint8_t i = 0;\n    for( i = 0; i < gZDSECMGR_TC_DEVICE_MAX; i++ )"
UNSAFE_ORDER = "osal_nv_delete_ex(ZCD_NV_EX_TCLK_TABLE, i"


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def validate_profile(profile: dict) -> None:
    if (profile.get("profile_id") != "P7U_R4_FULL_NV4" or
            profile.get("source_sdk_sha") != PIN or
            profile.get("capacities", {}).get("trust_center_devices") != 300 or
            profile.get("flash", {}).get("nvocmp_pages") != 4 or
            profile.get("policies", {}).get("auto_nv_format") is not False or
            profile.get("policies", {}).get("auto_flash") is not False or
            profile.get("policies", {}).get("physical_flash_authorized") is not False or
            profile.get("policies", {}).get("network_forming_by_default") is not False or
            profile.get("policies", {}).get("full_b0_b4_sealed") is not False):
        raise ValueError("T6 full NV4 source/profile drift or unsafe authorization")


def migration_body(text: str) -> str:
    marker = "static void zgMigrateTo530SDK( void )\n{"
    terminator = "\n#endif // ZSTACK_5_30_NV_MIGRATION"
    if text.count(marker) != 1:
        raise ValueError("T6 legacy migration definition drift")
    start = text.index(marker)
    stop = text.find(terminator, start)
    if stop < 0:
        raise ValueError("T6 legacy migration terminator drift")
    return text[start:stop]


def guarded(raw: bytes, pinned: bytes) -> bytes:
    try:
        source = raw.decode("utf-8")
        upstream = pinned.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("T6 pinned source must be UTF-8") from error
    if (GUARD in source or source.count("static void zgMigrateTo530SDK( void )") != 2 or
            source.count(UNSAFE_LOOP) != 1 or source.count(UNSAFE_ORDER) != 1 or
            "#ifdef ZSTACK_5_30_NV_MIGRATION" not in source or
            migration_body(source) != migration_body(upstream)):
        raise ValueError("T6 expected pinned TI unsafe migration source drift")
    return (GUARD + source).encode("utf-8")


def git_blob(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def stage(sdk: Path, profile_file: Path, receipt: Path, b1_receipt: Path) -> dict:
    sdk = sdk.resolve(strict=True)
    if sdk == Path("/tmp") or Path("/tmp") not in sdk.parents:
        raise ValueError("T6 only permits disposable /tmp SDK")
    source_file = sdk / REL
    cursor = sdk
    for part in Path(REL).parts:
        cursor /= part
        if cursor.is_symlink():
            raise ValueError("T6 source parent/leaf symlink")
    if not source_file.is_file() or not source_file.resolve().is_relative_to(sdk):
        raise ValueError("T6 source absent or escaped checkout")
    if (receipt.exists() or receipt.is_symlink() or
            receipt.resolve() == source_file.resolve() or
            receipt.resolve() == b1_receipt.resolve()):
        raise ValueError("T6 receipt must be a new independent path")
    if b1_receipt.is_symlink() or not b1_receipt.is_file():
        raise ValueError("T6 bound B1/B3 receipt absent or linked")
    validate_profile(json.loads(profile_file.read_text()))
    head = subprocess.check_output(["git", "-C", str(sdk), "rev-parse", "HEAD"]).decode().strip()
    if head != PIN:
        raise ValueError("T6 SDK commit mismatch")
    pinned = subprocess.check_output(["git", "-C", str(sdk), "show", PIN + ":" + REL])
    actual = source_file.read_bytes()
    # All B1 and B3 overlays must finish their pinned preimage validation first.
    # Their authoritative receipt is rebound after controlled security fusion.
    bound = json.loads(b1_receipt.read_text())
    if (bound.get("schema") != "r4-b1-admission-overlay-v2" or
            bound.get("upstream_zglobals_blob") != git_blob(pinned) or
            bound.get("post_b1_security_fusion") != "B1_PLUS_SELECTED_B3_IMMUTABLE_INPUTS" or
            bound.get("b3_source_commit") != "b481e0beabf1966900644f69d7f5d024708ebf73" or
            bound.get("modified_zglobals_sha256") != digest(actual)):
        raise ValueError("T6 post-overlay B1/B3 source receipt drift")
    changed = guarded(actual, pinned)
    result = {
        "schema": "r4-t6-tc300-legacy-migration-prohibition-v2",
        "source_pin": PIN,
        "profile_id": "P7U_R4_FULL_NV4",
        "source_rel": REL,
        "before_sha256": digest(actual),
        "after_sha256": digest(changed),
        "b1_b3_receipt_before_sha256": digest(b1_receipt.read_bytes()),
        "tc_capacity_requested": 300,
        "legacy_migration_if_enabled": "COMPILE_TIME_ERROR",
        "actual_tc300_linked_capacity_proven": False,
        "installed_or_flash_authorized": False,
    }
    # Retain B1/B3 security ownership while rebinding the exact extra C guard.
    bound["modified_zglobals_sha256"] = digest(changed)
    bound["t6_legacy_migration_denial"] = {
        "pre_guard_sha256": digest(actual),
        "post_guard_sha256": digest(changed),
        "legacy_migration_if_enabled": "COMPILE_TIME_ERROR",
        "full_role_sealed": False,
    }
    # Disposable-only writes after source hash and both receipts validated.
    source_file.write_bytes(changed)
    b1_receipt.write_text(json.dumps(bound, sort_keys=True, indent=2) + "\n")
    receipt.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    return result


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--sdk", type=Path, required=True)
    p.add_argument("--profile", type=Path, required=True)
    p.add_argument("--receipt", type=Path, required=True)
    p.add_argument("--b1-overlay-receipt", type=Path, required=True)
    a = p.parse_args()
    print(json.dumps(stage(a.sdk, a.profile, a.receipt, a.b1_overlay_receipt), sort_keys=True))


if __name__ == "__main__":
    main()
