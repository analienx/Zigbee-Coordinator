#!/usr/bin/env python3
"""Same-unit original app rollback, from pinned source AND two verified captures.

Reuses the unchanged 23-sector app writer. No NV/CCFG write, reset or retry.
This is separate from the R2 kit's immutable 20240710 paired fallback.
"""
from __future__ import annotations

import re

import p7u_nv_recovery as backup
import p7u_stock_rollback as stock
import p7u_strict_sector_writer as core
from p7u_rom_lowlevel import APP_SECTOR_ADDRESSES
from p7u_rom_transport import LiveSmlightSession, normalized_mac

OUTSIDE = tuple(range(0x2E000, core.gate.RADIO_SIZE, core.gate.SECTOR))


def original_bundle(original, copy, vendor):
    manifest, data = backup.verified_pair(original, copy)
    proof = backup.known_original_application(data, vendor)
    image, source, plan, receipt = stock.extract_original(vendor, "p7u-cap192-f07")
    bundle = core.load_bundle(image, source, plan)
    core.check(tuple(addr for addr, _ in bundle.sectors) == APP_SECTOR_ADDRESSES,
               "ORIGINAL_APP_REQUIRES_EXACT_23_SECTORS")
    core.check(b"".join(value for _, value in bundle.sectors) == data[:0x2E000],
               "ORIGINAL_APP_REDERIVATION_DIFFERS_FROM_CAPTURE")
    return bundle, manifest, proof


async def outside_crc(rom):
    rows = []
    for address in OUTSIDE:
        crc = await rom.crc32(address, core.gate.SECTOR)
        core.check(type(crc) is int and 0 <= crc <= 0xffffffff, "ORIGINAL_OUTSIDE_ROM_CRC_INVALID")
        rows.append({"address": address, "crc32": f"{crc:08x}"})
    return rows


def bind(approval, manifest, proof):
    approval.pop("approval_digest", None)
    approval.update(original_backup_digest=manifest["digest"], original_application=proof,
                    original_app_restore_only=True)
    approval["approval_digest"] = core.sha(core.canonical(approval))
    return approval


def validate(bundle, approval, digest, endpoint, manifest, proof):
    core.validate_approval(bundle, approval, digest, endpoint)
    core.check(approval.get("original_backup_digest") == manifest["digest"]
               and approval.get("identity") == manifest["identity"]
               and endpoint == manifest["endpoint"]
               and approval.get("original_application") == proof
               and approval.get("original_app_restore_only") is True,
               "ORIGINAL_APPROVAL_NOT_BOUND_TO_VERIFIED_CAPTURE")
    rows = approval.get("outside_application_crc32")
    core.check(type(rows) is list and len(rows) == len(OUTSIDE), "ORIGINAL_OUTSIDE_CRC_LIST_INVALID")
    for address, row in zip(OUTSIDE, rows):
        core.check(type(row) is dict and row.get("address") == address
                   and type(row.get("crc32")) is str
                   and re.fullmatch(r"[0-9a-f]{8}", row["crc32"]) is not None,
                   "ORIGINAL_OUTSIDE_CRC_LIST_INVALID")


async def inspect(rom, bundle, endpoint, manifest, proof):
    core.check(endpoint == manifest["endpoint"], "ORIGINAL_ENDPOINT_NOT_CAPTURED_DEVICE")
    result = await core.preflight(rom, bundle, endpoint)
    core.check(result["identity"] == manifest["identity"], "ORIGINAL_TARGET_NOT_CAPTURED_DEVICE")
    result["outside_application_crc32"] = await outside_crc(rom)
    return bind(result, manifest, proof)


async def execute(rom, bundle, approval, digest, endpoint, manifest, proof):
    validate(bundle, approval, digest, endpoint, manifest, proof)
    core.check(await core.observe(rom) == manifest["identity"], "ORIGINAL_TARGET_NOT_CAPTURED_DEVICE")
    core.check(await outside_crc(rom) == approval["outside_application_crc32"],
               "ORIGINAL_OUTSIDE_CHANGED_SINCE_INSPECT")
    result = await core.write_checked(rom, bundle, approval, digest, endpoint)
    core.check(await outside_crc(rom) == approval["outside_application_crc32"],
               "ORIGINAL_OUTSIDE_CHANGED_DURING_WRITE")
    return {**result, "status": "ORIGINAL_APP_VERIFIED_LEAVE_IN_ROM_FOR_NV_RESTORE",
            "original_backup_digest": manifest["digest"], "original_application": proof,
            "all_outside_application_sectors_unchanged": True,
            "original_network_restored": False}


async def run(args):
    core.check(args.backup_dir is not None and args.backup_copy_dir is not None
               and args.independent_copy_confirmed, "ORIGINAL_TWO_VERIFIED_BACKUPS_REQUIRED")
    core.check(args.unused_p7u and args.already_in_rom_bsl and args.device,
               "ORIGINAL_UNUSED_P7U_FRESH_ROM_ENTRY_REQUIRED")
    core.check(args.out is not None and not args.out.exists() and not args.out.is_symlink(),
               "ORIGINAL_NEW_RECEIPT_REQUIRED")
    vendor = args.official_stock_bin.read_bytes()
    bundle, manifest, proof = original_bundle(args.backup_dir, args.backup_copy_dir, vendor)
    core.check(args.device == manifest["endpoint"]
               and manifest["target"]["management_mac_digest"] ==
               core.sha(normalized_mac(args.management_mac).encode("ascii")),
               "ORIGINAL_ENDPOINT_OR_MANAGEMENT_MAC_NOT_CAPTURED_UNIT")
    if args.write:
        core.check(args.recovery_proven and args.plan is not None and args.approve_digest,
                   "ORIGINAL_WRITE_REQUIRES_RECOVERY_PLAN_AND_DIGEST")
        approval = core.load_json(args.plan)
        validate(bundle, approval, args.approve_digest, args.device, manifest, proof)
    async with LiveSmlightSession(args.device, args.management_mac) as rom:
        if args.write:
            return await execute(rom, bundle, approval, args.approve_digest, args.device, manifest, proof)
        return await inspect(rom, bundle, args.device, manifest, proof)
