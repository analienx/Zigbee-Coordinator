#!/usr/bin/env python3
"""Explicit two-phase CC2652P7U *spare* radio flasher (ROM, sector-only).

Default behavior is offline validation. No automatic reset / HA/Z2M access.
Stock SMLIGHT cc-flasher CLI MUST NOT be used for CCFG-free segmented HEX:
the stock CLI forcibly calls BANK_ERASE for segmented writes.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path

import p7u_strict_sector_writer as strict
import p7u_stock_rollback as stock
from p7u_rom_lowlevel import APP_SECTOR_ADDRESSES
from p7u_rom_transport import LiveSmlightSession, normalized_mac


NV5_BYTES = strict.gate.CCFG_SECTOR - strict.gate.NV5_BASE
BLANK_NV5 = {
    "address": f"0x{strict.gate.NV5_BASE:05X}",
    "length": NV5_BYTES,
    "sha256": strict.sha(b"\xff" * NV5_BYTES),
    "all_ff": True,
}


def needs_blank_nv5(args, bundle: strict.Bundle) -> bool:
    # This CLI qualifies an initial R2 installation, not an existing NV5 network
    # update. App-only rollback and R1 must remain possible with nonblank NV.
    return args.target_image == "candidate" and bundle.profile == "p7u-cap192-f07"


async def observe_nv5(rom: strict.Rom) -> dict:
    """Read all five pages; publish only their digest and blank status."""
    digest = hashlib.sha256()
    blank = True
    for addr in range(strict.gate.NV5_BASE, strict.gate.CCFG_SECTOR, strict.gate.SECTOR):
        page = await strict.read_exact(rom, addr, strict.gate.SECTOR)
        digest.update(page)
        blank = blank and page == b"\xff" * strict.gate.SECTOR
    return {"address": f"0x{strict.gate.NV5_BASE:05X}", "length": NV5_BYTES,
            "sha256": digest.hexdigest(), "all_ff": blank}


def json_write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True,exist_ok=True)
    # Preserve prior receipts and recovery artifacts, including symlink/hardlink aliases.
    with path.open("x", encoding="utf8") as report:
        report.write(json.dumps(data,indent=2,sort_keys=True)+"\n")


def validate_output(args) -> None:
    inputs = [args.app_only_hex, args.full_image_evidence, args.sector_plan,
              args.official_stock_bin, args.rollback_app_hex, args.rollback_receipt]
    if args.approval_file is not None:
        inputs.append(args.approval_file)
    output = args.out.resolve()
    strict.check(all(output != path.resolve() for path in inputs),
                 "OUTPUT_COLLIDES_WITH_RECOVERY_INPUT")
    strict.check(not args.out.exists() and not args.out.is_symlink(),
                 "OUTPUT_MUST_BE_NEW")


def validate_stock(vendor_bin: Path, rollback: Path, receipt: Path,
                   profile: str) -> strict.Bundle:
    # Re-derive ALL rollback bytes and the receipt from the independently
    # SHA-256-pinned official vendor blob, not from self-attested JSON fields.
    regenerated, source, expected_plan, expected_receipt = stock.extract(
        vendor_bin.read_bytes(), profile)
    strict.check(rollback.read_bytes() == regenerated,
                 "ROLLBACK_BYTES_NOT_FROM_PINNED_VENDOR")
    strict.check(strict.load_json(receipt) == expected_receipt,
                 "ROLLBACK_RECEIPT_NOT_FROM_PINNED_VENDOR")
    return strict.load_bundle(regenerated, source, expected_plan)


def load_request(args):
    source=strict.load_json(args.full_image_evidence)
    plan=strict.load_json(args.sector_plan)
    bundle=strict.load_bundle(args.app_only_hex.read_bytes(),source,plan)
    rollback=validate_stock(args.official_stock_bin,args.rollback_app_hex,args.rollback_receipt,bundle.profile)
    strict.check(rollback.hex_sha256!=bundle.hex_sha256,
                 "CANDIDATE_IS_IDENTICAL_TO_ROLLBACK")
    strict.check(23 <= len(bundle.sectors) <= len(APP_SECTOR_ADDRESSES)
                 and tuple(addr for addr, _ in bundle.sectors) ==
                     APP_SECTOR_ADDRESSES[:len(bundle.sectors)]
                 and tuple(addr for addr, _ in rollback.sectors) == APP_SECTOR_ADDRESSES,
                 "APPLICATION_AND_ROLLBACK_CONTRACT_MISMATCH")
    return bundle,rollback


async def run(args):
    validate_output(args)
    candidate,rollback=load_request(args)
    bundle = rollback if args.target_image == "stock" else candidate
    if args.phase == "offline":
        return {"qualification":"OFFLINE_BUNDLE_VALIDATED",
                "candidate_sha256":candidate.hex_sha256,
                "selected_target":args.target_image,
                "selected_target_sha256":bundle.hex_sha256,
                "stock_rollback_sha256":rollback.hex_sha256,
                "sector_count":len(bundle.sectors),
                "hardware_contacted":False, "flash_performed":False}
    strict.check(args.isolated_spare_only is True,"SPARE_RADIO_ACK_REQUIRED")
    strict.check(bool(args.device),"DEVICE_EXPLICIT_REQUIRED")
    if args.device.startswith("socket://"):
        strict.check(bool(args.expected_spare_mac),"SPARE_MAC_REQUIRED_BEFORE_BSL_ENTRY")
        spare_mac_digest=strict.sha(normalized_mac(args.expected_spare_mac).encode("ascii"))
    else:
        spare_mac_digest=None
    if args.phase=="flash":
        strict.check(args.execute_radio_write is True
                     and args.rom_bsl_reentry_twice_confirmed is True
                     and args.stock_rollback_available is True,
                     "EXPLICIT_RECOVERY_APPROVAL_MISSING")
        strict.check(args.approval_file is not None
                     and args.approve_digest is not None,
                     "APPROVAL_NOT_SUPPLIED")
        approval=strict.load_json(args.approval_file)
        strict.validate_approval(bundle,approval,args.approve_digest,args.device)
        strict.check(approval.get("spare_management_mac_digest")==spare_mac_digest,
                     "INSPECTED_SPARE_MAC_DOES_NOT_MATCH_WRITE")
        strict.check(approval.get("rollback_app_sha256")==rollback.hex_sha256
                     and approval.get("rollback_manufacturer_sha256")==stock.VENDOR_SHA,
                     "STOCK_ROLLBACK_NOT_BOUND_TO_APPROVAL")
        if needs_blank_nv5(args, bundle):
            strict.check(approval.get("initial_nv5") == BLANK_NV5,
                         "R2_INITIAL_NV5_NOT_PROVEN_BLANK")
        # Authorization digest of preflight includes rollback fields; validated
        # independently in write_checked(), never inferred from CLI flags alone.
        if args.resume:
            strict.check(args.accept_interrupted_sector_reerase,
                         "INTERRUPTED_REFLASH_NEEDS_EXPLICIT_ACCEPTANCE")
    async with LiveSmlightSession(args.device,args.expected_spare_mac) as rom:
        if args.phase=="inspect":
            result=await strict.preflight(rom,bundle,args.device)
            current={row["address"]:row["before_crc32"] for row in result["sectors"]}
            rollback_expected={f"0x{addr:05X}":
                 f"{__import__('binascii').crc32(image)&0xffffffff:08x}"
                 for addr,image in rollback.sectors}
            result["spare_management_mac_digest"]=spare_mac_digest
            result["rollback_app_sha256"]=rollback.hex_sha256
            result["rollback_manufacturer_sha256"]=stock.VENDOR_SHA
            result["stock_rollback_matching_sector_count"] = sum(
                current.get(addr)==crc for addr,crc in rollback_expected.items())
            result["stock_rollback_sector_count"]=len(rollback_expected)
            if needs_blank_nv5(args, bundle):
                result["initial_nv5"] = await observe_nv5(rom)
            previous=result.pop("approval_digest")
            strict.check(bool(previous),"MISSING_PREFLIGHT_TOKEN")
            result["approval_digest"]=strict.sha(strict.canonical(result))
            return result
        if needs_blank_nv5(args, bundle):
            strict.check(await strict.observe(rom) == approval["identity"],
                         "TARGET_IDENTITY_OR_CCFG_CHANGED")
            strict.check(await observe_nv5(rom) == BLANK_NV5,
                         "R2_INITIAL_NV5_CHANGED_OR_NOT_BLANK")
        # Live mutation is possible only here, with the exact offline image
        # and stock rollback sources pinned in the separately approved document.
        return await strict.write_checked(
            rom,bundle,approval,args.approve_digest,args.device,
            allow_resume=args.resume)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--phase",choices=("offline","inspect","flash"),default="offline")
    p.add_argument("--target-image",choices=("candidate","stock"),default="candidate",
                   help="For rollback: select stock, inspect damaged radio, then flash using new approval digest")
    p.add_argument("--app-only-hex",type=Path,required=True)
    p.add_argument("--full-image-evidence",type=Path,required=True)
    p.add_argument("--sector-plan",type=Path,required=True)
    p.add_argument("--official-stock-bin",type=Path,required=True)
    p.add_argument("--rollback-app-hex",type=Path,required=True)
    p.add_argument("--rollback-receipt",type=Path,required=True)
    p.add_argument("--device",help="Exact COM, /dev/tty or socket://HOST:6638 target; NEVER production MR4U")
    p.add_argument("--expected-spare-mac",help="Full physical ESP MAC of spare P7U; required before network BSL reset")
    p.add_argument("--isolated-spare-only",action="store_true")
    p.add_argument("--execute-radio-write",action="store_true")
    p.add_argument("--rom-bsl-reentry-twice-confirmed",action="store_true")
    p.add_argument("--stock-rollback-available",action="store_true")
    p.add_argument("--approval-file",type=Path)
    p.add_argument("--approve-digest",help="Exact digest printed by independent inspect run")
    p.add_argument("--resume",action="store_true")
    p.add_argument("--accept-interrupted-sector-reerase",action="store_true")
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    try:
        validate_output(a)
    except (strict.StrictError, OSError) as exc:
        # Do not write an error receipt to a path that would destroy recovery input.
        reason=str(exc) if isinstance(exc,strict.StrictError) else "OUTPUT_PATH_INVALID"
        print(json.dumps({"qualification":"FAIL_CLOSED", "flash_authorized":False,
                          "error_code":reason, "hardware_contacted":False},sort_keys=True))
        raise SystemExit(2) from None
    try:
        result=asyncio.run(run(a))
    except Exception as exc:
        # Connection, dependency and unexpected driver errors fail closed too;
        # do not leak raw serial reads, private IEEE or management responses.
        reason=str(exc) if isinstance(exc,strict.StrictError) else "RUNTIME_OR_CONNECTION_FAILED"
        result={"qualification":"FAIL_CLOSED","flash_authorized":False,
                "error_code":reason,"post_flash_radio_reset_issued":False,
                "bsl_entry_may_have_reset_spare_radio":a.phase!="offline"}
        json_write(a.out,result)
        print(json.dumps(result,sort_keys=True))
        raise SystemExit(2)
    json_write(a.out,result)
    print(json.dumps(result,sort_keys=True))


if __name__=="__main__":
    main()
