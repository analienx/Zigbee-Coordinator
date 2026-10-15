#!/usr/bin/env python3
"""Private same-radio raw backup and two-phase, exactly-five-sector NV recovery.

No device discovery, BSL entry/reset, application write or bank/CCFG erase.
Raw flash contains keys: use a private local directory and an independent copy.
Offline verification is the default command. Hardware evidence remains required.
"""
from __future__ import annotations

import argparse
import asyncio
import binascii
import json
import os
import time
import uuid
from pathlib import Path

import p7u_strict_sector_writer as s
import p7u_stock_rollback as stock
from p7u_nv_rom_transport import NvSession, NV_SECTORS, SECTOR
from p7u_rom_transport import normalized_mac

RADIO_BYTES = 704 * 1024
ALL_SECTORS = tuple(range(0, RADIO_BYTES, SECTOR))
NV_START, NV_END = 0xA4000, 0xAE000
MODEL = "SLZB-06P7U"
QUIESCENT = "ORIGINAL_NETWORK_NOT_USED_SINCE_CAPTURE"


def crc(data: bytes) -> str:
    return f"{binascii.crc32(data) & 0xffffffff:08x}"


def seal(value: dict) -> dict:
    return {**value, "digest": s.sha(s.canonical(value))}


def unseal(value: dict) -> dict:
    s.check(type(value) is dict, "NV_DOCUMENT_NOT_OBJECT")
    raw = dict(value)
    digest = raw.pop("digest", None)
    s.check(type(digest) is str and digest == s.sha(s.canonical(raw)), "NV_DOCUMENT_DIGEST_CHANGED")
    return raw


def new_bytes(path: Path, data: bytes) -> None:
    """Durable exclusive publication. Failed/stale staging files are preserved."""
    temp = path.with_name(path.name + ".partial-" + uuid.uuid4().hex)
    with temp.open("xb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    # link() refuses existing destinations (including aliases); never overwrite.
    os.link(temp, path)
    temp.unlink()


def new_json(path: Path, obj: dict) -> None:
    new_bytes(path, (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode())


class Journal:
    def __init__(self, path: Path, *, resume: bool = False):
        self.file = path.open("a" if resume else "x", encoding="utf8")

    def __call__(self, **event):
        self.file.write(json.dumps({"unix_time": time.time(), **event}, sort_keys=True) + "\n")
        self.file.flush()
        os.fsync(self.file.fileno())

    def close(self):
        self.file.close()


async def checked_page(rom, addr: int) -> bytes:
    """Two independent complete reads, with ROM CRC before/between/after."""
    before = await rom.crc32(addr, SECTOR)
    first = await s.read_exact(rom, addr, SECTOR)
    middle = await rom.crc32(addr, SECTOR)
    second = await s.read_exact(rom, addr, SECTOR)
    after = await rom.crc32(addr, SECTOR)
    expected = binascii.crc32(first) & 0xffffffff
    s.check(type(before) is int and type(middle) is int and type(after) is int
            and before == middle == after == expected, "NV_READ_ROM_CRC_MISMATCH")
    s.check(first == second and s.sha(first) == s.sha(second), "NV_REPEATED_READ_MISMATCH")
    return first


def target_descriptor(model: str, board: str, host_version: str, mac: str) -> dict:
    s.check(model == MODEL and bool(board.strip()) and bool(host_version.strip()), "NV_PHYSICAL_MODEL_BOARD_HOST_REQUIRED")
    return {"model": model, "board_revision": board,
            "slzb_os_version": host_version,
            "management_mac_digest": s.sha(normalized_mac(mac).encode("ascii")),
            "usb_model_evidence": "operator_physical_confirmation_not_ROM_detection"}


async def probe(rom, endpoint: str, target: dict) -> dict:
    """Small read-only reliability/throughput sample before a long capture."""
    # perf_counter is monotonic with finer Windows resolution than monotonic().
    started = time.perf_counter()
    identity = await s.observe(rom)
    page_started = time.perf_counter()
    page = await checked_page(rom, 0)
    page_seconds = time.perf_counter() - page_started
    s.check(await s.observe(rom) == identity, "NV_PROBE_IDENTITY_CHANGED")
    return {"status": "READ_ONLY_ROM_PAGE_PROBE_VERIFIED", "endpoint": endpoint,
            "identity": identity, "target": target, "page_address": 0, "page_bytes": SECTOR,
            "page_sha256": s.sha(page), "page_crc32": crc(page),
            "independent_page_reads": 2, "scalar_read_transactions_for_page": 4096,
            "additional_scalar_identity_reads": 52,
            "page_double_read_elapsed_seconds": page_seconds,
            "probe_total_elapsed_seconds": time.perf_counter() - started,
            "projected_88_sector_double_read_seconds": page_seconds * len(ALL_SECTORS),
            "projection_is_estimate_not_full_capture_measurement": True,
            "projection_excludes_filesystem_and_later_bridge_variability": True,
            "write_performed": False, "post_flash_radio_reset_issued": False,
            "hardware_recovery_demonstrated": False}


async def capture(rom, directory: Path, endpoint: str, target: dict, *, resume=False, event=lambda **kw: None) -> dict:
    """Resumable read-only capture. Canonical sector files are never replaced."""
    identity = await s.observe(rom)
    header = seal({"schema": "p7u-raw-capture-v1", "endpoint": endpoint,
                   "target": target, "identity": identity,
                   "scope": "entire_704KiB_radio_including_NV_and_CCFG_read_only",
                   "reader": "pinned_scalar_4_bytes_two_passes_per_sector"})
    if resume:
        s.check(s.load_json(directory / "capture.json") == header, "NV_RESUME_DEVICE_OR_CAPTURE_CHANGED")
    else:
        new_json(directory / "capture.json", header)
    rows = []
    raw = bytearray()
    for addr in ALL_SECTORS:
        path = directory / f"sector-{addr:05x}.bin"
        data = await checked_page(rom, addr)
        if path.exists() or path.is_symlink():
            s.check(resume and not path.is_symlink() and path.read_bytes() == data, "NV_CAPTURE_SECTOR_CHANGED")
        else:
            new_bytes(path, data)
        rows.append({"address": addr, "length": SECTOR, "sha256": s.sha(data), "crc32": crc(data)})
        raw.extend(data)
        event(stage="backup_sector_verified", address=f"0x{addr:05X}", completed=len(rows), total=len(ALL_SECTORS))
    s.check(await s.observe(rom) == identity, "NV_CAPTURE_IDENTITY_CHANGED")
    original = bytes(raw)
    manifest = seal({"schema": "p7u-original-raw-backup-v1", "capture_digest": header["digest"],
                     "endpoint": endpoint, "target": target, "identity": identity,
                     "flash_bytes": RADIO_BYTES, "sha256": s.sha(original),
                     "nv5_sha256": s.sha(original[NV_START:NV_END]), "sectors": rows,
                     "rom_crc_and_independent_reads_per_sector": True,
                     "hardware_recovery_demonstrated": False})
    for name, data in (("original.bin", original),):
        path = directory / name
        if path.exists():
            s.check(resume and path.read_bytes() == data, "NV_ORIGINAL_ALREADY_EXISTS_OR_CHANGED")
        else:
            new_bytes(path, data)
    if (directory / "manifest.json").exists():
        s.check(resume and s.load_json(directory / "manifest.json") == manifest, "NV_MANIFEST_ALREADY_EXISTS_OR_CHANGED")
    else:
        new_json(directory / "manifest.json", manifest)
    verify_backup(directory)
    event(stage="backup_complete", backup_digest=manifest["digest"], flash_sha256=manifest["sha256"])
    return manifest


def verify_backup(directory: Path) -> tuple[dict, bytes]:
    """Rehash all raw bytes; self-attested JSON alone never permits mutation."""
    manifest = s.load_json(directory / "manifest.json")
    unseal(manifest)
    header = s.load_json(directory / "capture.json")
    unseal(header)
    data = (directory / "original.bin").read_bytes()
    s.check(manifest.get("schema") == "p7u-original-raw-backup-v1"
            and header.get("schema") == "p7u-raw-capture-v1"
            and manifest.get("capture_digest") == header["digest"]
            and manifest.get("identity") == header.get("identity")
            and manifest.get("target") == header.get("target")
            and manifest.get("endpoint") == header.get("endpoint")
            and manifest.get("flash_bytes") == len(data) == RADIO_BYTES
            and manifest.get("sha256") == s.sha(data)
            and manifest.get("nv5_sha256") == s.sha(data[NV_START:NV_END])
            and manifest.get("rom_crc_and_independent_reads_per_sector") is True,
            "NV_BACKUP_CONTENT_OR_CAPTURE_INVALID")
    rows = [{"address": addr, "length": SECTOR, "sha256": s.sha(data[addr:addr + SECTOR]),
             "crc32": crc(data[addr:addr + SECTOR])} for addr in ALL_SECTORS]
    s.check(manifest.get("sectors") == rows, "NV_BACKUP_SECTOR_MANIFEST_INVALID")
    s.check(manifest["target"].get("model") == MODEL, "NV_BACKUP_MODEL_INVALID")
    identity = manifest["identity"]
    ccfg = data[s.gate.CCFG_START:s.gate.CCFG_END]
    s.valid_ccfg(ccfg)
    s.check(identity.get("flash_bytes") == RADIO_BYTES
            and identity.get("ccfg_sha256") == s.sha(ccfg)
            and identity.get("silicon_wafer") == "CC13x2x7_CC26x2x7_0xBB77",
            "NV_BACKUP_CCFG_OR_SILICON_INVALID")
    return manifest, data


def verified_pair(original: Path, copy: Path) -> tuple[dict, bytes]:
    s.check(original.resolve() != copy.resolve(), "NV_INDEPENDENT_COPY_REQUIRED")
    s.check(not os.path.samefile(original / "original.bin", copy / "original.bin"), "NV_COPY_IS_SAME_FILE")
    one, data = verify_backup(original)
    two, copydata = verify_backup(copy)
    s.check(one == two and data == copydata, "NV_INDEPENDENT_BACKUP_COPY_DIFFERS")
    return one, data


def known_original_application(data: bytes, vendor: bytes) -> dict:
    """Prove existing app can be rebuilt by the pinned stock app-only writer."""
    _, _, plan, receipt = stock.extract(vendor, "p7u-cap192-f07")
    expected = vendor[28:28 + stock.APP_BYTES]
    s.check(data[:stock.APP_BYTES] == expected, "NV_CAPTURED_ORIGINAL_APP_NOT_PINNED_STOCK")
    s.check(data[stock.APP_BYTES:NV_START] == b"\xff" * (NV_START - stock.APP_BYTES),
            "NV_CAPTURED_ORIGINAL_HAS_UNRECOVERABLE_APP_GAP_DATA")
    return {"manufacturer_sha256": stock.VENDOR_SHA, "original_app_sha256": s.sha(expected),
            "original_app_bytes": stock.APP_BYTES, "original_gap_to_nv5_all_ff": True,
            "stock_app_only_hex_sha256": receipt["rollback_app_only_hex_sha256"],
            "stock_app_only_plan_sha256": s.sha(s.canonical(plan)),
            "original_application_rebuildable_by_pinned_app_writer": True}


async def require_original_application_live(rom, data: bytes) -> None:
    # Raw original NV must never be installed under a custom/different app.
    # Check every sector below NV5, including the untouched FF gap.
    for addr in range(0, NV_START, SECTOR):
        s.check(await rom.crc32(addr, SECTOR) == int(crc(data[addr:addr + SECTOR]), 16),
                "NV_RESTORE_REQUIRES_ORIGINAL_STOCK_APPLICATION_FIRST")


async def inspect(rom, original: Path, copy: Path, endpoint: str, action: str, vendor: bytes,
                  *, event=lambda **kw: None) -> dict:
    manifest, data = verified_pair(original, copy)
    app_proof = known_original_application(data, vendor)
    s.check(action in ("prepare-nv5", "restore-original-nv5"), "NV_UNKNOWN_ACTION")
    identity = await s.observe(rom)
    s.check(identity == manifest["identity"] and endpoint == manifest["endpoint"], "NV_TARGET_NOT_CAPTURED_DEVICE")
    if action == "restore-original-nv5":
        await require_original_application_live(rom, data)
    before = []
    for addr in NV_SECTORS:
        page = await checked_page(rom, addr)
        # Preparation starts from the independently captured original state;
        # resume requires a NEW inspect/plan, never an unchecked retry switch.
        if action == "prepare-nv5":
            s.check(page == data[addr:addr + SECTOR] or page == b"\xff" * SECTOR,
                    "NV_PREP_STATE_NOT_ORIGINAL_OR_BLANK")
        desired = b"\xff" * SECTOR if action == "prepare-nv5" else data[addr:addr + SECTOR]
        before.append({"address": addr, "before_sha256": s.sha(page), "before_crc32": crc(page),
                       "desired_sha256": s.sha(desired), "desired_crc32": crc(desired)})
        event(stage="nv_inspect_verified", address=f"0x{addr:05X}")
    # Protect all bytes outside NV, including the complete CCFG erase sector.
    outside = []
    for addr in ALL_SECTORS:
        if addr not in NV_SECTORS:
            value = await rom.crc32(addr, SECTOR)
            s.check(type(value) is int and 0 <= value <= 0xffffffff, "NV_OUTSIDE_CRC_INVALID")
            outside.append({"address": addr, "crc32": f"{value:08x}"})
    s.check(await s.observe(rom) == identity, "NV_INSPECTION_IDENTITY_CHANGED")
    return seal({"schema": "p7u-nv5-plan-v1", "action": action, "endpoint": endpoint,
                 "backup_digest": manifest["digest"], "backup_sha256": manifest["sha256"],
                 "original_application_recovery_proof": app_proof,
                 "identity": identity, "target": manifest["target"], "sectors": before,
                 "outside_nv_crc32": outside, "requires_declaration": QUIESCENT,
                 "independent_copy_rehashed": True, "write_performed": False,
                 "radio_reset_permitted": False, "network_restore_qualified": False})


def validate_plan(plan: dict, digest: str, manifest: dict, data: bytes, endpoint: str, vendor: bytes) -> None:
    unseal(plan)
    app_proof = known_original_application(data, vendor)
    s.check(plan["digest"] == digest and plan.get("schema") == "p7u-nv5-plan-v1"
            and plan.get("endpoint") == endpoint == manifest["endpoint"]
            and plan.get("identity") == manifest["identity"]
            and plan.get("target") == manifest["target"]
            and plan.get("backup_digest") == manifest["digest"]
            and plan.get("backup_sha256") == s.sha(data)
            and plan.get("original_application_recovery_proof") == app_proof
            and plan.get("requires_declaration") == QUIESCENT
            and plan.get("independent_copy_rehashed") is True
            and plan.get("write_performed") is False
            and plan.get("radio_reset_permitted") is False,
            "NV_PLAN_BINDING_INVALID")
    action = plan.get("action")
    s.check(action in ("prepare-nv5", "restore-original-nv5"), "NV_UNKNOWN_ACTION")
    rows = plan.get("sectors")
    s.check(type(rows) is list and len(rows) == 5, "NV_PLAN_SECTORS_CHANGED")
    for addr, row in zip(NV_SECTORS, rows):
        desired = b"\xff" * SECTOR if action == "prepare-nv5" else data[addr:addr + SECTOR]
        s.check(row.get("address") == addr and row.get("desired_sha256") == s.sha(desired)
                and row.get("desired_crc32") == crc(desired), "NV_PLAN_SECTORS_CHANGED")
    outside = plan.get("outside_nv_crc32")
    s.check(type(outside) is list and [r.get("address") for r in outside]
            == [a for a in ALL_SECTORS if a not in NV_SECTORS], "NV_PLAN_OUTSIDE_SECTORS_CHANGED")


async def execute(rom, original: Path, copy: Path, endpoint: str, plan: dict, digest: str,
                  declaration: str, vendor: bytes, *, event=lambda **kw: None) -> dict:
    manifest, data = verified_pair(original, copy)
    validate_plan(plan, digest, manifest, data, endpoint, vendor)
    s.check(declaration == QUIESCENT, "NV_COUNTER_ROLLBACK_DECLARATION_REQUIRED")
    s.check(await s.observe(rom) == plan["identity"], "NV_TARGET_NOT_CAPTURED_DEVICE")
    if plan["action"] == "restore-original-nv5":
        await require_original_application_live(rom, data)
    # All five pages must match inspect before the first mutation. SHA and CRC
    # both checked; a different live network state needs a new plan.
    pages = []
    for row in plan["sectors"]:
        page = await checked_page(rom, row["address"])
        s.check(s.sha(page) == row["before_sha256"] and crc(page) == row["before_crc32"],
                "NV_CHANGED_SINCE_INSPECT")
        pages.append(page)
    for row in plan["outside_nv_crc32"]:
        s.check(await rom.crc32(row["address"], SECTOR) == int(row["crc32"], 16),
                "NV_OUTSIDE_CHANGED_SINCE_INSPECT")
    changed = 0
    for addr, row, page in zip(NV_SECTORS, plan["sectors"], pages):
        desired = b"\xff" * SECTOR if plan["action"] == "prepare-nv5" else data[addr:addr + SECTOR]
        if page == desired:
            event(stage="nv_sector_already_verified", address=f"0x{addr:05X}")
            continue
        s.check(addr in NV_SECTORS and addr + SECTOR <= NV_END, "NV_RUNTIME_ADDRESS_REJECTED")
        event(stage="nv_erase_about_to_start", address=f"0x{addr:05X}", plan_digest=digest)
        s.check(await rom.erase_sector(addr) is True, "NV_SECTOR_ERASE_FAILED")
        event(stage="nv_erased", address=f"0x{addr:05X}")
        s.check(await checked_page(rom, addr) == b"\xff" * SECTOR, "NV_ERASE_READBACK_FAILED")
        if desired != b"\xff" * SECTOR:
            s.check(await rom.begin_download(addr, SECTOR) is True, "NV_DOWNLOAD_FAILED")
            for offset in range(0, SECTOR, s.PACKET):
                s.check(await rom.send_data(desired[offset:offset + s.PACKET]) is True, "NV_SEND_FAILED")
            s.check(await checked_page(rom, addr) == desired, "NV_RESTORE_READBACK_FAILED")
        s.check(await s.observe(rom) == plan["identity"], "NV_CCFG_OR_IDENTITY_CHANGED")
        # The entire protected CCFG sector, not merely the last 88 bytes.
        protected = plan["outside_nv_crc32"][-1]
        s.check(protected["address"] == NV_END and await rom.crc32(NV_END, SECTOR)
                == int(protected["crc32"], 16), "NV_CCFG_SECTOR_CHANGED")
        changed += 1
        event(stage="nv_sector_verified", address=f"0x{addr:05X}")
    for row in plan["outside_nv_crc32"]:
        s.check(await rom.crc32(row["address"], SECTOR) == int(row["crc32"], 16), "NV_OUTSIDE_CHANGED_DURING_WRITE")
    s.check(await s.observe(rom) == plan["identity"], "NV_FINAL_IDENTITY_CHANGED")
    return {"status": "NV5_OPERATION_READBACK_VERIFIED_LEAVE_IN_ROM_BSL", "action": plan["action"],
            "plan_digest": digest, "sectors_changed": changed, "exact_five_sector_scope": list(NV_SECTORS),
            "application_and_full_CCFG_sector_unchanged": True, "post_flash_radio_reset_issued": False,
            "network_restore_qualified": False, "hardware_recovery_demonstrated": False}


async def run(args):
    if args.command != "probe":
        s.check(args.backup_dir is not None, "NV_BACKUP_DIRECTORY_REQUIRED")
    if args.command == "verify":
        manifest, _ = (verified_pair(args.backup_dir, args.backup_copy_dir)
                       if args.backup_copy_dir else verify_backup(args.backup_dir))
        return {"status": "PRIVATE_RAW_BACKUP_OFFLINE_VERIFIED", "backup_digest": manifest["digest"],
                "flash_sha256": manifest["sha256"], "hardware_contacted": False}
    s.check(args.unused_p7u and args.already_in_rom_bsl and args.device,
            "NV_UNUSED_P7U_ALREADY_IN_BSL_AND_EXPLICIT_ENDPOINT_REQUIRED")
    s.check(type(args.management_mac) is str and bool(args.management_mac), "NV_MANAGEMENT_MAC_REQUIRED")
    normalized_mac(args.management_mac)
    if args.command == "probe":
        s.check(args.out_dir is not None, "NV_NEW_PROBE_OUTPUT_DIRECTORY_REQUIRED")
        target = target_descriptor(args.model, args.board_revision, args.host_version, args.management_mac)
        args.out_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
        journal = Journal(args.out_dir / "events.jsonl")
        try:
            journal(stage="read_only_probe_start")
            async with NvSession(args.device, args.management_mac) as rom:
                result = await probe(rom, args.device, target)
            new_json(args.out_dir / "probe.json", result)
            journal(stage="read_only_probe_verified", page_sha256=result["page_sha256"])
            return result
        except BaseException:
            journal(stage="read_only_probe_failed_leave_in_BSL")
            raise
        finally:
            journal.close()
    if args.command == "backup":
        target = target_descriptor(args.model, args.board_revision, args.host_version, args.management_mac)
        if not args.resume:
            args.backup_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
        s.check(args.backup_dir.is_dir() and not args.backup_dir.is_symlink(), "NV_PRIVATE_DIRECTORY_REQUIRED")
        lock = args.backup_dir / "capture.lock"
        # A stale lock must be inspected/removed manually after confirming no
        # capture is running. Never open two readers over one BSL stream.
        with lock.open("x"):
            pass  # Close before unlink: Windows cannot remove an open lock file.
        journal = Journal(args.backup_dir / "events.jsonl", resume=args.resume)
        try:
            async with NvSession(args.device, args.management_mac) as rom:
                result = await capture(rom, args.backup_dir, args.device, target,
                                       resume=args.resume, event=journal)
            return {"status": "RAW_BACKUP_COMPLETE", "backup_digest": result["digest"],
                    "flash_sha256": result["sha256"], "hardware_recovery_demonstrated": False}
        except BaseException:
            journal(stage="capture_failed_leave_in_BSL", completed_sectors_preserved=True)
            raise
        finally:
            journal.close()
            lock.unlink()
    s.check(args.backup_copy_dir is not None and args.out_dir is not None,
            "NV_BACKUP_COPY_AND_NEW_OUTPUT_DIRECTORY_REQUIRED")
    s.check(args.official_stock_bin is not None, "NV_PINNED_OFFICIAL_STOCK_SOURCE_REQUIRED")
    if args.command == "inspect":
        s.check(args.action is not None, "NV_ACTION_REQUIRED")
    else:
        s.check(args.plan is not None and args.approve_digest is not None,
                "NV_PLAN_AND_APPROVAL_DIGEST_REQUIRED")
    manifest, data = verified_pair(args.backup_dir, args.backup_copy_dir)
    vendor = args.official_stock_bin.read_bytes()
    known_original_application(data, vendor)  # All offline, before opening ROM.
    s.check(args.independent_copy_confirmed, "NV_INDEPENDENT_COPY_CONFIRMATION_REQUIRED")
    s.check(manifest["target"]["management_mac_digest"] == s.sha(normalized_mac(args.management_mac).encode("ascii")),
            "NV_CAPTURE_MANAGEMENT_MAC_MISMATCH")
    if args.command == "execute":
        s.check(args.execute_nv_write and args.rom_bsl_reentry_twice_confirmed
                and args.stock_application_rollback_available, "NV_EXPLICIT_WRITE_RECOVERY_APPROVAL_REQUIRED")
        plan = s.load_json(args.plan)
        validate_plan(plan, args.approve_digest, manifest, data, args.device, vendor)
        s.check(args.original_network_declaration == QUIESCENT, "NV_COUNTER_ROLLBACK_DECLARATION_REQUIRED")
    args.out_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
    journal = Journal(args.out_dir / "events.jsonl")
    try:
        async with NvSession(args.device, args.management_mac) as rom:
            if args.command == "inspect":
                result = await inspect(rom, args.backup_dir, args.backup_copy_dir, args.device, args.action, vendor, event=journal)
                new_json(args.out_dir / "plan.json", result)
            else:
                result = await execute(rom, args.backup_dir, args.backup_copy_dir, args.device, plan,
                                       args.approve_digest, args.original_network_declaration, vendor, event=journal)
                new_json(args.out_dir / "receipt.json", result)
            return result
    except BaseException:
        journal(stage="operation_failed_leave_in_BSL", inspect_again_before_any_retry=True)
        raise
    finally:
        journal.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", nargs="?", choices=("verify", "probe", "backup", "inspect", "execute"), default="verify")
    parser.add_argument("--backup-dir", type=Path)
    parser.add_argument("--backup-copy-dir", type=Path)
    parser.add_argument("--official-stock-bin", type=Path)
    parser.add_argument("--independent-copy-confirmed", action="store_true")
    parser.add_argument("--device")
    parser.add_argument("--management-mac")
    parser.add_argument("--unused-p7u", action="store_true")
    parser.add_argument("--already-in-rom-bsl", action="store_true")
    parser.add_argument("--model", default=MODEL)
    parser.add_argument("--board-revision", default="")
    parser.add_argument("--host-version", default="")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--action", choices=("prepare-nv5", "restore-original-nv5"))
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--approve-digest")
    parser.add_argument("--execute-nv-write", action="store_true")
    parser.add_argument("--rom-bsl-reentry-twice-confirmed", action="store_true")
    parser.add_argument("--stock-application-rollback-available", action="store_true")
    parser.add_argument("--original-network-declaration", choices=(QUIESCENT,))
    args = parser.parse_args()
    try:
        print(json.dumps(asyncio.run(run(args)), sort_keys=True))
    except Exception as exc:
        reason = str(exc) if isinstance(exc, s.StrictError) else "NV_IO_OR_PROTOCOL_FAILURE"
        print(json.dumps({"status": "FAIL_CLOSED", "error_code": reason,
                          "post_flash_radio_reset_issued": False}))
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
