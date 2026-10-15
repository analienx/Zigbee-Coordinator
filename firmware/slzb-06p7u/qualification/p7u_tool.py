#!/usr/bin/env python3
"""One P7U/R2 operator entry point; check is offline, writes require a fresh plan.

Reuses the existing sector writer and NV recovery implementation. Management
and serial endpoints are separate so Wi-Fi management works with USB radio data.
"""
from __future__ import annotations

import argparse
import asyncio
import binascii
import json
from pathlib import Path
import re
from types import SimpleNamespace
import urllib.request

import p7u_flash_spare as app
import p7u_nv_recovery as nv
import p7u_original_rollback as original
import p7u_rc1_package as kit
import p7u_strict_sector_writer as core
from p7u_rom_transport import normalized_mac, BslConnectionError, LiveSmlightSession
from p7u_rom_lowlevel import RomWireError


COMMANDS = ("check", "identify", "enter-bsl", "restart-radio", "probe", "backup",
            "verify-backup", "prepare-nv5", "restore-nv5", "flash", "rollback", "restore-app",
            "inspect-installed", "bootdiag")


def load_target(path: Path) -> dict:
    target = core.load_json(path)
    core.check(target.get("schema") == "p7u-operator-target-v1", "P7U_TARGET_SCHEMA")
    core.check(target.get("model") == nv.MODEL, "P7U_TARGET_MODEL")
    normalized_mac(target.get("management_mac", ""))
    core.check(type(target.get("management_host")) is str and
               re.fullmatch(r"[A-Za-z0-9.-]+", target["management_host"]) is not None,
               "P7U_EXACT_MANAGEMENT_HOST_REQUIRED")
    core.check(bool(target.get("board_revision")) and bool(target.get("host_version")),
               "P7U_BOARD_AND_HOST_VERSION_REQUIRED")
    core.check(type(target.get("device")) is str and
               re.fullmatch(r"(COM[0-9]+|/dev/tty(?:ACM|USB|S)[0-9]+|socket://[A-Za-z0-9.-]+:6638)",
                            target["device"]) is not None, "P7U_EXACT_RADIO_ENDPOINT_REQUIRED")
    # Relative packet location is relative to the target file, never the cwd.
    packet = Path(target["packet"])
    target["packet"] = (path.parent / packet).resolve()
    return target


def app_request(target: dict, args) -> SimpleNamespace:
    packet = target["packet"]
    directory = packet / "kit"
    return SimpleNamespace(
        app_only_hex=directory / "candidate.APP-ONLY-NOT-FLASHABLE.hex",
        full_image_evidence=directory / "candidate.source.json",
        sector_plan=directory / "candidate.plan.json",
        official_stock_bin=packet / "official-stock-20240710.bin",
        rollback_app_hex=directory / "stock-20240710.APP-ONLY-ROLLBACK-NOT-FLASHABLE.hex",
        rollback_receipt=directory / "stock-20240710.receipt.json",
        phase="flash" if args.write else "inspect",
        target_image="stock" if args.command == "rollback" else "candidate",
        device=target["device"], expected_spare_mac=target["management_mac"],
        isolated_spare_only=args.unused_p7u,
        execute_radio_write=args.write,
        rom_bsl_reentry_twice_confirmed=args.recovery_proven,
        stock_rollback_available=args.recovery_proven,
        approval_file=args.plan, approve_digest=args.approve,
        resume=False, accept_interrupted_sector_reerase=False, out=args.out)


def validate_packet(target: dict, args) -> dict:
    result = kit.verify_directory(target["packet"] / "kit")
    core.check(result["profile"] == "p7u-cap192-f07", "P7U_TOOL_REQUIRES_R2_NV5_KIT")
    manifest = core.load_json(target["packet"] / "kit" / "RC1-MANIFEST.json")
    core.check(manifest["release_custom_app_hex_sha256"] == target.get("candidate_sha256"),
               "P7U_TARGET_CANDIDATE_CHANGED")
    app.load_request(app_request(target, args))  # Re-derive official fallback too.
    nv.stock.extract_original(original_vendor(target).read_bytes(), "p7u-cap192-f07")
    return result


def original_vendor(target: dict) -> Path:
    name = target.get("original_stock_file", "official-stock-20240710.bin")
    core.check(name in ("official-stock-20240316.bin", "official-stock-20240710.bin"),
               "P7U_ORIGINAL_SOURCE_MUST_BE_PINNED_REVISION")
    return target["packet"] / name


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise core.StrictError("P7U_MANAGEMENT_REDIRECT_REJECTED")


def management_get(host: str, path: str) -> bytes:
    # Only an explicitly configured host; no discovery, proxy or redirects.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(f"http://{host}{path}", timeout=8) as response:
        data = response.read(65537)
    core.check(len(data) <= 65536, "P7U_MANAGEMENT_RESPONSE_TOO_LARGE")
    return data


def identify(target: dict) -> dict:
    info = json.loads(management_get(target["management_host"], "/ha_info"))["Info"]
    core.check(str(info.get("model", "")).upper() == nv.MODEL, "P7U_MANAGEMENT_MODEL_CHANGED")
    core.check(normalized_mac(info.get("MAC", "")) == normalized_mac(target["management_mac"]),
               "P7U_MANAGEMENT_MAC_CHANGED")
    hardware = info.get("hw_version")
    board = f"{hardware // 100}.{hardware % 100:02d}" if type(hardware) is int else str(hardware)
    core.check(board == target["board_revision"] and info.get("sw_version") == target["host_version"],
               "P7U_MANAGEMENT_BOARD_OR_OS_CHANGED")
    core.check(info.get("zb_hw") == "CC2652P7", "P7U_MANAGEMENT_RADIO_CHANGED")
    return {"status": "P7U_MANAGEMENT_IDENTITY_MATCHED", "model": nv.MODEL,
            "board_revision": board, "slzb_os_version": info["sw_version"],
            "management_mac_digest": core.sha(normalized_mac(info["MAC"]).encode("ascii")),
            "coordinator_mode": info.get("coord_mode"),
            "reported_radio_version": info.get("zb_version"),
            "reported_version_is_not_ZNP_readback": True, "radio_modified": False}


def radio_control(target: dict, command: str) -> dict:
    core.check(command in ("enter-bsl", "restart-radio"), "P7U_UNKNOWN_RADIO_CONTROL")
    result = identify(target)  # Must match immediately before every command.
    # Manufacturer pysmlight v0.5.3: action=4, CMD_ZB_BSL=2 / CMD_ZB_RST=1.
    # Never invoke ESP reset/update, radio OTA, settings, bank erase or IEEE write.
    code = 2 if command == "enter-bsl" else 1
    response = management_get(target["management_host"], f"/api2?action=4&cmd={code}")
    core.check(response == b"ok", "P7U_RADIO_COMMAND_NOT_ACKNOWLEDGED")
    return {**result, "status": "P7U_RADIO_COMMAND_ACKNOWLEDGED", "command": command,
            "radio_modified": True, "flash_performed": False,
            "rom_access_or_stock_startup_proven": False}


def nv_request(target: dict, args) -> SimpleNamespace:
    action = "restore-original-nv5" if args.command == "restore-nv5" else "prepare-nv5"
    command = ({"verify-backup": "verify"}.get(args.command, args.command)
               if args.command in ("probe", "backup", "verify-backup")
               else "execute" if args.write else "inspect")
    return SimpleNamespace(
        command=command, backup_dir=args.backup, backup_copy_dir=args.copy,
        official_stock_bin=original_vendor(target),
        independent_copy_confirmed=args.independent_copy,
        device=target["device"], management_mac=target["management_mac"],
        unused_p7u=args.unused_p7u, already_in_rom_bsl=args.already_in_rom_bsl,
        model=target["model"], board_revision=target["board_revision"],
        host_version=target["host_version"], resume=args.resume, out_dir=args.out,
        action=action, plan=args.plan, approve_digest=args.approve,
        execute_nv_write=args.write, rom_bsl_reentry_twice_confirmed=args.recovery_proven,
        stock_application_rollback_available=args.recovery_proven,
        original_network_declaration=nv.QUIESCENT if args.original_network_quiescent else None)


def expected_application_images(target: dict, args) -> dict[str, core.Bundle]:
    """Re-derive R2 and both pinned stock apps from validated local sources."""
    candidate, stock_20240710 = app.load_request(app_request(target, args))
    # Compare both independently pinned vendor images, even if the target's
    # selected original happens to be the kit's 20240710 fallback.
    old_stock = target["packet"] / "official-stock-20240316.bin"
    core.check(old_stock.is_file(), "INSPECT_PINNED_20240316_REQUIRED")
    core.check(core.sha(old_stock.read_bytes()) == nv.stock.ORIGINAL_20240316_SHA,
               "INSPECT_PINNED_20240316_HASH_MISMATCH")
    image, source, plan, _receipt = nv.stock.extract_original(
        old_stock.read_bytes(), "p7u-cap192-f07")
    stock_20240316 = core.load_bundle(image, source, plan)
    return {"r2": candidate, "stock_20240710": stock_20240710,
            "stock_20240316": stock_20240316}


def _vector_record(raw: bytes) -> dict:
    core.check(len(raw) == 8, "INSTALLED_VECTOR_READ_INVALID")
    msp = int.from_bytes(raw[:4], "little")
    reset = int.from_bytes(raw[4:], "little")
    reset_address = reset & ~1
    # The pinned P7 linker supplies SRAM 0x20000000..0x20023FFF.
    # MSP may point one byte past that region; ResetISR must be in the app envelope.
    valid = (msp % 8 == 0 and 0x20000000 < msp <= 0x20024000
             and reset & 1 == 1 and 0x100 <= reset_address < 23 * core.gate.SECTOR)
    return {"msp": f"0x{msp:08X}", "reset_vector": f"0x{reset:08X}",
            "plausible_cc26x2_vector": valid}


async def inspect_installed_rom(rom, identity: dict, images: dict[str, core.Bundle], endpoint: str) -> dict:
    """Read application CRCs, vectors, NV5 page fingerprints and CCFG identity only."""
    core.check(set(images) == {"r2", "stock_20240710", "stock_20240316"},
               "INSPECT_IMAGE_SET_INCOMPLETE")
    core.check(all(len(bundle.sectors) == 23 for bundle in images.values()),
               "INSPECT_IMAGE_NOT_23_SECTORS")
    addresses = [addr for addr, _ in images["r2"].sectors]
    core.check(addresses == list(range(0, 23 * core.gate.SECTOR, core.gate.SECTOR))
               and all([addr for addr, _ in bundle.sectors] == addresses
                       for bundle in images.values()), "INSPECT_IMAGE_SECTOR_SET_MISMATCH")

    expected = {
        name: {addr: f"{binascii.crc32(data) & 0xffffffff:08x}"
               for addr, data in bundle.sectors}
        for name, bundle in images.items()
    }
    actual = {}
    for addr in addresses:
        crc = await rom.crc32(addr, core.gate.SECTOR)
        core.check(type(crc) is int and 0 <= crc <= 0xffffffff, "INSPECT_ROM_CRC_INVALID")
        actual[addr] = f"{crc:08x}"

    vector_bytes = await core.read_exact(rom, 0, 8)
    vectors = _vector_record(vector_bytes)
    expected_vectors = {name: _vector_record(bundle.sectors[0][1][:8])
                        for name, bundle in images.items()}
    exact_matches = [name for name, crcs in expected.items()
                     if all(actual[addr] == crcs[addr] for addr in addresses)
                     and vector_bytes == images[name].sectors[0][1][:8]]
    nv_pages = []
    for addr in range(core.gate.NV5_BASE, core.gate.CCFG_SECTOR, core.gate.SECTOR):
        header = await core.read_exact(rom, addr, 16)
        crc = await rom.crc32(addr, core.gate.SECTOR)
        core.check(type(crc) is int and 0 <= crc <= 0xffffffff,
                   "INSPECT_NV5_ROM_CRC_INVALID")
        nv_pages.append({"address": f"0x{addr:05X}",
                         "header_prefix_hex": header.hex(),
                         "page_state": header[0], "cycle": header[1],
                         "all_active_bits": header[2] & 3,
                         "format_version": header[2] >> 2, "signature": header[3],
                         "header_bytes_sha256": core.sha(header),
                         "header_all_ff": header == b"\xff" * 16,
                         "header_all_00": header == b"\x00" * 16,
                         "sector_crc32": f"{crc:08x}"})
    return {
        "schema": "p7u-installed-inspection-v1", "endpoint": endpoint,
        "identity": identity, "application_sector_count": len(addresses),
        "images": {name: {"sha256": bundle.hex_sha256,
                          "matches_all_sectors": name in exact_matches,
                          "sector_crc32": expected[name]}
                   for name, bundle in images.items()},
        "installed_sector_crc32": {f"0x{addr:05X}": actual[addr] for addr in addresses},
        "installed_vectors": vectors, "expected_vectors": expected_vectors,
        "exact_image_matches": exact_matches,
        "application_classification": exact_matches[0] if len(exact_matches) == 1
            else "unmatched" if not exact_matches else "ambiguous_exact_match",
        "nv5_pages": nv_pages,
        "flash_write_or_erase_performed": False,
    }


async def inspect_installed(target: dict, args) -> dict:
    core.check(args.unused_p7u, "P7U_UNUSED_UNIT_ACK_REQUIRED")
    core.check(args.already_in_rom_bsl, "P7U_MUST_ALREADY_BE_IN_ROM_BSL")
    core.check(not target["device"].startswith("socket://"),
               "INSPECT_INSTALLED_USB_ONLY_NO_MANAGEMENT_RESET")
    for key in ("factory_id_digest", "ccfg_sha256"):
        pinned = target.get("radio_" + key)
        core.check(type(pinned) is str and re.fullmatch(r"[0-9a-f]{64}", pinned) is not None,
                   "INSPECT_ORIGINAL_RADIO_IDENTITY_PIN_REQUIRED")
    images = expected_application_images(target, args)
    # Read-only management identity first; this command never asks management to enter BSL.
    management_identity = identify(target)
    async with LiveSmlightSession(target["device"]) as rom:
        # Validate the actual TI silicon, full CCFG and factory IEEE in ROM;
        # the SMLIGHT management MAC alone is not the radio identity.
        rom_identity = await core.observe(rom)
        # Management MAC does not independently bind the USB radio. Reuse
        # pinned identities from the independently verified original capture.
        for key in ("factory_id_digest", "ccfg_sha256"):
            core.check(rom_identity[key] == target["radio_" + key], "INSPECT_WRONG_RADIO_OR_CCFG_CHANGED")
        evidence = await inspect_installed_rom(
            rom, {"management": management_identity, "radio": rom_identity},
            images, target["device"])
        core.check(await core.observe(rom) == rom_identity,
                   "INSPECT_IDENTITY_OR_CCFG_CHANGED_DURING_READ")
    app.json_write(args.out, evidence)
    blank_crc = f"{binascii.crc32(bytes([0xff]) * core.gate.SECTOR) & 0xffffffff:08x}"
    return {"status": "P7U_INSTALLED_INSPECTION_COMPLETE",
            "evidence_file": str(args.out),
            "application_classification": evidence["application_classification"],
            "exact_image_matches": evidence["exact_image_matches"],
            "installed_vectors_plausible": evidence["installed_vectors"]["plausible_cc26x2_vector"],
            "nv5_all_ff": all(page["header_all_ff"] and page["sector_crc32"] == blank_crc
                               for page in evidence["nv5_pages"]),
            "flash_write_or_erase_performed": False}


async def run(args) -> dict:
    core.check(not args.write or args.command in ("flash", "rollback", "prepare-nv5", "restore-nv5", "restore-app", "bootdiag"),
               "P7U_WRITE_NOT_VALID_FOR_COMMAND")
    core.check(not args.resume or args.command == "backup", "P7U_RESUME_BACKUP_ONLY")
    if args.write:
        core.check(args.plan is not None and bool(args.approve) and args.recovery_proven,
                   "P7U_WRITE_REQUIRES_PLAN_DIGEST_AND_RECOVERY_PROOF")
    target = load_target(args.target)
    packet = validate_packet(target, args)  # Always offline before hardware.
    if args.command == "check":
        return {**packet, "status": "P7U_R2_AND_PINNED_ROLLBACK_VALIDATED_OFFLINE",
                "hardware_contacted": False, "flash_performed": False}
    if args.command == "identify":
        return identify(target)
    if args.command != "backup":  # Backup core exclusively creates its own directory.
        core.check(args.out is not None, "P7U_NEW_OUTPUT_REQUIRED")
        core.check(not args.out.exists() and not args.out.is_symlink(), "P7U_OUTPUT_MUST_BE_NEW")
    if args.command in ("enter-bsl", "restart-radio"):
        core.check(args.unused_p7u, "P7U_UNUSED_UNIT_ACK_REQUIRED")
        # Reserve the receipt before issuing a radio command, never overwrite a backup.
        with args.out.open("x", encoding="utf8") as receipt:
            receipt.write('{"status":"RADIO_COMMAND_PENDING_DO_NOT_RETRY_BLINDLY"}\n')
            receipt.flush()
            result = radio_control(target, args.command)
            receipt.seek(0)
            receipt.truncate()
            receipt.write(json.dumps(result, sort_keys=True) + "\n")
        return result
    if args.command == "inspect-installed":
        return await inspect_installed(target, args)
    if args.command == "bootdiag":
        import p7u_bootdiag as bd
        core.check(args.unused_p7u and args.already_in_rom_bsl, "BOOTDIAG_UNUSED_USB_ALREADY_IN_BSL_REQUIRED")
        core.check(args.bootdiag_native is not None and args.bootdiag_commit,
                   "BOOTDIAG_NATIVE_ARTIFACT_AND_COMMIT_REQUIRED")
        for key in ("factory_id_digest", "ccfg_sha256"):
            pinned = target.get("radio_" + key)
            core.check(type(pinned) is str and re.fullmatch(r"[0-9a-f]{64}", pinned) is not None,
                       "INSPECT_ORIGINAL_RADIO_IDENTITY_PIN_REQUIRED")
        baseline, _fallback = app.load_request(app_request(target, args))
        candidate, stock = bd.paired_images(args.bootdiag_native, original_vendor(target).read_bytes(),
                                             baseline, args.bootdiag_commit)
        selected = stock if args.bootdiag_stock else candidate
        plan = core.load_json(args.plan) if args.write else None
        if args.write:
            core.validate_approval(selected, plan, args.approve, target["device"])
        bd.Session(target["device"])  # Reject socket/implicit reset before any contact.
        identify(target)
        async with bd.Session(target["device"]) as rom:
            if args.write:
                result = await bd.execute(rom, selected, baseline, target["device"], target,
                                          plan, args.approve, diagnostic=not args.bootdiag_stock)
            else:
                result = await bd.inspect(rom, selected, baseline, target["device"], target,
                                          diagnostic=not args.bootdiag_stock)
        app.json_write(args.out, result)
        return {"status": result.get("status", "BOOTDIAG24_READ_ONLY_PLAN_CREATED"),
                "evidence_file": str(args.out), "application_sectors": 24,
                "approval_digest": result.get("approval_digest"),
                "flash_performed": bool(args.write), "temporary_diagnostic_profile": True}
    if args.command in ("flash", "rollback"):
        if not target["device"].startswith("socket://"):
            core.check(args.already_in_rom_bsl, "P7U_USB_MUST_ALREADY_BE_IN_ROM_BSL")
        result = await app.run(app_request(target, args))
        app.json_write(args.out, result)
        return result
    if args.command == "restore-app":
        request = SimpleNamespace(
            backup_dir=args.backup, backup_copy_dir=args.copy,
            independent_copy_confirmed=args.independent_copy,
            official_stock_bin=original_vendor(target), unused_p7u=args.unused_p7u,
            already_in_rom_bsl=args.already_in_rom_bsl, device=target["device"],
            management_mac=target["management_mac"], out=args.out, write=args.write,
            recovery_proven=args.recovery_proven, plan=args.plan, approve_digest=args.approve)
        result = await original.run(request)
        app.json_write(args.out, result)
        return result
    # NV core owns its capture/plan/receipt directories and all existing guards.
    result = await nv.run(nv_request(target, args))
    if args.command == "verify-backup":
        app.json_write(args.out, result)
    return result


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=COMMANDS, nargs="?", default="check")
    p.add_argument("--target", type=Path, required=True, help="Private target JSON; see P7U_TOOL.md")
    p.add_argument("--out", type=Path, help="New receipt file, or new directory for NV operations")
    p.add_argument("--backup", type=Path)
    p.add_argument("--copy", type=Path, help="Independently stored, verified original backup")
    p.add_argument("--independent-copy", action="store_true")
    p.add_argument("--unused-p7u", action="store_true")
    p.add_argument("--already-in-rom-bsl", action="store_true")
    p.add_argument("--recovery-proven", action="store_true", help="Stock/ROM/stock/ROM proved and stock rollback available")
    p.add_argument("--write", action="store_true", help="Execute the supplied plan; otherwise inspect only")
    p.add_argument("--plan", type=Path)
    p.add_argument("--approve", help="Exact digest from the separate inspected plan")
    p.add_argument("--original-network-quiescent", action="store_true")
    p.add_argument("--resume", action="store_true", help="Resume an interrupted read-only backup only")
    p.add_argument("--bootdiag-native", type=Path, help="Exact temporary bootdiag native artifact directory")
    p.add_argument("--bootdiag-commit", help="Exact commit recorded by that native CI build")
    p.add_argument("--bootdiag-stock", action="store_true", help="Inspect/execute paired original stock cleanup through 0x30000")
    p.epilog = ("inspect-installed is read-only: require --unused-p7u and --already-in-rom-bsl; "
                "it never commands a reset, erase, program, NV restore or CCFG write.")
    return p


def main():
    args = parser().parse_args()
    try:
        print(json.dumps(asyncio.run(run(args)), sort_keys=True))
    except Exception as exc:
        reason = (str(exc) if isinstance(exc, (core.StrictError, RomWireError, BslConnectionError))
                  else "P7U_INPUT_IO_OR_PROTOCOL_FAILED")
        print(json.dumps({"status": "FAIL_CLOSED", "error_code": reason,
                          "automatic_retry_or_reset_issued": False}, sort_keys=True))
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
