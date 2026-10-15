#!/usr/bin/env python3
"""One P7U/R2 operator entry point; check is offline, writes require a fresh plan.

Reuses the existing sector writer and NV recovery implementation. Management
and serial endpoints are separate so Wi-Fi management works with USB radio data.
"""
from __future__ import annotations

import argparse
import asyncio
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
from p7u_rom_transport import normalized_mac, BslConnectionError
from p7u_rom_lowlevel import RomWireError


COMMANDS = ("check", "identify", "enter-bsl", "restart-radio", "probe", "backup",
            "verify-backup", "prepare-nv5", "restore-nv5", "flash", "rollback", "restore-app")


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


async def run(args) -> dict:
    core.check(not args.write or args.command in ("flash", "rollback", "prepare-nv5", "restore-nv5", "restore-app"),
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
