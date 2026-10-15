#!/usr/bin/env python3
"""Offline CLI and approval regression tests. Never imports a live driver."""
import asyncio
import dataclasses
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[2]/"firmware/slzb-06p7u/qualification"
sys.path.insert(0, str(BASE))
import p7u_flash_spare as cli
import p7u_strict_sector_writer as core
import p7u_stock_rollback as stock
from test_strict_sector_writer import FakeROM, make_bundle


def args_for(folder):
    return SimpleNamespace(
        app_only_hex=folder/"candidate.hex", full_image_evidence=folder/"source.json",
        sector_plan=folder/"plan.json", official_stock_bin=folder/"vendor.bin",
        rollback_app_hex=folder/"rollback.hex", rollback_receipt=folder/"receipt.json",
        approval_file=folder/"approval.json", out=folder/"result.json",
        phase="flash", target_image="candidate", isolated_spare_only=True,
        device="socket://spare-p7u.local:6638", expected_spare_mac="aa:bb:cc:dd:ee:ff",
        execute_radio_write=True, rom_bsl_reentry_twice_confirmed=True,
        stock_rollback_available=True, approve_digest=None, resume=False,
        accept_interrupted_sector_reerase=False)


def cli_output_checks(folder):
    original = b"keep recovery bytes intact"
    input_file = folder/"vendor.bin"
    input_file.write_bytes(original)
    common = [sys.executable, str(BASE/"p7u_flash_spare.py"),
        "--app-only-hex", str(input_file), "--full-image-evidence", str(input_file),
        "--sector-plan", str(input_file), "--official-stock-bin", str(input_file),
        "--rollback-app-hex", str(input_file), "--rollback-receipt", str(input_file)]
    result = subprocess.run(common+["--out", str(input_file)], capture_output=True, text=True)
    assert result.returncode==2, result.stderr
    assert json.loads(result.stdout)["error_code"]=="OUTPUT_COLLIDES_WITH_RECOVERY_INPUT"
    assert input_file.read_bytes()==original, "Error receipt overwrote stock backup"
    # Existing output, including hardlink aliases, must never be truncated.
    alias = folder/"alias.json"
    alias.hardlink_to(input_file)
    result = subprocess.run(common+["--out", str(alias)], capture_output=True, text=True)
    assert result.returncode==2 and json.loads(result.stdout)["error_code"]=="OUTPUT_MUST_BE_NEW"
    assert input_file.read_bytes()==alias.read_bytes()==original
    try:
        cli.json_write(alias, {"error":"failed"})
    except FileExistsError:
        pass
    else:
        raise AssertionError("Receipt writer overwrote existing recovery artifact")
    assert input_file.read_bytes()==original


async def approval_checks(folder):
    args = args_for(folder)
    bundle, raw, source, plan = make_bundle()
    rollback = dataclasses.replace(bundle, hex_sha256="f"*64)
    approval = await core.preflight(FakeROM(),bundle,args.device)
    approval.update(spare_management_mac_digest=core.sha(b"AABBCCDDEEFF"),
                    rollback_app_sha256=rollback.hex_sha256,
                    rollback_manufacturer_sha256=stock.VENDOR_SHA)
    def save(value):
        value.pop("approval_digest",None)
        value["approval_digest"]=core.sha(core.canonical(value))
        args.approval_file.write_text(json.dumps(value),encoding="utf8")
        args.approve_digest=value["approval_digest"]
    save(approval)
    entered=[]
    class NoContact:
        def __init__(self,*a): entered.append(a)
        async def __aenter__(self): raise AssertionError("Reset before offline approval checks")
        async def __aexit__(self,*a): pass
    with patch.object(cli,"load_request",return_value=(bundle,rollback)), \
         patch.object(cli,"LiveSmlightSession",NoContact):
        cases = (("APPROVAL_TOKEN_MISMATCH", lambda value: None),
                 ("APPROVAL_IDENTITY_INVALID", lambda value: value.pop("identity")),
                 ("APPROVAL_TARGET_OR_IMAGE_CHANGED", lambda value: value.update(endpoint="COM99")),
                 ("APPROVAL_PRIOR_CRC_INVALID", lambda value: value["sectors"][0].update(before_crc32="bad")))
        for code, mutate in cases:
            value=json.loads(json.dumps(approval))
            mutate(value)
            save(value)
            if code=="APPROVAL_TOKEN_MISMATCH": args.approve_digest="0"*64
            try:
                await cli.run(args)
            except core.StrictError as exc:
                assert str(exc)==code,(str(exc),code)
            else:
                raise AssertionError("Invalid approval accepted")
            assert entered==[],"Invalid approval contacted/reset a radio"
        value=json.loads(json.dumps(approval))
        value["approval_digest"]="0"*64
        args.approval_file.write_text(json.dumps(value))
        args.approve_digest="0"*64
        try:
            await cli.run(args)
        except core.StrictError as exc:
            assert str(exc)=="APPROVAL_FILE_TAMPERED"
        else:
            raise AssertionError("Tampered approval accepted")
        assert entered==[]

    # A generic smaller application passes core geometry but is outside RC1's
    # reviewed 23-sector contract, so the physical CLI must refuse it offline.
    args.app_only_hex.write_bytes(raw)
    args.full_image_evidence.write_text(json.dumps(source))
    args.sector_plan.write_text(json.dumps(plan))
    with patch.object(cli,"validate_stock",return_value=rollback):
        try:
            cli.load_request(args)
        except core.StrictError as exc:
            assert str(exc)=="RC1_REQUIRES_EXACT_23_APPLICATION_SECTORS"
        else:
            raise AssertionError("Non-RC1 application accepted by physical CLI")


def main():
    with tempfile.TemporaryDirectory() as tmp:
        folder=Path(tmp)
        cli_output_checks(folder)
        asyncio.run(approval_checks(folder))
    print("P7U_CLI_RECOVERY_INPUT_AND_PRE_RESET_APPROVAL_GUARDS_PASS_NO_DEVICE")


if __name__=="__main__":
    main()
