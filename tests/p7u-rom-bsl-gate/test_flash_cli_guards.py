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


async def initial_nv5_checks(folder):
    """Exercise real CLI preflight/write logic with the in-memory ROM only."""
    bundle, _, _, _ = make_bundle()
    args = args_for(folder)
    entered = []

    class NvROM(FakeROM):
        def __init__(self):
            super().__init__()
            self.nv_reads = []

        async def read_word(self, addr):
            if core.gate.NV5_BASE <= addr < core.gate.CCFG_SECTOR:
                self.nv_reads.append(addr)
            return await super().read_word(addr)

    async def run(rom, candidate=bundle):
        rollback = dataclasses.replace(candidate, hex_sha256="f"*64)

        class Session:
            def __init__(self, *unused):
                entered.append(rom)
            async def __aenter__(self):
                return rom
            async def __aexit__(self, *unused):
                pass

        with patch.object(cli, "load_request", return_value=(candidate, rollback)), \
             patch.object(cli, "LiveSmlightSession", Session):
            return await cli.run(args)

    def save(approval):
        approval.pop("approval_digest", None)
        approval["approval_digest"] = core.sha(core.canonical(approval))
        args.approval_file.write_text(json.dumps(approval), encoding="utf8")
        args.approve_digest = approval["approval_digest"]
        args.phase = "flash"

    async def reject(rom, reason, candidate=bundle):
        try:
            await run(rom, candidate)
        except core.StrictError as exc:
            assert str(exc) == reason, (str(exc), reason)
        else:
            raise AssertionError("Initial R2 accepted unprepared NV5")
        assert rom.erases == [], "NV5 guard ran after application erase"

    # Typical inherited stock NV2 occupies the last two pages of NV5. Inspect
    # records all five pages, but the resulting approval must fail before reset.
    inherited = NvROM()
    inherited.flash[core.gate.NV2_BASE:core.gate.CCFG_SECTOR] = b"\x96" * (2*core.gate.SECTOR)
    inherited_before = bytes(inherited.flash)
    args.phase = "inspect"
    approval = await run(inherited)
    assert approval["initial_nv5"]["all_ff"] is False
    assert approval["initial_nv5"]["sha256"] == core.sha(
        inherited_before[core.gate.NV5_BASE:core.gate.CCFG_SECTOR])
    expected_reads = list(range(core.gate.NV5_BASE, core.gate.CCFG_SECTOR, 4))
    assert inherited.nv_reads == expected_reads, "Inspect did not read every NV5 word"
    assert bytes(inherited.flash) == inherited_before
    save(approval)
    contacts = len(entered)
    await reject(inherited, "R2_INITIAL_NV5_NOT_PROVEN_BLANK")
    assert len(entered) == contacts, "Nonblank approval reset the radio"

    blank = NvROM()
    args.phase = "inspect"
    approval = await run(blank)
    assert approval["initial_nv5"] == cli.BLANK_NV5
    assert blank.nv_reads == expected_reads

    # Earlier approvals, or invented geometry/digests, cannot authorize R2.
    for bad_state in (None, {**cli.BLANK_NV5, "length": core.gate.SECTOR},
                      {**cli.BLANK_NV5, "sha256": "0"*64}):
        invalid = json.loads(json.dumps(approval))
        if bad_state is None:
            invalid.pop("initial_nv5")
        else:
            invalid["initial_nv5"] = bad_state
        save(invalid)
        contacts = len(entered)
        await reject(blank, "R2_INITIAL_NV5_NOT_PROVEN_BLANK")
        assert len(entered) == contacts

    # A correct approval is insufficient if any of the five pages changes.
    for page in range(5):
        changed = NvROM()
        changed.flash[core.gate.NV5_BASE + page*core.gate.SECTOR + core.gate.SECTOR-1] = 0
        save(json.loads(json.dumps(approval)))
        await reject(changed, "R2_INITIAL_NV5_CHANGED_OR_NOT_BLANK")
        assert changed.nv_reads == expected_reads, "Live guard skipped an NV5 word"

    changed_identity = NvROM()
    changed_identity.fc[core.FCFG_PRIMARY_IEEE] = b"ijklmnop"
    save(json.loads(json.dumps(approval)))
    await reject(changed_identity, "TARGET_IDENTITY_OR_CCFG_CHANGED")
    assert changed_identity.nv_reads == [], "Read private NV on a different target"

    # The legitimate blank first installation still programs through the real
    # restricted sector writer and preserves all NV and CCFG bytes.
    save(json.loads(json.dumps(approval)))
    blank.nv_reads.clear()
    original_nv = bytes(blank.flash[core.gate.NV5_BASE:core.gate.CCFG_SECTOR])
    result = await run(blank)
    assert result["sectors_written"] == len(bundle.sectors)
    assert blank.nv_reads == expected_reads
    assert bytes(blank.flash[core.gate.NV5_BASE:core.gate.CCFG_SECTOR]) == original_nv
    assert bytes(blank.flash[core.gate.CCFG_START:core.gate.CCFG_END]) == blank.ccfg

    # Existing NV must not block stock rollback or the R1 NV2 candidate. Neither
    # path inspects/initializes NV, and both retain application-only writes.
    for target, profile in (("stock", "p7u-cap192-f07"), ("candidate", "p7u-f07-stock")):
        retained = NvROM()
        retained.flash[core.gate.NV5_BASE:core.gate.CCFG_SECTOR] = b"\x96" * cli.NV5_BYTES
        prior_nv = bytes(retained.flash[core.gate.NV5_BASE:core.gate.CCFG_SECTOR])
        selected = dataclasses.replace(bundle, profile=profile)
        args.target_image = target
        args.phase = "inspect"
        prior = await run(retained, selected)
        assert "initial_nv5" not in prior
        save(prior)
        result = await run(retained, selected)
        assert result["sectors_written"] == len(bundle.sectors)
        assert retained.nv_reads == []
        assert bytes(retained.flash[core.gate.NV5_BASE:core.gate.CCFG_SECTOR]) == prior_nv
        assert bytes(retained.flash[core.gate.CCFG_START:core.gate.CCFG_END]) == retained.ccfg


def main():
    with tempfile.TemporaryDirectory() as tmp:
        folder=Path(tmp)
        cli_output_checks(folder)
        asyncio.run(approval_checks(folder))
        asyncio.run(initial_nv5_checks(folder))
    print("P7U_CLI_RECOVERY_INPUT_AND_PRE_RESET_APPROVAL_GUARDS_PASS_NO_DEVICE")


if __name__=="__main__":
    main()
