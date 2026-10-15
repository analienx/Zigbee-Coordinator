#!/usr/bin/env python3
"""Pinned 20240316 original app + NV recovery, full fake flash; never hardware."""
import argparse
import asyncio
import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[2] / "firmware/slzb-06p7u/qualification"
sys.path.insert(0, str(BASE))
import p7u_original_rollback as original
import p7u_nv_recovery as nv
import p7u_stock_rollback as stock
import p7u_strict_sector_writer as core
from test_strict_sector_writer import FakeROM


def reject(function, code):
    try: function()
    except core.StrictError as exc: assert str(exc) == code, (str(exc), code)
    else: raise AssertionError("accepted " + code)


async def rejects(awaitable, code):
    try: await awaitable
    except core.StrictError as exc: assert str(exc) == code, (str(exc), code)
    else: raise AssertionError("accepted " + code)


def reseal(plan):
    plan.pop("approval_digest", None)
    plan["approval_digest"] = core.sha(core.canonical(plan))
    return plan


async def tests(vendor):
    legacy = core.sha(vendor) == stock.ORIGINAL_20240316_SHA
    length = 172240 if legacy else stock.APP_BYTES
    image, source, plan, receipt = stock.extract_original(vendor, "p7u-cap192-f07")
    assert receipt["version"] == ("20240316" if legacy else "20240710")
    assert receipt["app_payload_bytes"] == length
    assert receipt["manufacturer_container_sha256"] == (stock.ORIGINAL_20240316_SHA if legacy else stock.VENDOR_SHA)
    assert core.sha(vendor[28+length:]) == (stock.ORIGINAL_20240316_CCFG_SHA if legacy else core.gate.VENDOR_CCFG_SHA256)
    if legacy:
        reject(lambda: stock.extract(vendor, "p7u-cap192-f07"), "STOCK_VENDOR_SOURCE_HASH_MISMATCH")
    else:
        assert stock.extract(vendor, "p7u-cap192-f07") == (image, source, plan, receipt)
    reject(lambda: stock.extract_original(vendor[:-1], "p7u-cap192-f07"), "STOCK_VENDOR_SOURCE_HASH_MISMATCH")
    corrupt = bytearray(vendor); corrupt[100] ^= 1
    reject(lambda: stock.extract_original(bytes(corrupt), "p7u-cap192-f07"), "STOCK_VENDOR_SOURCE_HASH_MISMATCH")
    rom = FakeROM()
    rom.flash[:length] = vendor[28:28+length]
    rom.flash[core.gate.CCFG_START:core.gate.CCFG_END] = vendor[28+length:]
    rom.flash[nv.NV_START:nv.NV_END] = bytes((i * 17) % 251 for i in range(nv.NV_END-nv.NV_START))
    pristine = bytes(rom.flash)
    descriptor = nv.target_descriptor(nv.MODEL, "1.73", "v3.2.6.dev3", "01:23:45:67:89:AB")
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp); one = root/"original"; two = root/"copy"
        one.mkdir()
        manifest = await nv.capture(rom, one, "COM31", descriptor)
        shutil.copytree(one, two)
        bundle, verified, proof = original.original_bundle(one, two, vendor)
        assert manifest == verified
        assert proof["manufacturer_sha256"] == receipt["manufacturer_container_sha256"]
        assert proof["original_app_bytes"] == length
        assert tuple(a for a, _ in bundle.sectors) == core.APP_SECTOR_ADDRESSES
        assert b"".join(b for _, b in bundle.sectors) == pristine[:0x2E000]

        # Emulate R2 app and trial NV; original-app rollback must leave trial NV untouched.
        rom.flash[:0x2E000] = b"\xa5" * 0x2E000
        rom.flash[nv.NV_START:nv.NV_END] = b"\x69" * (nv.NV_END-nv.NV_START)
        outside = bytes(rom.flash[0x2E000:])
        approval = await original.inspect(rom, bundle, "COM31", manifest, proof)
        assert len(approval["outside_application_crc32"]) == 65
        for mutation, code in (
            (lambda p: p.update(original_backup_digest="0"*64), "ORIGINAL_APPROVAL_NOT_BOUND_TO_VERIFIED_CAPTURE"),
            (lambda p: p.update(original_application={}), "ORIGINAL_APPROVAL_NOT_BOUND_TO_VERIFIED_CAPTURE"),
            (lambda p: p.update(outside_application_crc32=[]), "ORIGINAL_OUTSIDE_CRC_LIST_INVALID"),
        ):
            altered = copy.deepcopy(approval); mutation(altered); reseal(altered)
            reject(lambda: original.validate(bundle, altered, altered["approval_digest"], "COM31", manifest, proof), code)
        reject(lambda: original.validate(bundle, approval, "0"*64, "COM31", manifest, proof), "APPROVAL_TOKEN_MISMATCH")
        reject(lambda: original.validate(bundle, approval, approval["approval_digest"], "COM32", manifest, proof), "APPROVAL_TARGET_OR_IMAGE_CHANGED")
        changed = copy.deepcopy(rom); changed.flash[nv.NV_START] ^= 1
        await rejects(original.execute(changed,bundle,approval,approval["approval_digest"],"COM31",manifest,proof),
                      "ORIGINAL_OUTSIDE_CHANGED_SINCE_INSPECT")
        assert changed.erases == []
        changed = copy.deepcopy(rom); changed.flash[core.gate.CCFG_START] ^= 1
        await rejects(original.execute(changed,bundle,approval,approval["approval_digest"],"COM31",manifest,proof),
                      "ORIGINAL_TARGET_NOT_CAPTURED_DEVICE")
        assert changed.erases == []

        # Reject a mismatched backup/app, even if the operator can supply a receipt.
        damaged = bytearray(pristine); damaged[100] ^= 1
        reject(lambda: nv.known_original_application(bytes(damaged), vendor), "NV_CAPTURED_ORIGINAL_APP_NOT_PINNED_STOCK")
        damaged = bytearray(pristine); damaged[0x40000] = 0
        reject(lambda: nv.known_original_application(bytes(damaged), vendor), "NV_CAPTURED_ORIGINAL_HAS_UNRECOVERABLE_APP_GAP_DATA")
        args = SimpleNamespace(backup_dir=one,backup_copy_dir=two,independent_copy_confirmed=True,
            unused_p7u=True,already_in_rom_bsl=True,device="COM31",management_mac="01:23:45:67:89:AB",
            out=root/"new.json",official_stock_bin=root/"vendor.bin",write=True,
            recovery_proven=True,plan=root/"approval.json",approve_digest="0"*64)
        args.official_stock_bin.write_bytes(vendor)
        args.plan.write_text(json.dumps(approval))
        with patch.object(original,"LiveSmlightSession",side_effect=AssertionError("radio contacted")) as session:
            await rejects(original.run(args), "APPROVAL_TOKEN_MISMATCH")
            session.assert_not_called()
            args.approve_digest=approval["approval_digest"]
            args.management_mac="00:11:22:33:44:55"
            await rejects(original.run(args), "ORIGINAL_ENDPOINT_OR_MANAGEMENT_MAC_NOT_CAPTURED_UNIT")
            session.assert_not_called()

        result = await original.execute(rom,bundle,approval,approval["approval_digest"],"COM31",manifest,proof)
        assert result["all_outside_application_sectors_unchanged"]
        assert not result["post_flash_radio_reset_issued"] and not result["original_network_restored"]
        assert rom.erases == list(core.APP_SECTOR_ADDRESSES[1:]) + [0]
        assert bytes(rom.flash[:0x2E000]) == pristine[:0x2E000]
        assert bytes(rom.flash[0x2E000:]) == outside
        await nv.require_original_application_live(rom, pristine)

        # App recovery precedes NV recovery; the original TI 20240316 source is accepted
        # without changing NV's five-sector backend into an application writer.
        from test_nv_recovery import FakeROM as NvROM
        nrom = NvROM.__new__(NvROM)
        nrom.__dict__.update(flash=bytearray(rom.flash),factory=b"abcdefgh",erases=[],sent=0,reads=0,
            pending=None,fail_erase=None,fail_send=None,fail_read=None,change_ccfg=False,change_other=False,bad_crc=False)
        nvplan = await nv.inspect(nrom,one,two,"COM31","restore-original-nv5",vendor)
        await nv.execute(nrom,one,two,"COM31",nvplan,nvplan["digest"],nv.QUIESCENT,vendor)
        assert bytes(nrom.flash) == pristine
        assert set(nrom.erases) == set(nv.NV_SECTORS)
    print(f"P7U_PINNED_{receipt['version']}_ORIGINAL_APP_THEN_NV_RESTORE_PASS_NO_HARDWARE")


if __name__ == "__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--vendor",type=Path,required=True)
    parser.add_argument("--paired-vendor",type=Path)
    args=parser.parse_args()
    asyncio.run(tests(args.vendor.read_bytes()))
    if args.paired_vendor:
        asyncio.run(tests(args.paired_vendor.read_bytes()))
