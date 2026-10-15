#!/usr/bin/env python3
"""Safeguarded read-only original P7U raw FLASH escrow; no radio writes.

When explicitly invoked, needs a radio ALREADY in qualified TI ROM BSL or
SMLIGHT-managed network BSL entry (radio reset). Never auto-executes.
Preserves raw application, original NV2/NV5 and actual per-device CCFG.
"""
from __future__ import annotations
import argparse,asyncio,binascii,hashlib,json
from pathlib import Path
import p7u_strict_sector_writer as strict
from p7u_rom_transport import LiveSmlightSession

FLASH_BYTES=strict.gate.RADIO_SIZE
SECTOR=strict.gate.SECTOR
PRIVATE_ROOT=Path(r"C:\Workspace\.analienx\sonoff-private")

def check_private(root:Path) -> None:
    resolved=root.resolve()
    private=PRIVATE_ROOT.resolve()
    strict.check(private in resolved.parents,"ESCROW_PRIVATE_ROOT_REQUIRED")
    strict.check(not root.exists() and not root.is_symlink(),"ESCROW_OUTPUT_MUST_BE_NEW")
    strict.check(SECTOR==8192 and FLASH_BYTES==0xB0000,
                 "P7U_EXPECTED_FLASH_GEOMETRY_CHANGED")

async def capture(rom,folder:Path)->dict:
    """Capture full physical flash with two target CRC rounds per sector.

    Caller has independently validated this P7U and private output path.
    Device-borne secrets never appear in console/log receipts.
    """
    identity=await strict.observe(rom)
    strict.check(identity["flash_bytes"]==FLASH_BYTES,"ESCROW_RADIO_SIZE_CHANGED")
    filename="original_p7u_raw_704k.private.bin"
    partial=folder/(filename+".partial")
    receipt=folder/"original_flash_readback_seal.json"
    sector_sha=[];nv5blank=True
    with partial.open("xb") as fd:
        for address in range(0,FLASH_BYTES,SECTOR):
            raw=await strict.read_exact(rom,address,SECTOR)
            strict.check(len(raw)==SECTOR,"ESCROW_SHORT_SECTOR_READ")
            crc=binascii.crc32(raw)&0xffffffff
            first=await rom.crc32(address,SECTOR)
            second=await rom.crc32(address,SECTOR)
            strict.check(first==crc and second==crc,"ESCROW_ROM_CRC_MISMATCH")
            fd.write(raw)
            sector_sha.append(hashlib.sha256(raw).hexdigest())
            if strict.gate.NV5_BASE<=address<strict.gate.CCFG_SECTOR:
                nv5blank=nv5blank and raw==b"\xff"*SECTOR
        fd.flush()
    unchanged=await strict.observe(rom)
    strict.check(identity==unchanged,"ESCROW_RADIO_CHANGED_DURING_CAPTURE")
    entire=partial.read_bytes()
    strict.check(len(entire)==FLASH_BYTES,"ESCROW_LENGTH_MISMATCH")
    ccfg=entire[strict.gate.CCFG_START:strict.gate.CCFG_START+strict.gate.CCFG_SIZE]
    strict.check(strict.sha(ccfg)==identity["ccfg_sha256"],
                 "ESCROW_INSTALLED_CCFG_INCONSISTENT")
    # This is a copy; never rewrite CCFG or IEEE from a different board.
    raw_digest=strict.sha(entire)
    final=folder/filename
    partial.rename(final)
    result={
     "status":"ORIGINAL_SAME_DEVICE_FLASH_PRESERVED_READ_ONLY",
     "flash_bytes":FLASH_BYTES,"sector_bytes":SECTOR,"sector_count":len(sector_sha),
     "raw_sha256":raw_digest,"sector_sha256":sector_sha,
     "identity":identity,"initial_nv5_all_ff":nv5blank,
     "nv5_bytes_captured":strict.gate.CCFG_SECTOR-strict.gate.NV5_BASE,
     "raw_private_file":filename,
     "ccfg_sector_untouched":True,"nv_and_app_untouched":True,
     "no_rom_erase_write_reset_called":True,
     "rom_bsl_reentry_twice_proven":False,
     "stock_app_rollback_physically_proven":False,
     "flash_authorized":False,"nv5_erase_authorized":False,
    }
    with receipt.open("x",encoding="utf8") as out:
        out.write(json.dumps(result,sort_keys=True,indent=2)+"\n")
    return {"status":result["status"],"flash_bytes":FLASH_BYTES,
      "raw_sha256":raw_digest,"nv5_all_ff":nv5blank,
      "ccfg_sha256":identity["ccfg_sha256"],
      "same_device_identity_after_capture":True,
      "flash_authorized":False,"rom_bsl_reentry_twice_proven":False}

async def run(args):
    if not args.capture_from_bsl:
        return {"status":"NO_CAPTURE_REQUESTED","writes":False,
                "flash_authorized":False}
    strict.check(args.isolated_spare_only,"ESCROW_ISOLATED_P7U_REQUIRED")
    strict.check(bool(args.device),"ESCROW_DEVICE_REQUIRED")
    strict.check(args.device.startswith("socket://")
      or args.confirm_verified_usb_board,"ESCROW_USB_BOARD_UNVERIFIED")
    if args.device.startswith("socket://"):
        strict.check(bool(args.expected_spare_mac)
           and args.acknowledge_network_bsl_reset,
           "ESCROW_NETWORK_BSL_RESET_EXPLICIT_GATE_REQUIRED")
    check_private(args.out_private_dir)
    async with LiveSmlightSession(args.device,args.expected_spare_mac) as rom:
        args.out_private_dir.mkdir(parents=True)
        return await capture(rom,args.out_private_dir)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--device",help="Explicit /dev/ttyACM#, COM# or socket://host:6638; isolated spare only")
    p.add_argument("--out-private-dir",type=Path,required=True)
    p.add_argument("--expected-spare-mac")
    p.add_argument("--capture-from-bsl",action="store_true")
    p.add_argument("--isolated-spare-only",action="store_true")
    p.add_argument("--confirm-verified-usb-board",action="store_true")
    p.add_argument("--acknowledge-network-bsl-reset",action="store_true")
    args=p.parse_args()
    try:
        result=asyncio.run(run(args))
        print(json.dumps(result,sort_keys=True))
    except Exception as exc:
        print(json.dumps({"status":"FAIL_CLOSED", "error_code":
          str(exc) if isinstance(exc,strict.StrictError) else "ROM_ESCROW_OR_CONNECTION_FAILED",
          "flash_authorized":False,"no_automatic_retry":True}))
        raise SystemExit(2) from None

if __name__=="__main__":main()
