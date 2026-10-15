#!/usr/bin/env python3
"""Offline NV5 exact five-sector preservation / preparation preflight.

Consumes separately-captured raw original P7U 704-KiB FLASH + receipt.
No firmware writes, no BSL, no serial, no live radio, no erase operations.
Never dumps raw sector bytes or Zigbee keys to a log or to Git.
"""
from __future__ import annotations
import argparse,binascii,hashlib,json,re
from pathlib import Path

SECTOR=8192
FLASH_SIZE=0xB0000
NV5_START=0xA4000
CCFG_START=0xAE000
NV5_ADDRESSES=tuple(range(NV5_START,CCFG_START,SECTOR))
ESCROW="original_p7u_raw_704k.private.bin"
RECEIPT="original_flash_readback_seal.json"
PRIVATE=Path(r"C:\Workspace\.analienx\sonoff-private")

class GateError(ValueError):pass

def check(value:bool,code:str):
    if not value:raise GateError(code)

def hash256(data:bytes)->str:
    return hashlib.sha256(data).hexdigest()

def inspect(original:bytes,seal:dict)->dict:
    check(len(original)==FLASH_SIZE,"ORIGINAL_FLASH_SIZE_INVALID")
    check(isinstance(seal,dict) and seal.get("status")==
          "ORIGINAL_SAME_DEVICE_FLASH_PRESERVED_READ_ONLY","READBACK_SEAL_UNTRUSTED")
    check(seal.get("flash_bytes")==FLASH_SIZE and seal.get("sector_bytes")==SECTOR
          and seal.get("sector_count")==FLASH_SIZE//SECTOR,
          "ESCROW_SECTOR_GEOMETRY_INVALID")
    check(seal.get("raw_sha256")==hash256(original),"ORIGINAL_RAW_HASH_MISMATCH")
    per=seal.get("sector_sha256")
    check(type(per) is list and len(per)==FLASH_SIZE//SECTOR,
          "ESCROW_SECTOR_DIGEST_ROSTER_INVALID")
    for i in range(len(per)):
        check(type(per[i]) is str and per[i]==hash256(original[i*SECTOR:(i+1)*SECTOR]),
              "ORIGINAL_SECTOR_DIGEST_MISMATCH")
    identity=seal.get("identity")
    check(type(identity) is dict and identity.get("flash_bytes")==FLASH_SIZE
          and identity.get("silicon_wafer")=="CC13x2x7_CC26x2x7_0xBB77"
          and identity.get("rom_backdoor_pin")=="TI_DIO15_ACTIVE_LOW"
          and identity.get("read_only_identity") is True,
          "ORIGINAL_RADIO_IDENTITY_UNQUALIFIED")
    ccfg=original[CCFG_START:CCFG_START+88]
    check(identity.get("ccfg_sha256")==hash256(ccfg),
          "ORIGINAL_CCFG_SHA_MISMATCH")
    check(seal.get("ccfg_sector_untouched") is True
          and seal.get("nv_and_app_untouched") is True
          and seal.get("no_rom_erase_write_reset_called") is True
          and seal.get("nv5_bytes_captured")==5*SECTOR,
          "ESCROW_READONLY_PRESERVATION_UNPROVEN")
    blocks=[original[a:a+SECTOR] for a in NV5_ADDRESSES]
    all_ff=all(v==b"\xff"*SECTOR for v in blocks)
    check(seal.get("initial_nv5_all_ff") is all_ff,
          "ESCROW_NV5_BLANK_ASSERTION_MISMATCH")
    return {
       "schema":"p7u-five-sector-NV5-preservation-v1",
       "source_raw_sha256":hash256(original),
       "ccfg_sha256":hash256(ccfg),
       "original_nv5_sha256":hash256(b"".join(blocks)),
       "nv5_sector_digests": [
          {"address":f"0x{addr:05X}","length":SECTOR,"original_sha256":hash256(v),
           "non_ff_bytes":sum(x!=255 for x in v)}
          for addr,v in zip(NV5_ADDRESSES,blocks)
       ],
       "all_five_nv5_blank":all_ff,
       "exact_nv5_sector_allowlist":[f"0x{a:05X}" for a in NV5_ADDRESSES],
       "ccfg_protected_sector":"0xAE000",
       "ccfg_original_sha256":hash256(original[CCFG_START:CCFG_START+SECTOR]),
       "original_704k_recovery_escrow_verified_offline":True,
       "radio_hardware_live_readback_confirmed":False,
       "same_device_rom_reentry_physically_proven":False,
       "same_device_stock_rollback_physically_proven":False,
       "nv5_prepare_plan_ready_for_independent_review":not all_ff,
       "nv5_erase_authorized":False,
       "nv5_write_authorized":False,
       "application_flash_authorized":False,
       "restore_original_NV2_after_stock_rollback_required":not all_ff,
       "prerequisite":"EXACT_ROM_IDENTITY_AND_RECOVERY_APPROVAL_REQUIRED",
    }

def check_private(path:Path):
    resolved=path.resolve()
    root=PRIVATE.resolve()
    check(root==resolved or root in resolved.parents,"PRIVATE_ESCROW_ROOT_REQUIRED")

def run(source_dir:Path,output:Path)->dict:
    check_private(source_dir)
    check_private(output.parent)
    check(not output.exists() and not output.is_symlink(),"PLAN_OUTPUT_MUST_BE_NEW")
    raw=source_dir/ESCROW
    seal=source_dir/RECEIPT
    check(raw.is_file() and seal.is_file(),"ORIGINAL_ESCROW_FILES_REQUIRED")
    try:
        source=raw.read_bytes()
        report=json.loads(seal.read_text("utf-8"))
    except (OSError,UnicodeDecodeError,json.JSONDecodeError) as e:
        raise GateError("ESCROW_READ_OR_JSON_FAILED") from e
    plan=inspect(source,report)
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open("x",encoding="utf-8") as f:
        f.write(json.dumps(plan,indent=2,sort_keys=True)+"\n")
    return {"result":"OFFLINE_NV5_PRESERVATION_INSPECTED_NO_ERASE",
            "original_raw_sha256":plan["source_raw_sha256"],
            "nv5_blank":plan["all_five_nv5_blank"],
            "nv5_nonblank_sector_count":sum(x["non_ff_bytes"]>0 for x in plan["nv5_sector_digests"]),
            "nv5_erase_authorized":False,"application_flash_authorized":False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--escrow-private-dir",type=Path,required=True)
    p.add_argument("--out-private-plan",type=Path,required=True)
    a=p.parse_args()
    try: print(json.dumps(run(a.escrow_private_dir,a.out_private_plan),sort_keys=True))
    except (GateError,OSError) as e:
        print(json.dumps({"status":"FAIL_CLOSED",
             "code":str(e) if isinstance(e,GateError) else "ESCROW_IO_FAILED",
             "nv5_erase_authorized":False,"flash_authorized":False},sort_keys=True))
        raise SystemExit(2) from None

if __name__=="__main__":main()
