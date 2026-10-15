#!/usr/bin/env python3
"""Synthetic-only NV5 preflight, no sensitive real device data."""
import copy,hashlib,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/"firmware/slzb-06p7u/qualification"))
import p7u_nv5_preservation_plan as gate

def fixture(nonblank=True):
    raw=bytearray(b"\xff"*gate.FLASH_SIZE)
    raw[0]=0x13
    raw[gate.CCFG_START:gate.CCFG_START+4]=b"\xc5\x0f\x00\xc5"
    if nonblank:
        raw[gate.NV5_START]=0x43
        raw[gate.NV5_START+2*gate.SECTOR]=0x91
    raw=bytes(raw)
    label={
        "status":"ORIGINAL_SAME_DEVICE_FLASH_PRESERVED_READ_ONLY",
        "flash_bytes":gate.FLASH_SIZE,
        "sector_bytes":gate.SECTOR,
        "sector_count":gate.FLASH_SIZE//gate.SECTOR,
        "raw_sha256":gate.hash256(raw),
        "sector_sha256":[gate.hash256(raw[i:i+gate.SECTOR])
           for i in range(0,len(raw),gate.SECTOR)],
        "identity":{"silicon_wafer":"CC13x2x7_CC26x2x7_0xBB77",
          "rom_backdoor_pin":"TI_DIO15_ACTIVE_LOW",
          "flash_bytes":gate.FLASH_SIZE,
          "read_only_identity":True,
          "ccfg_sha256":gate.hash256(raw[gate.CCFG_START:gate.CCFG_START+88])},
        "ccfg_sector_untouched":True,"nv_and_app_untouched":True,
        "no_rom_erase_write_reset_called":True,
        "nv5_bytes_captured":5*gate.SECTOR,
        "initial_nv5_all_ff":not nonblank
    }
    return raw,label

def reject(code,fun):
    try:fun()
    except gate.GateError as e:assert str(e)==code,(str(e),code)
    else:raise AssertionError("FAIL_OPEN: "+code)

raw,seal=fixture()
report=gate.inspect(raw,seal)
assert report["all_five_nv5_blank"] is False
assert sum(x["non_ff_bytes"]>0 for x in report["nv5_sector_digests"])==2
assert report["nv5_erase_authorized"] is False
assert report["application_flash_authorized"] is False
assert report["restore_original_NV2_after_stock_rollback_required"] is True
assert report["exact_nv5_sector_allowlist"] == [
    "0xA4000","0xA6000","0xA8000","0xAA000","0xAC000"
]
assert report["ccfg_protected_sector"]=="0xAE000"
r2,s2=fixture(nonblank=False)
assert gate.inspect(r2,s2)["all_five_nv5_blank"] is True
bad=copy.deepcopy(seal);bad["raw_sha256"]="0"*64
reject("ORIGINAL_RAW_HASH_MISMATCH",lambda:gate.inspect(raw,bad))
bad=copy.deepcopy(seal);bad["sector_sha256"][0]="f"*64
reject("ORIGINAL_SECTOR_DIGEST_MISMATCH",lambda:gate.inspect(raw,bad))
bad=copy.deepcopy(seal);bad["identity"]["silicon_wafer"]="WRONG"
reject("ORIGINAL_RADIO_IDENTITY_UNQUALIFIED",lambda:gate.inspect(raw,bad))
bad=copy.deepcopy(seal);bad["identity"]["ccfg_sha256"]="0"*64
reject("ORIGINAL_CCFG_SHA_MISMATCH",lambda:gate.inspect(raw,bad))
bad=copy.deepcopy(seal);bad["initial_nv5_all_ff"]=True
reject("ESCROW_NV5_BLANK_ASSERTION_MISMATCH",lambda:gate.inspect(raw,bad))
bad=copy.deepcopy(seal);bad["no_rom_erase_write_reset_called"]=False
reject("ESCROW_READONLY_PRESERVATION_UNPROVEN",lambda:gate.inspect(raw,bad))
reject("ORIGINAL_FLASH_SIZE_INVALID",lambda:gate.inspect(raw[:gate.FLASH_SIZE-4],seal))
print("P7U_NV5_EXACT_FIVE_SECTOR_OFFLINE_PLAN_TEST_PASS_NO_ERASE")
