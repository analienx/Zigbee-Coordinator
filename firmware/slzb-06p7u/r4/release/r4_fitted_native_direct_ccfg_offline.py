#!/usr/bin/env python3
"""CC2652P7 fitted-board ROM-direct boot CCFG: PRIVATE OFFLINE PLAN ONLY.

NO serial/network/reset/erase/program commands. The two 704KiB factory
readbacks stay on the authorized owner's computer; never upload them to
GitHub/CI. Program and rollback are NOT implemented or authorized here.

The active board has factory IMAGE_VALID_CONF=0xAC000, DIO15-low ROM BSL
backdoor, and distinct fitted factory boost/DCDC CCFG compared with older
20240710 compile-time R4. The only proposed byte delta is IMAGE_VALID_CONF
0xAC000 -> 0x00000000; all other factory top sector bytes stay identical.

Reversing 0 -> 0xAC000 REQUIRES ERASE of the entire top 8KiB sector.
TI FlashSectorErase may rewrite security configuration defaults. A verified
manufacturer-managed 0xAE000 restore is an explicit external safety gate.
"""
from __future__ import annotations
import argparse
import binascii
import hashlib
import json
import struct
import sys
from pathlib import Path

HERE=Path(__file__).resolve().parents[1]/"b0"/"tools"
sys.path.insert(0,str(HERE))
from b0_image_audit import _parse_intel_hex

FULL=0xB0000
TOP=0xAE000
SECTOR=0x2000
CCFG=0xAFFA8
CCFG_BYTES=88
BOOT_WORD=0xAFFEC
APP_END=0x2E000
STOCK_VECTOR=0xAC000
FACTORY_SHA="ba654310cef8f1543a96c9bb6d5ef4f17411829642bcbe8249e91de6ae5b38f3"
APP_SHA="38fe3b5ddf06d79d4d9cbe90900c770d1b6042c9f7f4bd0216d292d966ca11e6"
EXPECTED_NATIVE_STOCK_DIFFS={
    1: (0xFFC00010,0xFF800010),  # fitted vs earlier R4: ALT_DCDC_VMIN 0xC vs 0x8
    3: (0xF1B9C1FF,0xFFB9C1FF),  # factory DCDC/boost bit differences
    17:(STOCK_VECTOR,0),         # native direct-vector IMAGE_VALID
}
FIELDS=(
    "EXT_LF_CLK","MODE_CONF_1","SIZE_AND_DIS_FLAGS","MODE_CONF",
    "VOLT_LOAD_0","VOLT_LOAD_1","RTC_OFFSET","FREQ_OFFSET",
    "IEEE_MAC_0","IEEE_MAC_1","IEEE_BLE_0","IEEE_BLE_1",
    "BL_CONFIG","ERASE_CONF","CCFG_TI_OPTIONS","CCFG_TAP_DAP_0",
    "CCFG_TAP_DAP_1","IMAGE_VALID_CONF","PROTECT_0_31",
    "PROTECT_32_63","PROTECT_64_95","PROTECT_96_127",
)
BL_CONFIG=0xAFFD8
PROTECT_64_95=0xAFFF8

def deny(reason):
    raise ValueError("R4_FITTED_NATIVE_DIRECT_OFFLINE_DENIED_"+reason)

def sha(b):
    return hashlib.sha256(b).hexdigest()

def crc(b):
    return "%08x"%(binascii.crc32(b)&0xffffffff)

def plan(factory1:bytes,factory2:bytes,native:dict[int,int],
         app_hex1:bytes,app_hex2:bytes,*,factory_pin:str=FACTORY_SHA,
         app_pin:str=APP_SHA, stock_top_crc:str="3c032e08")->tuple[bytes,bytes,dict]:
    if len(factory1)!=FULL or factory1!=factory2 or sha(factory1)!=factory_pin:
        deny("TWO_ORIGINAL_FACTORY_FLASH_PASSES_OR_SHA")
    if len(app_hex1)==0 or app_hex1!=app_hex2 or sha(app_hex1)!=app_pin:
        deny("TWO_IDENTICAL_NATIVE_APP_EXTRACTIONS")
    if not native or min(native)!=0 or max(native)>=FULL:
        deny("NATIVE_IMAGE_FLASH_SPAN")
    if not set(range(0x3C)).issubset(native):
        deny("NATIVE_VECTOR_TABLE_INCOMPLETE")
    sp=struct.unpack("<I",bytes(native[i] for i in range(4)))[0]
    reset=struct.unpack("<I",bytes(native[i] for i in range(4,8)))[0]
    if sp%8 or not 0x20000000<=sp<=0x20024000 or not reset&1 or not 0<(reset&~1)<APP_END:
        deny("R4_DIRECT_NATIVE_SP_RESET")
    if any(APP_END<=a<CCFG for a in native):
        deny("NATIVE_PAYLOAD_INTERSECTS_RESERVED_NV_OR_BOOT")
    if not set(range(CCFG,FULL)).issubset(native):
        deny("NATIVE_CCFG_NOT_FULL")
    if {a//SECTOR*SECTOR for a in native if a<CCFG} != set(range(0,APP_END,SECTOR)):
        deny("APPLICATION_NOT_EXACTLY_23_SECTORS")
    # Match the already verified byte-for-byte native app-only extraction
    # without bringing in its generator's own output trust.
    with __import__("tempfile").TemporaryDirectory() as tmp:
        p=Path(tmp)/"app.hex"
        p.write_bytes(app_hex1)
        data,err=_parse_intel_hex(p)
    if err or not data or data!={a:v for a,v in native.items() if a<APP_END}:
        deny("NATIVE_APP_HEX_NOT_SAME_COMPILED_IMAGE")
    original=factory1[TOP:FULL]
    if crc(original)!=stock_top_crc:
        deny("STOCK_TOP_SECTOR_CRC_NOT_PINNED")
    if struct.unpack_from("<I",factory1,BOOT_WORD)[0]!=STOCK_VECTOR:
        deny("OLD_FITTED_BOOT_ADDRESS_CHANGED")
    bsl=struct.unpack_from("<I",factory1,BL_CONFIG)[0]
    if bsl!=0xC5FE0FC5:
        deny("FITTED_ROM_BSL_DIO15_BACKDOOR_CHANGED")
    protect=struct.unpack_from("<I",factory1,PROTECT_64_95)[0]
    if not(protect & (1 << (87-64))):
        deny("FITTED_CCFG_TOP_SECTOR_WRITE_PROTECTED")
    compiled=bytes(native[i] for i in range(CCFG,FULL))
    observed={}
    for idx,name in enumerate(FIELDS):
        a=struct.unpack_from("<I",factory1,CCFG+idx*4)[0]
        b=struct.unpack_from("<I",compiled,idx*4)[0]
        if a!=b:
            if idx not in EXPECTED_NATIVE_STOCK_DIFFS or (a,b)!=EXPECTED_NATIVE_STOCK_DIFFS[idx]:
                deny("UNEXPECTED_COMPILED_CCFG_DRIFT_"+name)
            observed[name]={"factory":hex(a),"native":hex(b)}
        elif idx in EXPECTED_NATIVE_STOCK_DIFFS:
            deny("EXPECTED_FITTED_VS_NATIVE_CCFG_DIFFERENCE_MISSING_"+name)
    if set(observed)!={"MODE_CONF_1","MODE_CONF","IMAGE_VALID_CONF"}:
        deny("CCFG_FITTED_VENDOR_PROFILE_NOT_RECOGNIZED")
    candidate=bytearray(original)
    struct.pack_into("<I",candidate,BOOT_WORD-TOP,0)
    if struct.unpack_from("<I",candidate,BOOT_WORD-TOP)[0]!=0:
        deny("BOOT_WORD_DIRECT_VECTOR_WRONG")
    if bytes(x&y for x,y in zip(original,candidate))!=bytes(candidate):
        deny("PATCH_NEEDS_TOP_SECTOR_ERASE")
    changes=[i for i,(x,y) in enumerate(zip(original,candidate)) if x!=y]
    if changes != [BOOT_WORD-TOP+1,BOOT_WORD-TOP+2]:
        deny("TOP_SECTOR_NOT_EXACTLY_TWO_BYTES_CHANGED")
    if struct.unpack_from("<I",candidate,BL_CONFIG-TOP)[0]!=bsl:
        deny("ROM_BACKDOOR_NOT_IDENTICAL")
    # Hardware application already programmed separately: no guarantee the
    # current live bytes still match. A fresh read-only ROM CRC is required.
    return bytes(candidate),factory1[TOP:FULL],{
        "schema":"r4-p7u-fitted-direct-ccfg-offline-v2",
        "flash_authorized":False,
        "radio_contact":False,
        "source_p10_comparison":"P10_NATIVE_IMAGE_VALID_CONF_ZERO",
        "fitted_ccfg_compiled_corrections":observed,
        "safe_p7u_compiled_ccfg_replacement":False,
        "reason":"KEEP_FACTORY_POWER_CLOCK_BOOST_AND_SECURITY_FIELDS",
        "app_only_hex_sha256":sha(app_hex1),
        "factory_complete_sha256":sha(factory1),
        "factory_top_sector_sha256":sha(original),
        "factory_top_sector_crc32":crc(original),
        "candidate_top_sector_sha256":sha(candidate),
        "candidate_top_sector_crc32":crc(candidate),
        "four_byte_patch_address":hex(BOOT_WORD),
        "four_byte_patch_old":"00c00a00",
        "four_byte_patch_new":"00000000",
        "flash_program_bit_transition":"1_to_0_only",
        "sector_erase_required_for_forward_patch":False,
        "physical_no_erase_word_program_proven":False,
        "rollback_requires_full_top_sector_erase":True,
        "rollback_flash_top_sector_physical_restoration_proven":False,
        "erase_top_sector_currently_forbidden":True,
        "top_sector_address":hex(TOP),
        "no_carrying_raw_factory_to_public_ci":True,
        "flash_performed":False,
        "boot_proven":False,
        "r4_nv_init_proven":False,
        "requires_live_read_only_check_before_any_future_change":True,
    }

def main():
    a=argparse.ArgumentParser()
    for arg in ("factory-pass1","factory-pass2","native-hex","app-hex-replica1",
                "app-hex-replica2","private-output-dir"):
        a.add_argument("--"+arg,type=Path,required=True)
    args=a.parse_args()
    out=args.private_output_dir
    if out.exists() or out.is_symlink():
        deny("NEED_NEW_NONEXISTENT_PRIVATE_OUT_DIRECTORY")
    native,err=_parse_intel_hex(args.native_hex)
    if err or native is None:
        deny("NATIVE_HEX_PARSE")
    desired,rollback,receipt=plan(
        args.factory_pass1.read_bytes(),args.factory_pass2.read_bytes(),
        native,args.app_hex_replica1.read_bytes(),args.app_hex_replica2.read_bytes())
    out.mkdir(parents=True,exist_ok=False)
    (out/"CCFG_WORD_ZERO_NOT_FLASH_AUTHORIZED.bin").write_bytes(b"\x00"*4)
    (out/"FACTORY_TOP_8K_EXACT_RESTORE_NOT_FLASH_AUTHORIZED.bin").write_bytes(rollback)
    (out/"CANDIDATE_TOP_8K_COMPARISON_ONLY.bin").write_bytes(desired)
    (out/"offline-receipt.json").write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    print(json.dumps({k:v for k,v in receipt.items()
                      if k not in ("fitted_ccfg_compiled_corrections",)},
                     sort_keys=True))
if __name__=="__main__":main()
