#!/usr/bin/env python3
"""Offline CC2652P7 direct-ROM image and exact CCFG-word plan. NO WRITES.

Never generates a high-level flash command, sector erase operation or any
production/coordinator update. Factory flash bytes must stay on a trusted host.
"""
from __future__ import annotations
import argparse
import binascii
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "b0" / "tools"))
from b0_image_audit import _parse_intel_hex

FACTORY_LEN = 0xB0000
FACTORY_SHA256 = "ba654310cef8f1543a96c9bb6d5ef4f17411829642bcbe8249e91de6ae5b38f3"
APP_LIMIT = 0xA0000
SECTOR_SIZE = 0x2000
CCFG_SECTOR = 0xAE000
CCFG_START = 0xAFFA8
BOOT_WORD = 0xAFFEC
OLD_VECTOR = 0xAC000
NEW_VECTOR = 0


def guard(ok, reason):
    if not ok:
        raise ValueError("R4_DIRECT_ROM_BLOCKED_" + reason)


def crc(data):
    return "%08x" % (binascii.crc32(data) & 0xFFFFFFFF)


def image_plan(factory: bytes, native: dict[int, int]) -> dict:
    guard(len(factory) == FACTORY_LEN, "FACTORY_LENGTH")
    guard(type(native) is dict and len(native) > 0, "EMPTY_NATIVE")
    guard(all(isinstance(a, int) and 0 <= a < FACTORY_LEN
              and isinstance(v, int) and 0 <= v <= 255 for a, v in native.items()),
          "BAD_NATIVE_ADDRESS")
    guard(struct.unpack_from("<I", factory, BOOT_WORD)[0] == OLD_VECTOR,
          "ORIGINAL_BOOT_VECTOR_NOT_FITTED")
    bl = struct.unpack_from("<I", factory, 0xAFFD8)[0]
    er = struct.unpack_from("<I", factory, 0xAFFDC)[0]
    guard((bl & 0xFF) == 0xC5 and (bl >> 24) == 0xC5
          and ((bl >> 8) & 0xFF) == 15 and (bl & 0x10000) == 0,
          "ROM_BSL_DIO15_BACKDOOR")
    guard(er & 1, "BANK_ERASE_BACKDOOR_CONFIG")
    sp = int.from_bytes(bytes(native.get(i, 0xFF) for i in range(4)), "little")
    pc = int.from_bytes(bytes(native.get(i, 0xFF) for i in range(4, 8)), "little")
    guard(0x20000000 <= sp <= 0x20024000 and sp % 8 == 0, "NO_DIRECT_ROM_VECTOR_STACK")
    guard((pc & 1) == 1 and 0 < (pc & ~1) < APP_LIMIT, "NO_DIRECT_ROM_VECTOR_PC")
    guard(set(range(0x3C)).issubset(native), "INCOMPLETE_VECTOR_TABLE")
    guard(not any(APP_LIMIT <= a < CCFG_START for a in native),
          "NV_OR_BOOTLOADER_IN_NATIVE_HEX")
    guard(set(range(CCFG_START, FACTORY_LEN)).issubset(native),
          "NATIVE_CCFG_NOT_FULL_FOR_COMPARISON")
    app = {a: v for a,v in native.items() if a < APP_LIMIT}
    sectors = sorted(set((a//SECTOR_SIZE)*SECTOR_SIZE for a in app))
    guard(sectors == list(range(0, 0x2E000, 0x2000)), "APPLICATION_SECTORS_UNEXPECTED")
    old = factory[CCFG_SECTOR:FACTORY_LEN]
    after = bytearray(old)
    struct.pack_into("<I", after, BOOT_WORD-CCFG_SECTOR, NEW_VECTOR)
    guard(sum(a!=b for a,b in zip(after,old))==2, "BOOT_WORD_UNEXPECTED_DELTA")
    guard(bytes(x&y for x,y in zip(old,after))==bytes(after), "WOULD_REQUIRE_ERASE_ON_SWITCH")
    guard(all(after[i]==old[i] for i in range(SECTOR_SIZE)
              if not BOOT_WORD-CCFG_SECTOR <= i < BOOT_WORD-CCFG_SECTOR+4),
          "UNEXPECTED_TOP_SECTOR_MUTATION")
    return {
        "schema": "r4-p7u-direct-rom-offline-plan-v1",
        "factory_full_flash_sha256": hashlib.sha256(factory).hexdigest(),
        "application_first_vector": "0x00000",
        "application_reset_thumb_valid": True,
        "application_erase_sector_addresses": [hex(a) for a in sectors],
        "application_sector_count": len(sectors),
        "boot_address_old": hex(OLD_VECTOR),
        "boot_address_new": hex(NEW_VECTOR),
        "ccfg_word_address": hex(BOOT_WORD),
        "ccfg_original_sector_crc32": crc(old),
        "ccfg_target_sector_crc32": crc(after),
        "ccfg_changes_bytes": 2,
        "switch_requires_top_sector_erase": False,
        "exact_stock_rollback_requires_top_sector_erase": True,
        "rom_bsl_backdoor_config_unchanged": True,
        "unqualified_top_sector_erase_allowed": False,
        "no_swd_independent_recovery_proven": True,
        "no_flash_performed": True,
        "flash_authorized": False,
    }


def main():
    p=argparse.ArgumentParser(description="Private offline-only direct ROM plan")
    p.add_argument("--factory-pass1",type=Path,required=True)
    p.add_argument("--factory-pass2",type=Path,required=True)
    p.add_argument("--native-artifacts",type=Path,required=True)
    p.add_argument("--receipt",type=Path,required=True)
    a=p.parse_args()
    first=a.factory_pass1.read_bytes();second=a.factory_pass2.read_bytes()
    guard(first == second and hashlib.sha256(first).hexdigest()==FACTORY_SHA256,
          "TWO_MATCHING_FACTORY_BACKUPS")
    manifest=json.loads((a.native_artifacts/"manifest.json").read_text())
    guard(manifest.get("schema")=="r4-b0-artifact-manifest-v1","NATIVE_MANIFEST")
    entry=manifest["files"]["hex"]
    name=entry["file"]
    guard(Path(name).name==name and not name.startswith("."),"NATIVE_FILENAME")
    f=a.native_artifacts/name
    guard(f.is_file() and not f.is_symlink() and hashlib.sha256(f.read_bytes()).hexdigest()==entry["sha256"],
          "NATIVE_HEX_HASH")
    data,err=_parse_intel_hex(f)
    guard(err is None and data is not None,"NATIVE_HEX_FORMAT")
    result=image_plan(first,data)
    guard(not a.receipt.exists(),"RECEIPT_IMMUTABILITY")
    a.receipt.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(json.dumps(result,sort_keys=True))


if __name__=="__main__":
    main()
