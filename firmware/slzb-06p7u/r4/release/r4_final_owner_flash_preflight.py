#!/usr/bin/env python3
"""Prepare a board-bound R4 P7U application+handoff+rollback receipt. NO FLASH.

The two full-flash backups and extracted app/HANDOFF binaries must stay on
the owner's host. No real radio, serial port, web endpoint, credentials,
bank erase, protected NV or CCFG write is accessed by this module.
"""
from __future__ import annotations

import argparse
import binascii
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"b0"/"tools"))
from b0_image_audit import _parse_intel_hex
from r4_make_rom_handoff_sector import (
    BOOT, SECTOR, ROM_CCFG, EXPECTED_FACTORY_SHA,
    EXPECTED_FACTORY_BOOT_SHA, handoff_sector
)
from r4_make_direct_app_only import APP_END, serialize_app

BOOT_END = BOOT + SECTOR
CCFG_SECTOR = 0xAE000
CCFG_END = 0xB0000
EXPECTED_STOCK_TOP_CRC = "3c032e08"
EXPECTED_STOCK_BOOT_CRC = "448b8a3a"


def block(reason):
    raise ValueError("R4_P7U_FINAL_PREFLIGHT_BLOCKED_" + reason)


def sha(x):
    return hashlib.sha256(x).hexdigest()


def crc(x):
    return "%08x" % (binascii.crc32(x) & 0xFFFFFFFF)


def receipt_plan(first, second, app_hex: bytes, app_receipt: dict,
                 second_hex: bytes, second_receipt: dict,
                 handoff: bytes, handoff_receipt: dict) -> dict:
    if (len(first) != CCFG_END or first != second or
            sha(first) != EXPECTED_FACTORY_SHA):
        block("DUPLICATE_STOCK_BACKUP_PIN_MISMATCH")
    if sha(first[BOOT:BOOT_END]) != EXPECTED_FACTORY_BOOT_SHA:
        block("STOCK_BOOT_SECTOR_WRONG")
    if crc(first[BOOT:BOOT_END]) != EXPECTED_STOCK_BOOT_CRC:
        block("STOCK_BOOT_CRC_MISMATCH")
    if crc(first[CCFG_SECTOR:CCFG_END]) != EXPECTED_STOCK_TOP_CRC:
        block("STOCK_CCFG_TOP_SECTOR_WRONG")
    if struct.unpack_from("<I",first,ROM_CCFG)[0] != BOOT:
        block("FITTED_IMAGE_VALID_BOOT_VECTOR")
    config = struct.unpack_from("<I",first,0xAFFD8)[0]
    if (config & 255) != 0xC5 or config >> 24 != 0xC5 or (config >> 8) & 255 != 15 or config & 0x10000:
        block("SMLIGHT_MANAGEMENT_ROM_BSL_BACKDOOR_DISABLED")
    protection = struct.unpack_from("<I",first,0xAFFF8)[0]
    if not (protection & (1 << (86-64))):
        block("BOOT_SECTOR_WRT_PROTECTED")
    if first[0xA0000:0xA4000] != b"\xff"*0x4000:
        block("NEW_INTERNAL_NV_NOT_BLANK")
    if app_hex != second_hex:
        block("TWO_NATIVE_APP_REPLICAS_MISMATCH")
    for data in (app_receipt, second_receipt):
        if (data.get("schema") != "r4-p7u-direct-app-extraction-v1" or
                data.get("app_hex_sha256") != sha(app_hex) or
                data.get("sectors_to_program") != 23 or
                data.get("physical_vector_address") != "0x00000000" or
                data.get("native_ccfg_is_not_in_payload") is not True or
                any(data.get(x) is not False for x in
                    ("flash_authorized","erase_nv","erase_ccfg","erase_bootloader","bank_or_chip_erase"))):
            block("APP_PROVENANCE_OR_PROTECTION_MISMATCH")
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        path = Path(d)/"candidate.hex"
        path.write_bytes(app_hex)
        app,err = _parse_intel_hex(path)
    if err or not app or min(app) != 0 or max(app) >= APP_END:
        block("APP_HEX_NOT_EXACT_PROTECTED_RANGE")
    if serialize_app(app) != app_hex:
        block("APP_HEX_NONCANONICAL")
    if app_receipt.get("sector_crc32_ff_padded") != second_receipt.get("sector_crc32_ff_padded"):
        block("APP_REPLICA_SECTOR_CRCS_DIVERGE")
    computed = {}
    original = {}
    for addr in range(0,APP_END,SECTOR):
        sec = bytes(app.get(i,0xFF) for i in range(addr,addr+SECTOR))
        key = f"0x{addr:05X}"
        computed[key] = crc(sec)
        original[key] = crc(first[addr:addr+SECTOR])
    if computed != app_receipt.get("sector_crc32_ff_padded") or len(computed)!=23:
        block("APP_SECTOR_CRC_RECEIPT_UNTRUSTED")
    vectors=bytes(app[i] for i in range(0x3C))
    expected_handoff,generated = handoff_sector(vectors)
    if handoff != expected_handoff or sha(handoff) != generated["handoff_sector_sha256"]:
        block("HANDOFF_BINARY_NOT_REGENERATED")
    if (handoff_receipt.get("schema") != generated["schema"] or
            handoff_receipt.get("handoff_sector_sha256") != generated["handoff_sector_sha256"] or
            handoff_receipt.get("handoff_sector_crc32") != generated["handoff_sector_crc32"] or
            handoff_receipt.get("source_app_hex_sha256") != sha(app_hex) or
            handoff_receipt.get("factory_boot_sector_crc32") != EXPECTED_STOCK_BOOT_CRC or
            handoff_receipt.get("factory_ccfg_sector_crc32") != EXPECTED_STOCK_TOP_CRC or
            handoff_receipt.get("flash_authorized") is not False):
        block("HANDOFF_RECEIPT_NOT_BOUND_TO_APP_OR_FACTORY")
    return {
        "schema": "r4-p7u-owner-fitted-final-flash-prep-v1",
        "target": "SLZB-06P7U_R1.73_CC2652P7_ISOLATED_ONLY",
        "transport": "SMLIGHT-OS_MANAGEMENT_TO_TI_ROM_BSL_PORT_6638",
        "expected_flash_bytes": len(first),
        "exact_stock_factory_sha256": EXPECTED_FACTORY_SHA,
        "candidate_app_hex_sha256": sha(app_hex),
        "candidate_app_crc32_by_sector": computed,
        "stock_app_crc32_by_sector": original,
        "candidate_handoff_sector_sha256": sha(handoff),
        "candidate_handoff_sector_crc32": crc(handoff),
        "stock_handoff_sector_sha256": EXPECTED_FACTORY_BOOT_SHA,
        "stock_handoff_sector_crc32": EXPECTED_STOCK_BOOT_CRC,
        "stock_ccfg_top_sector_crc32": EXPECTED_STOCK_TOP_CRC,
        "stock_ccfg_image_valid": hex(BOOT),
        "boot_sector_write_protection_checked_clear": True,
        "native_two_builds_byte_identical": True,
        "stock_two_readbacks_byte_identical": True,
        "app_sector_writes": [hex(i) for i in range(0,APP_END,SECTOR)],
        "handoff_sector_write": hex(BOOT),
        "ccfg_sector_write": None,
        "nv_sector_write": None,
        "production_coordinator_write": None,
        "prepare_and_rollback_sequence": [
            "independent_live_SLZB_management_identity_PIN_and_ROM_chip_id",
            "read_only_23_app_sector_CRC_original_and_two_separate_top_sector_CRCs",
            "program_application_sector_0x00000_LAST_without_any_reset",
            "CRC_verify_all_23_native_application_sectors",
            "erase_and_program_only_0xAC000_handoff_sector_AFTER_app_success",
            "CRC_verify_handoff_sector_and_unchanged_0xAE000_CCFG_sector",
            "leave_BSL_then_SMLIGHT_radio_restart_and_check_ZNP_SYS_PING",
            "if_failure_reenter_management_ROM_BSL_restore_factory_0xAC000_FIRST",
            "restore_original_23_application_sectors_and_CRC_verify",
            "verify_exact_factory_CCFG_and_ZNP_SYS_PING_after_management_reset",
        ],
        "app_first_then_handoff_last": True,
        "factory_boot_first_in_rollback": True,
        "bank_erase_forbidden": True,
        "chip_erase_forbidden": True,
        "ccfg_erase_forbidden": True,
        "nv_erase_forbidden": True,
        "radio_write_performed": False,
        "flash_authorized": False,
        "reason": "OFFLINE_PREPARATION_ONLY_HARDWARE_WRITE_NOT_EXECUTED",
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--stock-pass1",required=True,type=Path)
    p.add_argument("--stock-pass2",required=True,type=Path)
    p.add_argument("--replica1-app-hex",required=True,type=Path)
    p.add_argument("--replica2-app-hex",required=True,type=Path)
    p.add_argument("--replica1-receipt",required=True,type=Path)
    p.add_argument("--replica2-receipt",required=True,type=Path)
    p.add_argument("--handoff-bin",required=True,type=Path)
    p.add_argument("--handoff-receipt",required=True,type=Path)
    p.add_argument("--out-receipt",required=True,type=Path)
    a = p.parse_args()
    result = receipt_plan(
        a.stock_pass1.read_bytes(),a.stock_pass2.read_bytes(),
        a.replica1_app_hex.read_bytes(),json.loads(a.replica1_receipt.read_text()),
        a.replica2_app_hex.read_bytes(),json.loads(a.replica2_receipt.read_text()),
        a.handoff_bin.read_bytes(),json.loads(a.handoff_receipt.read_text()))
    if a.out_receipt.exists() or a.out_receipt.is_symlink():
        block("OUTPUT_ALREADY_EXISTS")
    a.out_receipt.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print(json.dumps({k:v for k,v in result.items() if k not in
                      ("candidate_app_crc32_by_sector","stock_app_crc32_by_sector")},
                     sort_keys=True))


if __name__=="__main__":
    main()
