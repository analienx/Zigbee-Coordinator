#!/usr/bin/env python3
"""OFFLINE R4 handoff vector for fitted SMLIGHT CC2652P7, NOT FLASHABLE alone.

Avoid altering fitted CCFG: ROM still fetches its first vector at 0xAC000.
A fresh single-sector handoff stub initializes VTOR=0 then jumps to the
native R4 application's Reset_Handler. The original 8 KiB 0xAC000 sector
is backed up and must be restored for stock rollback. No NV/CCFG touching.

Hard-coded Thumb opcodes were independently disassembled with Capstone in
Cortex-M4 Thumb M-class mode. The code bytes are not obtained from a key or
an unaudited firmware source.
"""
from __future__ import annotations

import argparse
import binascii
import hashlib
import json
import struct
from pathlib import Path

BOOT = 0xAC000
SECTOR = 0x2000
ROM_CCFG = 0xAFFEC
APP_LIMIT = 0x2E000
ROM_VECTOR_RESET = BOOT + 9
VTOR_MMIO = 0xE000ED08
EXPECTED_FACTORY_SHA = "ba654310cef8f1543a96c9bb6d5ef4f17411829642bcbe8249e91de6ae5b38f3"
EXPECTED_FACTORY_BOOT_SHA = "9d7fdad2eb0a4e134bc6e61b982a1a3b17438d72c6b49fa2a403926d58647b47"

# Addresses 0xAC008..0xAC026. Thumb opcodes disassemble in this exact order:
# cpsid i
# ldr r0, [pc, #0x1c]           ; reads literal at 0xAC028
# movs r1, #0
# str r1, [r0]                  ; SCB->VTOR = 0
# dsb sy
# isb sy
# movs r0, #0
# ldr r1, [r0]                  ; R4 initial stack from vectors@0
# msr msp, r1
# ldr r1, [r0, #4]              ; R4 reset handler, Thumb bit set
# cpsie i
# bx r1
# nop
THUMB_HALFWORDS = (
    0xB672, 0x4807, 0x2100, 0x6001, 0xF3BF, 0x8F4F,
    0xF3BF, 0x8F6F, 0x2000, 0x6801, 0xF381, 0x8808,
    0x6841, 0xB662, 0x4708, 0xBF00,
)

NAME = "R4-ISOLATED-P7U-ROM-HANDOFF-0xAC000-NOT-FLASH-AUTHORIZED.bin"
RECEIPT = "r4-rom-handoff-sector-receipt.json"


def reject(reason: str) -> None:
    raise ValueError("R4_BOOT_HANDOFF_BLOCKED_" + reason)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def crc(raw: bytes) -> str:
    return "%08x" % (binascii.crc32(raw) & 0xFFFFFFFF)


def handoff_sector(native_vectors: bytes) -> tuple[bytes, dict]:
    if not isinstance(native_vectors, bytes) or len(native_vectors) < 0x3C:
        reject("NATIVE_VECTOR_MISSING")
    sp, reset = struct.unpack_from("<II", native_vectors)
    if not (0x20000000 <= sp <= 0x20024000 and sp % 8 == 0):
        reject("BAD_NATIVE_STACK")
    if not (reset & 1 and 0 < reset & ~1 < APP_LIMIT):
        reject("BAD_NATIVE_RESET")
    # Defensive internal consistency of the fixed minimal Thumb program.
    raw_code = b"".join(struct.pack("<H", insn) for insn in THUMB_HALFWORDS)
    if len(raw_code) != 32 or raw_code[:4] != bytes.fromhex("72b60748"):
        reject("STUB_CODE_INTEGRITY")
    head = struct.pack("<II", sp, ROM_VECTOR_RESET)
    sector = bytearray(b"\xff" * SECTOR)
    sector[0:8] = head
    sector[8:8 + len(raw_code)] = raw_code
    struct.pack_into("<I", sector, 0x28, VTOR_MMIO)
    if (struct.unpack_from("<II", sector, 0) != (sp, ROM_VECTOR_RESET)
            or struct.unpack_from("<I", sector, 0x28)[0] != VTOR_MMIO
            or sector[0x2C:] != b"\xff" * (SECTOR - 0x2C)):
        reject("STUB_SECTOR_LAYOUT")
    return bytes(sector), {
        "schema": "r4-p7u-rom-boot-sector-handoff-v1",
        "source_r4_initial_sp": hex(sp),
        "source_r4_reset_thumb": hex(reset),
        "resident_rom_vector_address_unchanged": hex(BOOT),
        "handoff_stub_reset_thumb": hex(ROM_VECTOR_RESET),
        "handoff_sector_range": [hex(BOOT), hex(BOOT + SECTOR)],
        "handoff_sector_sha256": sha(sector),
        "handoff_sector_crc32": crc(sector),
        "factory_boot_sector_sha256_expected": EXPECTED_FACTORY_BOOT_SHA,
        "factory_ccfg_image_valid_must_remain": hex(BOOT),
        "no_ccfg_write_required": True,
        "no_nv_write_required": True,
        "only_boot_sector_erase_required": True,
        "restore_factory_boot_sector_on_rollback": True,
        "flash_performed": False,
        "flash_authorized": False,
    }


def build(native_app_hex: Path, native_app_receipt: Path, factory_pass1: Path,
          factory_pass2: Path, out: Path) -> dict:
    if out.exists() or out.is_symlink():
        reject("OUTPUT_EXISTS")
    root = native_app_hex.resolve().parent
    if native_app_hex.is_symlink() or native_app_receipt.is_symlink():
        reject("INPUT_SYMLINK")
    receipt = json.loads(native_app_receipt.read_text())
    if not (receipt.get("schema") == "r4-p7u-direct-app-extraction-v1"
            and receipt.get("flash_authorized") is False
            and receipt.get("physical_vector_address") == "0x00000000"
            and receipt.get("app_hex_sha256") == sha(native_app_hex.read_bytes())
            and receipt.get("output_hex") == native_app_hex.name):
        reject("NATIVE_APP_PROVENANCE")
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "b0" / "tools"))
    from b0_image_audit import _parse_intel_hex
    app, error = _parse_intel_hex(native_app_hex)
    if error or not app or min(app) != 0 or max(app) >= APP_LIMIT:
        reject("NATIVE_APP_HEX")
    if not set(range(0x3C)).issubset(app):
        reject("NATIVE_VECTOR_NOT_COMPLETE")
    boot, detail = handoff_sector(bytes(app[i] for i in range(0x3C)))
    a, b = factory_pass1.read_bytes(), factory_pass2.read_bytes()
    if (len(a) != 0xB0000 or a != b
            or sha(a) != EXPECTED_FACTORY_SHA
            or sha(a[BOOT:BOOT + SECTOR]) != EXPECTED_FACTORY_BOOT_SHA
            or struct.unpack_from("<I", a, ROM_CCFG)[0] != BOOT):
        reject("FITTED_STOCK_BOOT_BACKUP_INVALID")
    # Factory protection bits 95:64. Sector 86 must allow sector erase.
    prot_95_64 = struct.unpack_from("<I", a, 0xAFFF8)[0]
    if not (prot_95_64 & (1 << (86 - 64))):
        reject("FITTED_BOOT_SECTOR_WRITE_PROTECTED")
    detail["source_app_hex_sha256"] = receipt["app_hex_sha256"]
    detail["factory_fullflash_sha256"] = EXPECTED_FACTORY_SHA
    detail["factory_boot_sector_crc32"] = crc(a[BOOT:BOOT + SECTOR])
    detail["factory_ccfg_sector_crc32"] = crc(a[0xAE000:0xB0000])
    detail["strict_sequence"] = [
        "program_23_app_sectors_in_BSL_erase_zero_last",
        "verify_23_app_sector_crc_against_receipt",
        "verify_top_ccfg_sector_exact_factory_crc",
        "erase_and_program_only_sector_0xAC000_stub_last",
        "verify_stub_and_top_ccfg_sector_crc_no_reset_between_steps",
        "after_BSL_exit_and_management_radio_restart_check_SYS_PING",
        "if_failure_reenter_management_BSL_and_restore_exact_factory_boot_and_app",
        "verify_factory_ccfg_and_stock_SYS_PING",
    ]
    detail["output_bin"] = NAME
    out.mkdir(parents=True)
    (out / NAME).write_bytes(boot)
    (out / RECEIPT).write_text(json.dumps(detail, sort_keys=True, indent=2) + "\n")
    return detail


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--native-app-hex", type=Path, required=True)
    p.add_argument("--native-app-receipt", type=Path, required=True)
    p.add_argument("--factory-pass1", type=Path, required=True)
    p.add_argument("--factory-pass2", type=Path, required=True)
    p.add_argument("--out-dir", type=Path, required=True)
    opts = p.parse_args()
    print(json.dumps(build(opts.native_app_hex, opts.native_app_receipt,
                           opts.factory_pass1, opts.factory_pass2, opts.out_dir),
                     sort_keys=True))


if __name__ == "__main__":
    main()
