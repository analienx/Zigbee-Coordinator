#!/usr/bin/env python3
"""Narrow 8KiB P7U boot-sector writer core, no transport/network or CLI.

This is deliberately NOT a ready-to-run hardware flasher. Only the generic
ROM adapter furnished by an explicitly selected operator session may write.
The coordinator's fitted CCFG and the entire NV area are never write targets.
"""
from __future__ import annotations

import binascii
import hashlib
import struct
from typing import Protocol

BOOT = 0xAC000
TOP = 0xAE000
LAST = 0xB0000
BSL_WORD = 0xAFFD8
IMAGE_VALID_WORD = 0xAFFEC
SECTOR = 8192
PACKET = 252
STOCK_TOP_CRC = 0x3C032E08
STOCK_BOOT_CRC = 0x448B8A3A
STOCK_BOOT_SHA = "9d7fdad2eb0a4e134bc6e61b982a1a3b17438d72c6b49fa2a403926d58647b47"


class ROM(Protocol):
    async def read_word(self, address: int) -> bytes: ...
    async def crc32(self, address: int, length: int) -> int: ...
    async def erase_sector(self, address: int) -> bool: ...
    async def begin_download(self, address: int, length: int) -> bool: ...
    async def send_data(self, payload: bytes) -> bool: ...


def reject(reason):
    raise ValueError("R4_BOOT_SECTOR_WRITE_BLOCKED_" + reason)


def crc(raw):
    return binascii.crc32(raw) & 0xffffffff


async def guard_boot_protection(rom: ROM) -> None:
    """Entirely read-only; never attempts to modify CCFG."""
    if await rom.crc32(TOP, SECTOR) != STOCK_TOP_CRC:
        reject("FITTED_CCFG_TOP_CRC_CHANGED")
    word = await rom.read_word(IMAGE_VALID_WORD)
    if word != struct.pack("<I", BOOT):
        reject("FITTED_CCFG_IMAGE_VALID_CHANGED")
    bl = await rom.read_word(BSL_WORD)
    if type(bl) is not bytes or len(bl)!=4:
        reject("NO_ROM_BACKDOOR_REGISTER")
    val = struct.unpack("<I",bl)[0]
    if (val & 255)!=0xC5 or val>>24!=0xC5 or (val>>8)&255!=15 or (val & 0x10000):
        reject("ROM_MANAGEMENT_BACKDOOR_INACCESSIBLE")


async def boot_sector_admission(rom: ROM, before: bytes, after: bytes,
                                expected_app_crcs: dict[int, int],
                                *, recover_partially_written_boot: bool = False) -> dict:
    """Read-only approval; verifies real 23 application CRCs before any write."""
    if (not isinstance(before,bytes) or len(before)!=SECTOR
            or not isinstance(after,bytes) or len(after)!=SECTOR):
        reject("SECTOR_BYTES_INVALID")
    if not isinstance(expected_app_crcs,dict) or set(expected_app_crcs)!=set(range(0,0x2E000,SECTOR)):
        reject("EXPECTED_APP_SECTOR_PLAN_MISSING")
    await guard_boot_protection(rom)
    observed_boot_crc = await rom.crc32(BOOT,SECTOR)
    if recover_partially_written_boot:
        # Only exact pinned stock boot-sector bytes can recover an
        # interrupted handoff erase/write. NEVER relax the install path.
        if (hashlib.sha256(after).hexdigest() != STOCK_BOOT_SHA
                or crc(after) != STOCK_BOOT_CRC):
            reject("PARTIAL_RECOVERY_REQUIRES_EXACT_FACTORY_BOOT")
    elif observed_boot_crc != crc(before):
        reject("BOOT_SECTOR_NOT_EXPECTED_BEFORE")
    for addr, wanted in sorted(expected_app_crcs.items()):
        if (type(wanted) is not int or not 0<=wanted<2**32
                or await rom.crc32(addr,SECTOR)!=wanted):
            reject("APP_CRC_NOT_AT_APPROVED_STAGE_" + hex(addr))
    digest = hashlib.sha256(
        before + after + struct.pack("<I",observed_boot_crc) +
        bytes([int(recover_partially_written_boot)]) +
        b"".join(struct.pack("<II",s,v) for s,v in sorted(expected_app_crcs.items()))
    ).hexdigest()
    return {"schema":"r4-p7u-boot-sector-admission-v1",
            "target_sector":BOOT,
            "before_crc32":crc(before),
            "observed_live_boot_crc32":observed_boot_crc,
            "partial_stock_recovery_only":recover_partially_written_boot,
            "after_crc32":crc(after),
            "app_sectors":23,
            "binding_sha256":digest,
            "ccfg_top_crc32":STOCK_TOP_CRC,
            "no_flash_executed":True,
            "flash_authorized":False}


async def write_single_boot_sector(rom: ROM, before: bytes, after: bytes,
                                   expected_app_crcs: dict[int,int],
                                   admission: dict, binding_token: str,
                                   *, recover_partially_written_boot: bool = False) -> dict:
    """One tightly bound flash sector; no bank/chip/CCFG/NV erase API.

    Only invoke from a separately authorized, board-identified live operator.
    Unlike generic CLI flash, this function cannot touch other sector values.
    """
    current=await boot_sector_admission(
        rom,before,after,expected_app_crcs,
        recover_partially_written_boot=recover_partially_written_boot)
    if (admission != current or current["binding_sha256"] != binding_token
            or admission.get("target_sector") != BOOT
            or admission.get("flash_authorized") is not False):
        reject("ADMISSION_TOKEN_OR_LIVE_STATE_CHANGED")
    if after==before:
        return {"status":"ALREADY_MATCHING","flash_authorized":False}
    if await rom.erase_sector(BOOT) is not True:
        reject("ROM_BOOT_SECTOR_ERASE_REJECTED")
    if await rom.begin_download(BOOT,SECTOR) is not True:
        reject("ROM_BOOT_SECTOR_DOWNLOAD_REJECTED")
    for pos in range(0,SECTOR,PACKET):
        data=after[pos:pos+PACKET]
        if not data or len(data)%4 or len(data)>PACKET:
            reject("ROM_BOOT_SECTOR_PACKET_SIZE")
        if await rom.send_data(data) is not True:
            reject("ROM_BOOT_SECTOR_PACKET_FAILED")
    if await rom.crc32(BOOT,SECTOR)!=crc(after):
        reject("ROM_BOOT_SECTOR_FINAL_CRC_FAILED")
    await guard_boot_protection(rom)
    return {"status":"SINGLE_BOOT_SECTOR_WRITE_CRC_VERIFIED",
            "sector_address":hex(BOOT),"sector_count":1,"ccfg_touched":False,
            "nv_touched":False,"reset_issued":False}
