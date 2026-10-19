"""Fail-closed tests for versioned SLZB-06P7U R4 ROM sector writer.

No network/serial device. Tests the actual production writer with a fake ROM.
"""
from __future__ import annotations
import asyncio
import binascii
import hashlib
import importlib.util
from pathlib import Path
import struct
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
WRITER = ROOT / "firmware/slzb-06p7u/r4/release/rom_writer"
sys.path.insert(0, str(WRITER))
import p7u_strict_sector_writer as strict
import p7u_rom_lowlevel as low

FLASH = 0xB0000
SECTOR = 0x2000
COUNT = 23

def bundle():
    blocks = []
    for index in range(COUNT):
        raw = bytearray(bytes([(index + 1) % 255]) * SECTOR)
        if index == 0:
            struct.pack_into("<II", raw, 0, 0x20004000, 0x00000125)
        blocks.append((index * SECTOR, bytes(raw)))
    return strict.Bundle("p7u-r4-NV4-native-full-znp-unit", "a"*64, "b"*64, tuple(blocks))

class FakeROM:
    def __init__(self, *, fail_packet_at=None):
        self.flash = bytearray(b"\x45" * FLASH)
        self.erases = []
        self.calls = 0
        self.cursor = None
        self.remaining = 0
        self.fail_packet_at = fail_packet_at
        ccfg = bytearray(b"\xff"*88)
        struct.pack_into("<I", ccfg, 0x30, 0xC5000FC5)
        struct.pack_into("<I", ccfg, 0x34, 1)
        struct.pack_into("<I", ccfg, 0x44, 0)
        self.flash[0xAFFA8:0xB0000] = ccfg

    async def get_chip_id(self):
        return 0x1234

    async def read_word(self, addr):
        if addr == 0x50001318:
            return bytes((0, 0x70, 0xB7, 0x0B))
        if addr == 0x4003002C:
            return bytes((88, 0, 0, 0))
        if 0x500012F0 <= addr < 0x500012F8:
            return b"\x22"*4
        if 0 <= addr < FLASH-3:
            return bytes(self.flash[addr:addr+4])
        raise AssertionError("fake ROM read outside allowlist")

    async def crc32(self, addr, length):
        return binascii.crc32(self.flash[addr:addr+length]) & 0xffffffff

    async def erase_sector(self, addr):
        assert addr % SECTOR == 0 and 0 <= addr < 0x2E000
        self.erases.append(addr)
        self.flash[addr:addr+SECTOR] = b"\xff"*SECTOR
        self.cursor = None
        self.remaining = 0
        return True

    async def begin_download(self, addr, length):
        assert length == SECTOR and addr in self.erases
        self.cursor = addr
        self.remaining = length
        return True

    async def send_data(self, packet):
        assert self.cursor is not None
        assert 0 < len(packet) <= 252 and len(packet) % 4 == 0
        assert self.remaining >= len(packet)
        self.calls += 1
        if self.calls == self.fail_packet_at:
            return False
        self.flash[self.cursor:self.cursor+len(packet)] = packet
        self.cursor += len(packet)
        self.remaining -= len(packet)
        return True

async def do_all(rom, image):
    approval = await strict.preflight(rom, image, "socket://offline-test")
    output = await strict.write_checked(rom, image, approval,
                                        approval["approval_digest"], "socket://offline-test")
    return approval, output

def test_full_23_sector_write_vectors_last_nv4_ccfg_untouched():
    rom = FakeROM()
    original_protected = bytes(rom.flash[0xA0000:])
    approval, receipt = asyncio.run(do_all(rom, bundle()))
    assert approval["writer_version"] == "1.0.0"
    assert receipt["sectors_written"] == COUNT
    assert rom.erases == [i*SECTOR for i in range(1, COUNT)] + [0]
    assert bytes(rom.flash[0xA0000:]) == original_protected
    assert all(rom.flash[addr:addr+SECTOR] == data
               for addr, data in bundle().sectors)

@pytest.mark.parametrize("changed", ["less", "extra", "swap", "length", "address", "vector", "profile", "pin"])
def test_bad_bundle_denied_before_observing_rom(changed):
    value = bundle()
    entries = list(value.sectors)
    profile, digest, plan = value.profile, value.hex_sha256, value.plan_sha256
    if changed == "less": entries.pop()
    if changed == "extra": entries.append((0x2E000, b"\x11"*SECTOR))
    if changed == "swap": entries[1], entries[2] = entries[2], entries[1]
    if changed == "length": entries[1] = (SECTOR, b"\x11"*(SECTOR-4))
    if changed == "address": entries[1] = (0xA6000, entries[1][1])
    if changed == "vector": entries[0] = (0, b"\xff"*SECTOR)
    if changed == "profile": profile = "p7u-legacy"
    if changed == "pin": digest = "not-a-pin"
    broken = strict.Bundle(profile, digest, plan, tuple(entries))
    with pytest.raises(strict.StrictError):
        asyncio.run(strict.preflight(FakeROM(), broken, "socket://offline-test"))

def test_tampered_approval_denied_without_erase():
    rom = FakeROM()
    image = bundle()
    approval = asyncio.run(strict.preflight(rom, image, "socket://offline-test"))
    approval["sectors"][1]["desired_crc32"] = "00000000"
    with pytest.raises(strict.StrictError):
        asyncio.run(strict.write_checked(rom, image, approval,
                                         approval["approval_digest"], "socket://offline-test"))
    assert rom.erases == []

def test_changed_app_denied_without_erase():
    rom = FakeROM()
    image = bundle()
    approval = asyncio.run(strict.preflight(rom, image, "socket://offline-test"))
    rom.flash[SECTOR+12] ^= 0xff
    with pytest.raises(strict.StrictError):
        asyncio.run(strict.write_checked(rom, image, approval,
                                         approval["approval_digest"], "socket://offline-test"))
    assert rom.erases == []

def test_bsl_packet_failure_stops_without_retry_or_next_sector():
    rom = FakeROM(fail_packet_at=3)
    image = bundle()
    with pytest.raises(strict.StrictError, match="ROM_SEND_DATA_REJECTED"):
        asyncio.run(do_all(rom, image))
    assert rom.erases == [SECTOR]
    assert rom.calls == 3

def test_broad_resume_is_prohibited():
    rom = FakeROM()
    image = bundle()
    approval = asyncio.run(strict.preflight(rom, image, "socket://offline-test"))
    with pytest.raises(strict.StrictError, match="UNBOUNDED_RESUME"):
        asyncio.run(strict.write_checked(rom, image, approval,
                                         approval["approval_digest"], "socket://offline-test",
                                         allow_resume=True))
    assert not rom.erases

def test_lowlevel_download_must_precede_send_data():
    rom = low.RomSerial()
    with pytest.raises(low.RomWireError, match="OUTSIDE_DOWNLOAD"):
        asyncio.run(rom.send_data(b"\x00"*4))
    assert not hasattr(low, "BANK_ERASE")
    assert not hasattr(low, "CHIP_ERASE")
    assert low.APP_SECTOR_ADDRESSES[-1] == 0x2C000
