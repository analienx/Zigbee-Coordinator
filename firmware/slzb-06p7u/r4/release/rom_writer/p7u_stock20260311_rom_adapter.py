"""Target-limited CC2652P7 ROM BSL adapter for stock20260311 transition.

Source-only operator component: no CLI, BSL entry, reset, power cycle,
network transport, captured secrets or implicit authorization. The historical
23-sector ROM writer is deliberately not modified or weakened.

CC26xx MEMORY_READ has two extension bytes: word-width=1 and word-count.
Reading at most 60 words per request reduces 704-KiB readback from 180224
single-word serial transactions to at most 3080 sector-contained requests,
without changing its read-only scope.
Exact long-response behavior must be confirmed on the one real device during
the separately approved ROM-BSL read-only admission, before any erase.

Protocol: TI SWRA466E and pinned SMLIGHT command.py at 9a1d33571c1cdaed.
"""
from __future__ import annotations

import hashlib
import json
import re

from p7u_rom_lowlevel import (
    DOWNLOAD, GET_STATUS, MEMORY_READ, SECTOR_ERASE, RomSerial, RomWireError,
)

FLASH = 0xB0000
SECTOR = 0x2000
APP_END = 0xA0000
BOOT = 0xAC000
CCFG = 0xAFFA8
FCFG_ICEPICK = 0x50001318
FCFG_IEEE = 0x500012F0
FLASH_SIZE_REG = 0x4003002C
MAX_READ_WORDS = 60
FACTORY_CCFG_SHA = "74707d474dc5ef0d1fdcc18fcd9d930f9a30030046833bdda7c1237219ae3758"


def _deny(code: str):
    raise RomWireError("P7U_STOCK20260311_BSL_" + code)


class Stock20260311ROM(RomSerial):
    """Exact transition adapter, with an irreversible-write poison latch.

    Only an operator-controlled *existing* UART ROM BSL can be opened; no
    management HTTP, DTR/RTS reset, GPIO or automatic bootloader action.
    Identity is derived freshly from ROM-accessible silicon/FCFG/CCFG and is
    hashed in a distinct domain from the management/profile identity.
    """

    def __init__(self):
        super().__init__()
        self._faulted = False
        self._erased_target = None
        self._window_end = None
        self._boot_tail_sent = False

    async def open(self, device: str, baud: int = 115200):
        if not isinstance(device, str) or re.fullmatch(r"COM[1-9][0-9]*", device, re.I) is None:
            _deny("EXPLICIT_WINDOWS_COM_ONLY")
        if type(baud) is not int or baud != 115200:
            _deny("FIXED_BSL_BAUD")
        await super().open(device, baud)

    async def read(self, address: int, length: int) -> bytes:
        if (type(address) is not int or type(length) is not int
                or address % 4 or length <= 0 or length % 4
                or not 0 <= address < FLASH or address + length > FLASH):
            _deny("FLASH_READ_BOUNDS")
        result = bytearray()
        for start in range(0, length, MAX_READ_WORDS * 4):
            count = min(MAX_READ_WORDS, (length - start) // 4)
            chunk = await self._call(MEMORY_READ, address=address + start,
                                     extra=bytes((1, count)))
            if type(chunk) is not bytes or len(chunk) != count * 4:
                _deny("MEMORY_READ_COUNT_OR_LENGTH_UNSUPPORTED")
            result.extend(chunk)
        return bytes(result)

    async def flash_size(self) -> int:
        """Capture-pair API: independently validate the live size register."""
        size = await self._read_rom_word(FLASH_SIZE_REG)
        if size[0] * SECTOR != FLASH:
            _deny("LIVE_FLASH_GEOMETRY_CHANGED")
        return FLASH

    async def read_flash(self, address: int, length: int) -> bytes:
        """Capture-pair API: use the identical ROM read bounds/protocol."""
        return await self.read(address, length)

    async def _read_rom_word(self, address: int) -> bytes:
        data = await self._call(MEMORY_READ, address=address, extra=b"\x01\x01")
        if type(data) is not bytes or len(data) != 4:
            _deny("FCFG_READ_NOT_FOUR_BYTES")
        return data

    async def identity_sha256(self) -> str:
        chip = await self.get_chip_id()
        wafer = await self._read_rom_word(FCFG_ICEPICK)
        wafer_id = (((wafer[3] & 15) << 16) + (wafer[2] << 8) + (wafer[1] & 0xF0)) >> 4
        size = await self._read_rom_word(FLASH_SIZE_REG)
        if type(chip) is not int or chip == 0 or wafer_id != 0xBB77 or size[0] * SECTOR != FLASH:
            _deny("NOT_CC26X2X7_704K_DEVICE")
        ieee = await self._read_rom_word(FCFG_IEEE) + await self._read_rom_word(FCFG_IEEE + 4)
        ccfg = await self.read(CCFG, FLASH - CCFG)
        if hashlib.sha256(ccfg).hexdigest() != FACTORY_CCFG_SHA:
            _deny("FACTORY_CCFG_CHANGED")
        document = {"domain": "p7u-rom-observed-hardware-identity-v1",
                    "chip_id": chip, "icepick": wafer.hex(), "flash_register": size.hex(),
                    "ieee": ieee.hex(), "ccfg_sha256": FACTORY_CCFG_SHA}
        return hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    async def status(self) -> bool:
        try:
            ok = await self._call(GET_STATUS) == 0x40
        except BaseException:
            self._faulted = True
            raise
        if not ok:
            self._faulted = True
        return ok

    async def _irreversible(self, opcode: int, **kwargs) -> bool:
        if self._faulted:
            _deny("SESSION_POISONED_AFTER_UNCERTAIN_WRITE")
        try:
            answer = await self._call(opcode, **kwargs)
            if answer is not True:
                _deny("COMMAND_NOT_ACCEPTED")
            return True
        except BaseException:
            self._faulted = True
            self._download_remaining = 0
            raise

    async def erase_sector(self, address: int) -> bool:
        if (type(address) is not int or address % SECTOR
                or not (0 <= address < APP_END or address == BOOT)):
            _deny("ERASE_PROTECTED_RANGE")
        if self._download_remaining:
            _deny("DOWNLOAD_IN_PROGRESS")
        self._erased_target = None
        self._window_end = None
        self._boot_tail_sent = False
        result = await self._irreversible(SECTOR_ERASE, address=address)
        self._erased_target = address
        return result

    async def begin_download(self, address: int, length: int) -> bool:
        if type(address) is not int or type(length) is not int or self._download_remaining:
            _deny("DOWNLOAD_STATE_INVALID")
        target = self._erased_target
        app = target is not None and 0 <= target < APP_END and address == target and length == SECTOR
        boot_tail = target == BOOT and address == BOOT + 8 and length == SECTOR - 8
        boot_vectors = target == BOOT and address == BOOT and length == 8 and self._boot_tail_sent
        if not (app or boot_tail or boot_vectors):
            _deny("DOWNLOAD_OUTSIDE_APPROVED_WINDOWS_OR_ORDER")
        self._window_end = None
        self._download_remaining = 0
        result = await self._irreversible(DOWNLOAD, address=address, length=length)
        self._window_end = address + length
        self._download_remaining = length
        return result

    async def send_data(self, data: bytes) -> bool:
        if (type(data) is not bytes or not 0 < len(data) <= 252
                or len(data) % 4 or not 0 < self._download_remaining
                or len(data) > self._download_remaining or self._window_end is None):
            _deny("SEND_DATA_OUTSIDE_FROZEN_WINDOW")
        prior = self._download_remaining
        self._download_remaining = 0
        result = await self._irreversible(0x24, payload=data)
        self._download_remaining = prior - len(data)
        if self._download_remaining == 0:
            if self._erased_target == BOOT and self._window_end == BOOT + SECTOR:
                self._boot_tail_sent = True
            else:
                self._erased_target = None
            self._window_end = None
        return result
