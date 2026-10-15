#!/usr/bin/env python3
"""Separate NV5-only ROM adapter. Never changes the application writer allowlist.

The caller must already have placed the radio in ROM BSL. This session sends no
management reset, ROM reset, bank erase, CCFG write or automatic recovery command.
MEMORY_READ remains the pinned, four-byte SMLIGHT primitive; bulk is unqualified.
"""
from __future__ import annotations

import re

from p7u_rom_lowlevel import (RomSerial, RomWireError, SECTOR_ERASE, DOWNLOAD)
from p7u_rom_transport import normalized_mac

NV_SECTORS = (0xA4000, 0xA6000, 0xA8000, 0xAA000, 0xAC000)
SECTOR = 8192


class NvRom(RomSerial):
    """Only these five complete NV sectors can be erased or downloaded."""

    async def erase_sector(self, addr: int) -> bool:
        self._download_remaining = 0
        if type(addr) is not int or addr not in NV_SECTORS:
            raise RomWireError("NV_ERASE_OUTSIDE_FIVE_SECTORS")
        return bool(await self._call(SECTOR_ERASE, address=addr))

    async def begin_download(self, addr: int, length: int) -> bool:
        self._download_remaining = 0
        if type(addr) is not int or addr not in NV_SECTORS or type(length) is not int or length != SECTOR:
            raise RomWireError("NV_DOWNLOAD_OUTSIDE_FIVE_SECTORS")
        ok = bool(await self._call(DOWNLOAD, address=addr, length=length))
        if ok:
            self._download_remaining = length
        return ok


class NvSession:
    """Open an exact, already-in-BSL endpoint; leave it in BSL on every exit."""

    def __init__(self, device: str, management_mac: str):
        if not (re.fullmatch(r"(COM[0-9]+|/dev/tty(?:ACM|USB|S)[0-9]+)", device)
                or re.fullmatch(r"socket://([A-Za-z0-9.-]+):6638", device)):
            raise RomWireError("NV_EXPLICIT_COM_TTY_OR_SOCKET6638_REQUIRED")
        self.device = device
        self.mac = normalized_mac(management_mac)
        self.rom = None

    async def __aenter__(self):
        if self.device.startswith("socket://"):
            # Read-only host identity, before opening the radio stream. No CMD_ZB_BSL.
            from pysmlight.web import Api2
            host = re.fullmatch(r"socket://([A-Za-z0-9.-]+):6638", self.device)[1]
            async with Api2(host) as api:
                info = await api.get_info()
                if (info.model or "").upper().replace("-", "") != "SLZB06P7U":
                    raise RomWireError("NV_MANAGEMENT_MODEL_NOT_P7U")
                if not info.MAC or normalized_mac(info.MAC) != self.mac:
                    raise RomWireError("NV_MANAGEMENT_MAC_MISMATCH")
        self.rom = NvRom()
        try:
            await self.rom.open(self.device, 115200)
            if await self.rom.synchronize() is not True:
                raise RomWireError("NV_ROM_SYNC_FAILED")
        except BaseException:
            await self.rom.close()
            raise
        return self.rom

    async def __aexit__(self, *exc):
        await self.rom.close()
        return False
