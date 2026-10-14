#!/usr/bin/env python3
"""SMLIGHT P7U only: vendor management BSL entry + minimal TI ROM transport.

NO import of upstream flasher, CLI, gpiod or high-level CC26xx.erase().
USB CDC mode demands the radio already be placed in ROM BSL via SMLIGHT OS.
"""
from __future__ import annotations

import asyncio
import re


def normalized_mac(value: str) -> str:
    """Reject partial, malformed or guessed management MAC identities."""
    compact = re.sub(r"[:-]", "", value).upper()
    if not re.fullmatch(r"[0-9A-F]{12}", compact):
        raise BslConnectionError("SPARE_SMLIGHT_MAC_INVALID")
    return compact
from p7u_rom_lowlevel import RomSerial


class BslConnectionError(RuntimeError):
    pass


class SmlightRom(RomSerial):
    """Exposes only READ/CRC and bounded ERASE_SECTOR/DOWNLOAD/SEND_DATA."""
    pass


class LiveSmlightSession:
    """Network entry resets the verified spare into BSL; never resets on exit."""
    def __init__(self,device:str,expected_spare_mac:str|None=None):
        self.device=device
        self.expected_spare_mac=expected_spare_mac
        self.__rom=None

    async def __aenter__(self):
        if self.device.startswith("socket://"):
            match=re.fullmatch(r"socket://([A-Za-z0-9.-]+):6638",self.device)
            if not match:raise BslConnectionError("P7U_SOCKET_MUST_USE_PORT_6638")
            from pysmlight.const import Commands
            from pysmlight.web import Api2
            if not self.expected_spare_mac:
                raise BslConnectionError("SPARE_MAC_REQUIRED_BEFORE_BSL_ENTRY")
            expected_mac=normalized_mac(self.expected_spare_mac)
            async with Api2(match.group(1)) as api:
                info=await api.get_info()  # READ ONLY, before radio BSL reset.
                model=(info.model or "").upper().replace("-", "")
                if model != "SLZB06P7U":
                    raise BslConnectionError("MANAGEMENT_MODEL_NOT_EXACT_SPARE_P7U")
                if not info.MAC or normalized_mac(info.MAC) != expected_mac:
                    raise BslConnectionError("MANAGEMENT_MAC_NOT_EXPECTED_SPARE")
                if await api.check_auth_needed():
                    raise BslConnectionError("SMLIGHT_API_AUTH_NOT_SUPPORTED_STOP")
                if not bool(await api.set_cmd(Commands.CMD_ZB_BSL)):
                    raise BslConnectionError("MANAGEMENT_BSL_ENTRY_NOT_ACKNOWLEDGED")
            await asyncio.sleep(0.35)
        elif not re.fullmatch(r"(COM[0-9]+|/dev/tty(?:ACM|USB|S)[0-9]+)",self.device):
            raise BslConnectionError("USB_PORT_EXPLICIT_NOT_COM_OR_TTY")
        serial=SmlightRom()
        try:
            await serial.open(self.device,115200)
            if not await serial.synchronize():
                raise BslConnectionError("ROM_BSL_SYNC_NOT_ACKNOWLEDGED")
        except Exception:
            try:await serial.close()
            except Exception:pass
            raise
        self.__rom=serial
        return serial

    async def __aexit__(self,exc_type,exc,tb):
        if self.__rom is not None:
            try:await self.__rom.close()
            finally:self.__rom=None
        # Leave radio in ROM BSL for explicit operator-controlled app reset.
        return False
