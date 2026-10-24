"""Bounded read-only bulk transport for the sole P7U's TI ROM BSL.

Why: the native RomSerial._call(MEMORY_READ) performs an additional
GET_STATUS for every 240-byte read. Across two 704 KiB captures this is
>6,000 redundant serial transactions. A well-formed MEMORY_READ response
already has a ROM ACK and a framed response checksum; the higher layers
independently enforce full-image ROM CRC32, duplicate exact SHA256 and final
all-sector readback.

This subclass suppresses ONLY redundant status calls on successful read-only
MEMORY_READ frames. It issues GET_STATUS every 32 *successful* frames,
including reads during SHA admission. Never optimizes mutating commands;
erase/download/SEND_DATA retain their original strict ROM status checks,
poison latch and protected NV/CCFG boundaries.

Never pass this adapter to an execution path that omits the ROM CRC32,
duplicate capture and write readback gates.
"""
from __future__ import annotations
import re
from p7u_stock20260311_rom_adapter import (
    Stock20260311ROM, MAX_READ_WORDS, FLASH, MEMORY_READ, GET_STATUS, _deny,
)
from p7u_rom_lowlevel import RomSerial
from p7u_rom_lowlevel import RomWireError

STATUS_INTERVAL = 32

class SafeFastUsbRom(Stock20260311ROM):
    """Same strict writer, optimized solely for authenticated read-only frames."""
    def __init__(self):
        super().__init__()
        self.read_packets = 0
        self.read_status_checks = 0
        self.fast_read_enabled = False

    async def open(self, device: str, baud: int = 115200):
        """Direct HA /dev/serial/by-id avoids Windows->TCP->socat packet RTT.

        The radio identity must still be independently pinned by the operator.
        No USB auto-discovery, GPIO toggling, DTR/RTS reset, BSL entry or
        management API is performed here. 115200 only until a hardware
        rate-and-bridge qualification exists.
        """
        if (type(device) is str and
                re.fullmatch(
                    r"/dev/serial/by-id/usb-SMLIGHT_SMLIGHT_SLZB-06p7U_"
                    r"SLZB-06p7U[0-9]+-if00", device)):
            if type(baud) is not int or baud != 115200:
                _deny("USB_BAUD_NOT_QUALIFIED")
            await RomSerial.open(self, device, baud)
            return
        return await super().open(device, baud)

    async def enable_fast_reads(self):
        """Only after the target has been synchronized and identified in BSL."""
        if self.writer is None or self._download_remaining or self._faulted:
            _deny("FAST_READ_ENABLE_REQUIRES_IDLE_LIVE_BSL")
        if await self.get_chip_id() != 0xf000:
            _deny("FAST_READ_CHIP_MISMATCH")
        self.fast_read_enabled = True

    async def read(self, address: int, length: int) -> bytes:
        if not self.fast_read_enabled:
            return await super().read(address, length)
        if (type(address) is not int or type(length) is not int
                or address % 4 or length <= 0 or length % 4
                or not 0 <= address < FLASH or address + length > FLASH):
            _deny("FLASH_READ_BOUNDS")
        if self._faulted or self._download_remaining:
            _deny("FAST_READ_BLOCKED_BY_FAULT_OR_DOWNLOAD")
        result = bytearray()
        try:
            for start in range(0, length, MAX_READ_WORDS * 4):
                count = min(MAX_READ_WORDS, (length - start) // 4)
                await self._send(MEMORY_READ, address=address + start, extra=bytes((1, count)))
                await self._ack()
                chunk = await self._receive()
                if type(chunk) is not bytes or len(chunk) != count * 4:
                    raise RomWireError("FAST_READ_INVALID_RESPONSE_LENGTH")
                result.extend(chunk)
                self.read_packets += 1
                # Catch ROM-reported problems no later than 32 read packets,
                # while leaving mutation and independent CRC check unchanged.
                if self.read_packets % STATUS_INTERVAL == 0:
                    if await self._call(GET_STATUS) != 0x40:
                        raise RomWireError("FAST_READ_ROM_STATUS_FAILED")
                    self.read_status_checks += 1
        except BaseException:
            self._faulted = True
            raise
        return bytes(result)

    async def assert_read_status(self) -> None:
        """Explicit read-only fence at end of a capture/admission phase."""
        if self._faulted or self._download_remaining or not self.fast_read_enabled:
            _deny("FAST_READ_STATUS_FENCE_NOT_AVAILABLE")
        try:
            if await self._call(GET_STATUS) != 0x40:
                raise RomWireError("FAST_READ_FINAL_ROM_STATUS_FAILED")
        except BaseException:
            self._faulted = True
            raise
        self.read_status_checks += 1
