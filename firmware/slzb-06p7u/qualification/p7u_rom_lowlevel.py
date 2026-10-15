#!/usr/bin/env python3
"""Minimal CC26x2 TI ROM serial BSL framing, fail-closed; NO chip/bank erase API.

Wire framing checked against SMLIGHT command.py pinned GitHub commit
9a1d33571c1cdaedc9dfcdcf2df5b5a5fece0b1c, SHA256
9fb42418ffa2301be52bfa2fe1208fb465138c2cc4cf432a767df2f6860ee25a.

No dependency on upstream high-level CLI or its unavailable Windows gpiod.
Only explicit SECTOR_ERASE, DOWNLOAD, SEND_DATA, CRC32, GET_CHIP_ID, MEM_READ.
"""
from __future__ import annotations

import asyncio
import struct
from typing import Any

ACK = b"\x00\xcc"
NACK = b"\x00\x33"

SYNC=0x55
DOWNLOAD=0x21
GET_STATUS=0x23
SEND_DATA=0x24
SECTOR_ERASE=0x26
CRC32=0x27
GET_CHIP_ID=0x28
MEMORY_READ=0x2A
APP_SECTOR_SIZE = 8192
APP_SECTOR_ADDRESSES = tuple(range(0, 0x2E000, APP_SECTOR_SIZE))
# BANK_ERASE 0x2C intentionally HAS NO implementation.
# SET_CCFG 0x2D, MEMORY_WRITE 0x2B and RESET 0x25 are also omitted.


class RomWireError(RuntimeError):
    """Bounded error code. Never expose raw serial memory/secret material."""


class RomSerial:
    def __init__(self):
        self.reader: Any = None
        self.writer: Any = None
        self._download_remaining = 0

    async def open(self, device: str, baud: int=115200):
        # Only transport dependency, serial_asyncio uses PySerial URL support.
        import serial_asyncio
        self.reader,self.writer=await serial_asyncio.open_serial_connection(
            url=device, baudrate=baud)

    async def close(self):
        self._download_remaining = 0
        if self.writer is not None:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            finally:
                self.writer=None

    async def _send(self, opcode: int, *, address: int | None=None,
                    length: int | None=None, payload: bytes=b"",
                    extra: bytes=b""):
        if self.writer is None:
            raise RomWireError("BSL_PORT_NOT_OPEN")
        if opcode not in (SYNC, DOWNLOAD, GET_STATUS, SEND_DATA,
                          SECTOR_ERASE, CRC32, GET_CHIP_ID, MEMORY_READ):
            raise RomWireError("BSL_OPCODE_NOT_ALLOWLISTED")
        if opcode == SYNC:
            frame=b"\x55\x55"
        else:
            body=bytes((opcode,))
            if address is not None:
                if not 0<=address<=0xffffffff:raise RomWireError("BSL_ADDRESS_INVALID")
                body+=struct.pack(">I",address)
            if length is not None:
                if not 0<=length<=0xffffffff:raise RomWireError("BSL_LENGTH_INVALID")
                body+=struct.pack(">I",length)
            body+=extra+payload
            if len(body)+2>255:raise RomWireError("BSL_FRAME_TOO_LARGE")
            frame=bytes((len(body)+2,sum(body)&255))+body
        self.writer.write(frame)
        await self.writer.drain()

    async def _ack(self):
        # Bound the resync window; no unbounded data drain on noise.
        last=b""
        for _ in range(64):
            try:
                one=await asyncio.wait_for(self.reader.readexactly(1),timeout=2)
            except (asyncio.TimeoutError,asyncio.IncompleteReadError) as e:
                raise RomWireError("BSL_ACK_TIMEOUT_OR_DISCONNECTED") from e
            last=(last+one)[-2:]
            if last==ACK:return
            if last==NACK:raise RomWireError("BSL_NACK")
        raise RomWireError("BSL_ACK_NOISE_LIMIT")

    async def _receive(self) -> bytes:
        try:
            header=await asyncio.wait_for(self.reader.readexactly(2),timeout=3)
            length,checksum=header
            if length<3 or length>255:raise RomWireError("BSL_RESPONSE_LENGTH")
            payload=await asyncio.wait_for(self.reader.readexactly(length-2),timeout=3)
        except (asyncio.TimeoutError,asyncio.IncompleteReadError) as e:
            raise RomWireError("BSL_RESPONSE_TIMEOUT") from e
        if sum(payload)&255 !=checksum:
            self.writer.write(NACK)
            await self.writer.drain()
            raise RomWireError("BSL_RESPONSE_CHECKSUM")
        self.writer.write(ACK)
        await self.writer.drain()
        return payload

    async def _call(self,opcode:int,*,address=None,length=None,payload=b"",extra=b""):
        await self._send(opcode,address=address,length=length,payload=payload,extra=extra)
        await self._ack()
        if opcode==SYNC:return True
        result=None
        if opcode in (GET_STATUS,CRC32,GET_CHIP_ID,MEMORY_READ):
            result=await self._receive()
        if opcode==GET_STATUS:
            if len(result)!=1:raise RomWireError("BSL_GET_STATUS_BAD_LENGTH")
            return result[0]
        status=await self._call(GET_STATUS)
        if status!=0x40:raise RomWireError("BSL_TARGET_NON_SUCCESS_STATUS")
        return result if result is not None else True

    async def synchronize(self)->bool:
        return bool(await self._call(SYNC))

    async def get_chip_id(self)->int:
        data=await self._call(GET_CHIP_ID)
        if type(data) is not bytes or len(data)!=4:
            raise RomWireError("BSL_CHIP_ID_WRONG_LENGTH")
        return (data[2]<<8)|data[3]

    async def read_word(self,addr:int)->bytes:
        if addr%4:raise RomWireError("BSL_MEMORY_READ_UNALIGNED")
        data=await self._call(MEMORY_READ,address=addr,extra=b"\x01\x01")
        if type(data) is not bytes or len(data)!=4:
            raise RomWireError("BSL_MEMORY_READ_NOT_FOUR_BYTES")
        return data

    async def crc32(self,addr:int,length:int)->int:
        if addr%4 or length<=0 or length%4:
            raise RomWireError("BSL_CRC_BAD_ALIGNMENT")
        data=await self._call(CRC32,address=addr,length=length,extra=b"\x00"*4)
        if type(data) is not bytes or len(data)!=4:
            raise RomWireError("BSL_CRC_BAD_LENGTH")
        return struct.unpack(">I",data)[0]

    async def erase_sector(self,addr:int)->bool:
        if type(addr) is not int or addr not in APP_SECTOR_ADDRESSES:
            raise RomWireError("BSL_ERASE_NOT_IN_P7U_APP_ALLOWLIST")
        self._download_remaining = 0
        return bool(await self._call(SECTOR_ERASE,address=addr))

    async def begin_download(self,addr:int,length:int)->bool:
        self._download_remaining = 0
        if (type(addr) is not int or addr % APP_SECTOR_SIZE
                or type(length) is not int or length != APP_SECTOR_SIZE):
            raise RomWireError("BSL_DOWNLOAD_BAD_GEOMETRY")
        if addr not in APP_SECTOR_ADDRESSES:
            raise RomWireError("BSL_DOWNLOAD_PROTECTED_RANGE")
        ok = bool(await self._call(DOWNLOAD,address=addr,length=length))
        if ok:
            self._download_remaining = length
        return ok

    async def send_data(self,data:bytes)->bool:
        if not isinstance(data,bytes) or not 0<len(data)<=252 or len(data)%4:
            raise RomWireError("BSL_SEND_DATA_BAD_SIZE")
        if not 0 < len(data) <= self._download_remaining:
            raise RomWireError("BSL_SEND_DATA_OUTSIDE_DOWNLOAD")
        remaining = self._download_remaining
        self._download_remaining = 0  # A failed/uncertain packet must not be retried.
        ok = bool(await self._call(SEND_DATA,payload=data))
        if ok:
            self._download_remaining = remaining - len(data)
        return ok
