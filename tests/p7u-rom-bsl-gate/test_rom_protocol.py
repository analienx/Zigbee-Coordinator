#!/usr/bin/env python3
"""SMLIGHT/TI CC26x2 ROM wire-framing parity and hostile protocol faults."""
import asyncio
import struct
import sys
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/"firmware/slzb-06p7u/qualification"))
from p7u_rom_lowlevel import (RomSerial,RomWireError,ACK,NACK,
    SYNC,DOWNLOAD,GET_STATUS,SEND_DATA,SECTOR_ERASE,CRC32,GET_CHIP_ID,MEMORY_READ)
from p7u_rom_transport import SmlightRom

class Writer:
    def __init__(self):self.sent=[];self.closed=False
    def write(self,data):self.sent.append(bytes(data))
    async def drain(self):pass
    def close(self):self.closed=True
    async def wait_closed(self):pass

def packet(data:bytes)->bytes:
    return bytes((len(data)+2,sum(data)&255))+data

def host_frame(op:int,*values:int,extra:bytes=b"")->bytes:
    body=bytes((op,))+b"".join(struct.pack(">I",x) for x in values)+extra
    return bytes((len(body)+2,sum(body)&255))+body

def stub(responses:bytes)->tuple[RomSerial,Writer]:
    rom=RomSerial()
    rom.reader=asyncio.StreamReader()
    rom.reader.feed_data(responses)
    writer=Writer()
    rom.writer=writer
    return rom,writer

async def reject(coro,reason):
    try:await coro
    except RomWireError as e:assert str(e)==reason,(str(e),reason)
    else:raise AssertionError("Expected "+reason)

async def main():
    rom,writer=stub(ACK)
    assert await rom.synchronize() is True
    assert writer.sent==[b"\x55\x55"]
    await rom.close();assert writer.closed

    rom,writer=stub(ACK+packet(b"\x00\x00\x00\xb7")+
                    ACK+packet(b"\x40"))
    assert await rom.get_chip_id()==0x00b7
    assert writer.sent==[host_frame(GET_CHIP_ID),ACK,
                         host_frame(GET_STATUS),ACK]

    addr=0x50001318
    rom,writer=stub(ACK+packet(b"\x00\x70\xb7\x0b")+ACK+packet(b"\x40"))
    assert await rom.read_word(addr)==b"\x00\x70\xb7\x0b"
    assert writer.sent[0]==host_frame(MEMORY_READ,addr,extra=b"\x01\x01")
    assert writer.sent[1:]==[ACK,host_frame(GET_STATUS),ACK]

    rom,writer=stub(ACK+packet(b"\x12\x34\x56\x78")+ACK+packet(b"\x40"))
    assert await rom.crc32(0x2000,8192)==0x12345678
    assert writer.sent[0]==host_frame(CRC32,0x2000,8192,extra=b"\x00"*4)

    for method,expected in (
        ("erase_sector",host_frame(SECTOR_ERASE,0x2000)),
        ("begin_download",host_frame(DOWNLOAD,0x2000,8192)),
        ("send_data",host_frame(SEND_DATA,extra=b"\x12"*252)),
    ):
        rom,writer=stub(ACK+ACK+packet(b"\x40"))
        if method=="erase_sector":ok=await rom.erase_sector(0x2000)
        elif method=="begin_download":ok=await rom.begin_download(0x2000,8192)
        else:ok=await rom.send_data(b"\x12"*252)
        assert ok is True
        assert writer.sent==[expected,host_frame(GET_STATUS),ACK]

    # Error/garbage handling. Never call an unlisted command on failure.
    rom,writer=stub(NACK)
    await reject(rom.erase_sector(0),"BSL_NACK")
    assert writer.sent==[host_frame(SECTOR_ERASE,0)]
    rom,writer=stub(ACK+bytes((3,0))+b"\x40")
    await reject(rom.get_chip_id(),"BSL_RESPONSE_CHECKSUM")
    assert writer.sent[-1]==NACK
    rom,writer=stub(ACK+ACK+packet(b"\x43"))
    await reject(rom.erase_sector(0),"BSL_TARGET_NON_SUCCESS_STATUS")
    rom,writer=stub(ACK+ACK+packet(b"\x40\x40"))
    await reject(rom.erase_sector(0),"BSL_GET_STATUS_BAD_LENGTH")
    rom,writer=stub(ACK+packet(b"\x11")+ACK+packet(b"\x40"))
    await reject(rom.get_chip_id(),"BSL_CHIP_ID_WRONG_LENGTH")

    rom,writer=stub(b"")
    await reject(rom.erase_sector(0xA4000),"BSL_ERASE_NOT_IN_P7U_APP_ALLOWLIST")
    await reject(rom.begin_download(0xA4000,8192),"BSL_DOWNLOAD_PROTECTED_RANGE")
    await reject(rom.send_data(b"\xff"*253),"BSL_SEND_DATA_BAD_SIZE")
    await reject(rom.send_data(b"\xff"*5),"BSL_SEND_DATA_BAD_SIZE")
    await reject(rom.read_word(3),"BSL_MEMORY_READ_UNALIGNED")
    await reject(rom.crc32(3,8192),"BSL_CRC_BAD_ALIGNMENT")
    await reject(rom._send(0x2C),"BSL_OPCODE_NOT_ALLOWLISTED")
    await reject(rom._send(0x2B),"BSL_OPCODE_NOT_ALLOWLISTED")
    assert writer.sent==[]
    assert not hasattr(SmlightRom,"erase_bank")
    assert not hasattr(SmlightRom,"cmdBankErase")
    assert not hasattr(SmlightRom,"reset_radio")
    print("P7U_TI_ROM_LOWLEVEL_WIRE_PARITY_HOSTILE_TEST_PASS_NO_DEVICE")

if __name__=="__main__":
    asyncio.run(main())
