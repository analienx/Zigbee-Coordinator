#!/usr/bin/env python3
"""Synthetic 704-KiB P7U ROM escrow tests. No hardware/network/flash."""
import asyncio,binascii,hashlib,json,sys,tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/"firmware/slzb-06p7u/qualification"))
import p7u_original_radio_escrow as e

class FakeRom:
    def __init__(self,corrupt=False):
        self.memory=bytearray(b"\xff"*e.FLASH_BYTES)
        self.memory[0]=0x19
        self.memory[e.strict.gate.NV5_BASE]=0x58
        self.crc_calls=0
        self.corrupt=corrupt
        self.writes=0
    async def read_word(self,addr):
        assert addr%4==0 and 0<=addr<e.FLASH_BYTES
        return bytes(self.memory[addr:addr+4])
    async def crc32(self,addr,length):
        self.crc_calls+=1
        c=binascii.crc32(self.memory[addr:addr+length])&0xffffffff
        return c^1 if self.corrupt and addr==e.strict.gate.NV5_BASE else c

async def test():
    old_observe=e.strict.observe
    async def observe(rom):
        ccfg=bytes(rom.memory[e.strict.gate.CCFG_START:
                            e.strict.gate.CCFG_START+e.strict.gate.CCFG_SIZE])
        return {"flash_bytes":e.FLASH_BYTES,"ccfg_sha256":hashlib.sha256(ccfg).hexdigest(),
                "chip_id":123,"read_only_identity":True}
    e.strict.observe=observe
    try:
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"capture";p.mkdir()
            rom=FakeRom()
            result=await e.capture(rom,p)
            assert result["status"]=="ORIGINAL_SAME_DEVICE_FLASH_PRESERVED_READ_ONLY"
            assert rom.crc_calls==2*(e.FLASH_BYTES//e.SECTOR)
            assert result["nv5_all_ff"] is False
            assert result["flash_authorized"] is False
            assert (p/"original_p7u_raw_704k.private.bin").read_bytes()==bytes(rom.memory)
            receipt=json.loads((p/"original_flash_readback_seal.json").read_text())
            assert receipt["nv5_bytes_captured"]==5*e.SECTOR
            assert receipt["rom_bsl_reentry_twice_proven"] is False
            p2=Path(td)/"fault";p2.mkdir()
            try:await e.capture(FakeRom(corrupt=True),p2)
            except e.strict.StrictError as ex:
                assert str(ex)=="ESCROW_ROM_CRC_MISMATCH"
            else:raise AssertionError("CORRUPT_ROM_CRC_ACCEPTED")
            assert not (p2/"original_p7u_raw_704k.private.bin").exists()
            assert not (p2/"original_flash_readback_seal.json").exists()
            try:e.check_private(Path(td)/"unsafe")
            except e.strict.StrictError as ex:
                assert str(ex)=="ESCROW_PRIVATE_ROOT_REQUIRED"
            else:raise AssertionError("PUBLIC_ESCROW_ACCEPTED")
    finally:e.strict.observe=old_observe
asyncio.run(test())
print("P7U_READONLY_ORIGINAL_704K_ESCROW_SYNTHETIC_PASS")
