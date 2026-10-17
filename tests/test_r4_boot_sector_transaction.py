"""Synthetic fake ROM: strict P7U 0xAC000 handoff write admission and guards."""
import asyncio
import importlib.util
from pathlib import Path
import struct
import unittest

PATH = Path(__file__).resolve().parents[1]/"firmware/slzb-06p7u/r4/release/r4_boot_sector_transaction.py"
spec=importlib.util.spec_from_file_location("boot_sector_tx",PATH)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class FakeROM:
    def __init__(self,before:bytes,expected_app:dict[int,int]):
        self.bytes=bytearray(before)
        self.app=dict(expected_app)
        self.ccfg_crc=m.STOCK_TOP_CRC
        self.boot_addr=m.BOOT
        self.bl=0xC5FE0FC5
        self.erase_calls=[]
        self.download_calls=[]
        self.pos=None
        self.fail_packet=False

    async def crc32(self,address,length):
        if length!=m.SECTOR:raise RuntimeError("SIZE")
        if address==m.TOP:return self.ccfg_crc
        if address==m.BOOT:return m.crc(self.bytes)
        return self.app[address]

    async def read_word(self,address):
        if address==m.IMAGE_VALID_WORD:return struct.pack("<I",self.boot_addr)
        if address==m.BSL_WORD:return struct.pack("<I",self.bl)
        raise RuntimeError("UNKNOWN_READ")

    async def erase_sector(self,address):
        if address!=m.BOOT:raise RuntimeError("INVALID_ERASE")
        self.erase_calls.append(address)
        self.bytes[:]=b"\xff"*m.SECTOR
        return True

    async def begin_download(self,address,length):
        if address!=m.BOOT or length!=m.SECTOR:raise RuntimeError("INVALID_DOWNLOAD")
        self.download_calls.append((address,length))
        self.pos=0
        return True

    async def send_data(self,packet):
        if self.fail_packet:return False
        if self.pos is None:raise RuntimeError("NO_DOWNLOAD")
        self.bytes[self.pos:self.pos+len(packet)]=packet
        self.pos+=len(packet)
        return True


class SingleBootSectorTests(unittest.TestCase):
    def setUp(self):
        self.before=bytes(range(256))*32
        self.after=b"\x55"*m.SECTOR
        self.app={addr:addr+1234 for addr in range(0,0x2E000,m.SECTOR)}

    def test_read_only_and_one_sector_only(self):
        async def scenario():
            rom=FakeROM(self.before,self.app)
            approval=await m.boot_sector_admission(rom,self.before,self.after,self.app)
            self.assertEqual(rom.erase_calls,[])
            self.assertFalse(approval["flash_authorized"])
            result=await m.write_single_boot_sector(
                rom,self.before,self.after,self.app,approval,approval["binding_sha256"])
            self.assertEqual(result["status"],"SINGLE_BOOT_SECTOR_WRITE_CRC_VERIFIED")
            self.assertEqual(rom.erase_calls,[m.BOOT])
            self.assertEqual(rom.download_calls,[(m.BOOT,m.SECTOR)])
            self.assertEqual(bytes(rom.bytes),self.after)
            self.assertFalse(result["ccfg_touched"])
            self.assertFalse(result["nv_touched"])
        asyncio.run(scenario())

    def test_denial_on_ccfg_or_app_changed(self):
        async def scenario():
            for mutation in ("ccfg","bootword","backdoor","app","sector"):
                rom=FakeROM(self.before,self.app)
                if mutation=="ccfg":rom.ccfg_crc^=1
                if mutation=="bootword":rom.boot_addr=0
                if mutation=="backdoor":rom.bl=0xFFFFFFFF
                if mutation=="app":rom.app[0x2000]^=1
                if mutation=="sector":rom.bytes[0]^=1
                with self.subTest(mutation=mutation),self.assertRaisesRegex(ValueError,"R4_BOOT_SECTOR_WRITE_BLOCKED"):
                    await m.boot_sector_admission(rom,self.before,self.after,self.app)
                self.assertFalse(rom.erase_calls)
        asyncio.run(scenario())

    def test_bad_token_never_erases(self):
        async def scenario():
            rom=FakeROM(self.before,self.app)
            approval=await m.boot_sector_admission(rom,self.before,self.after,self.app)
            with self.assertRaisesRegex(ValueError,"TOKEN"):
                await m.write_single_boot_sector(rom,self.before,self.after,self.app,approval,"0"*64)
            self.assertFalse(rom.erase_calls)
        asyncio.run(scenario())

    def test_data_transfer_failure_no_false_success(self):
        async def scenario():
            rom=FakeROM(self.before,self.app)
            approval=await m.boot_sector_admission(rom,self.before,self.after,self.app)
            rom.fail_packet=True
            with self.assertRaisesRegex(ValueError,"PACKET_FAILED"):
                await m.write_single_boot_sector(
                    rom,self.before,self.after,self.app,approval,approval["binding_sha256"])
            self.assertEqual(rom.erase_calls,[m.BOOT])
        asyncio.run(scenario())


if __name__=="__main__":
    unittest.main()
