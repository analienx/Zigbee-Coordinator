import asyncio
import binascii
import unittest
from p7u_usb_sparse_capture import (
    capture_sparse,FLASH,SECTOR,NV_START,NV_END,
)

IDENTITY="a"*64

class FakeROM:
    def __init__(self,image):
        self.image=bytes(image)
        self.calls=[]
        self.identity=IDENTITY
        self.corrupt_nv_crc=False
    async def identity_sha256(self):
        return self.identity
    async def crc32(self,address,length):
        self.calls.append(("CRC",address,length))
        val=binascii.crc32(self.image[address:address+length])&0xffffffff
        return (val^1) if self.corrupt_nv_crc and NV_START<=address<NV_END else val
    async def read_flash(self,address,length):
        self.calls.append(("READ",address,length))
        return self.image[address:address+length]

class SparseTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.base=b"\xff"*FLASH

    async def test_fresh_nv_only_and_88_crc_checks(self):
        new=bytearray(self.base)
        new[NV_START+123]=45
        new[NV_END-1]=99
        rom=FakeROM(new)
        result=await capture_sparse(rom,prior_full_verified=self.base,
                          expected_identity_sha256=IDENTITY)
        self.assertEqual(result.snapshot,bytes(new))
        self.assertEqual(result.receipt.nv_bytes_read,NV_END-NV_START)
        self.assertEqual(result.receipt.rom_crc32_sector_checks,88)
        self.assertEqual(result.receipt.baseline_nv_changed_sectors,2)
        self.assertEqual(len([x for x in rom.calls if x[0]=="READ"]),6)
        self.assertTrue(all(NV_START<=addr<NV_END
                     for mode,addr,length in rom.calls if mode=="READ"))

    async def test_unexpected_app_drift_blocks(self):
        altered=bytearray(self.base)
        altered[0x4001]=33
        rom=FakeROM(altered)
        with self.assertRaisesRegex(ValueError,"NON_NV_BASELINE_DRIFT"):
            await capture_sparse(rom,prior_full_verified=self.base,
                      expected_identity_sha256=IDENTITY)

    async def test_ccfg_drift_blocks(self):
        altered=bytearray(self.base)
        altered[0xAE000+1]=77
        with self.assertRaisesRegex(ValueError,"NON_NV_BASELINE_DRIFT"):
            await capture_sparse(FakeROM(altered),prior_full_verified=self.base,
                      expected_identity_sha256=IDENTITY)

    async def test_boot_drift_blocks(self):
        altered=bytearray(self.base)
        altered[0xAC000+1]=77
        with self.assertRaisesRegex(ValueError,"NON_NV_BASELINE_DRIFT"):
            await capture_sparse(FakeROM(altered),prior_full_verified=self.base,
                      expected_identity_sha256=IDENTITY)

    async def test_corrupted_nv_crc_blocks(self):
        rom=FakeROM(self.base)
        rom.corrupt_nv_crc=True
        with self.assertRaisesRegex(ValueError,"NV_CAPTURE_CRC_MISMATCH"):
            await capture_sparse(rom,prior_full_verified=self.base,
                      expected_identity_sha256=IDENTITY)

    async def test_readonly_deadline_invalid_fails_before_uart_access(self):
        rom=FakeROM(self.base)
        for invalid in (0,float("inf"),61,-1):
            with self.assertRaisesRegex(ValueError,"INVALID_READONLY_DEADLINE"):
                await capture_sparse(rom,prior_full_verified=self.base,
                       expected_identity_sha256=IDENTITY,total_timeout_seconds=invalid)
        self.assertEqual(rom.calls,[])

    async def test_readonly_timeout_never_mutates(self):
        rom=FakeROM(self.base)
        async def stalled_crc(address,length):
            await asyncio.sleep(0.10)
            return 0
        rom.crc32=stalled_crc
        with self.assertRaises(asyncio.TimeoutError):
            await capture_sparse(rom,prior_full_verified=self.base,
                expected_identity_sha256=IDENTITY,total_timeout_seconds=0.01)
        self.assertFalse(any(x[0]!="CRC" for x in rom.calls))

    async def test_device_identity_mismatch_blocks(self):
        rom=FakeROM(self.base)
        rom.identity="b"*64
        with self.assertRaisesRegex(ValueError,"HARDWARE_CHANGED"):
            await capture_sparse(rom,prior_full_verified=self.base,
                      expected_identity_sha256=IDENTITY)

if __name__=="__main__": unittest.main()
