"""Off-device known-R4 capture + admission + final full-byte parity regressions."""
import asyncio
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
R4=ROOT/"firmware/slzb-06p7u/r4"
for item in (ROOT/"tests", R4/"release", R4/"release/rom_writer"):
    sys.path.insert(0,str(item))
from test_r4_stock20260311_transition import (m,FakeROM,upgrade_inputs,LIVE)
from p7u_usb_sparse_capture import (capture_known_installed,KNOWN_R4_PROFILE,
                                     KnownR4FreshProtectedWitness)

class FastFakeROM(FakeROM):
    def __init__(self,capture):
        super().__init__(capture)
        self._faulted=False
        self.fences=0
    async def read_flash(self,address,length):
        return await self.read(address,length)
    async def assert_read_status(self):
        if self._faulted:raise RuntimeError("poisoned")
        self.fences+=1


def installed_image(up):
    plan=up["installed_plan"]
    before=bytearray(plan.snapshot)
    for a,content in plan.sectors.items():
        before[a:a+m.SECTOR]=content
    return bytes(before)


def known_current(up,cap):
    p=dict(up)
    p["pass2"]=None
    p["verified_known_capture"]=cap
    p["pass1"]=cap.snapshot
    p["expected_capture_sha256"]=m.sha(cap.snapshot)
    sec=dict(p["security_receipt"],capture_sha256=m.sha(cap.snapshot))
    p["security_receipt"]=sec
    p["expected_security_receipt_sha256"]=m.sha(m.canonical(sec))
    return p

class KnownR4FastPathTests(unittest.IsolatedAsyncioTestCase):
    async def make(self):
        up=upgrade_inputs()
        rom=FastFakeROM(up["pass1"])
        cap=await capture_known_installed(rom,installed_verified_image=installed_image(up),
                expected_identity_sha256=LIVE)
        kw=known_current(up,cap)
        plan=m.prepare_upgrade(**kw)
        return up,rom,cap,kw,plan

    async def test_single_live_protected_with_rom_crc_and_84_static_crc(self):
        up,rom,cap,_,plan=await self.make()
        self.assertEqual(cap.receipt["protected_reads"],1)
        self.assertEqual(cap.receipt["static_sector_rom_crc_checks"],84)
        self.assertEqual(cap.receipt["fresh_capture_bytes"],57344)
        self.assertGreaterEqual(rom.fences,2)
        self.assertEqual(plan.manifest["capture_mode"],KNOWN_R4_PROFILE)

    async def test_known_admission_final_88_sha_byte_verification(self):
        up,rom,cap,kw,plan=await self.make()
        adm=await m.admit_known_r4(rom,plan,expected_plan_sha256=plan.manifest["plan_sha256"],
              known_capture=cap,expected_live_identity_sha256=LIVE,
              security_receipt=kw["security_receipt"],
              expected_security_receipt_sha256=kw["expected_security_receipt_sha256"])
        async def durable(_):return True
        result=await m.execute(rom,plan,adm,
             expected_plan_sha256=plan.manifest["plan_sha256"],
             expected_admission_sha256=adm["admission_sha256"],
             capture_receipt=cap.receipt,
             expected_capture_receipt_sha256=m.sha(m.canonical(cap.receipt)),
             expected_live_identity_sha256=LIVE,
             journal=durable,same_session_known=True)
        self.assertEqual(result["verification_scope"],"ALL88_ROM_SHA")
        self.assertEqual(result["preflight_scope"],KNOWN_R4_PROFILE)
        self.assertFalse(result["nv_touched"])
        self.assertFalse(result["ccfg_touched"])
        self.assertEqual(rom.image[m.TOP:],plan.snapshot[m.TOP:])
        with self.assertRaisesRegex(ValueError,"SAME_TRANSPORT"):
            await m.execute(rom,plan,adm,
                 expected_plan_sha256=plan.manifest["plan_sha256"],
                 expected_admission_sha256=adm["admission_sha256"],
                 capture_receipt=cap.receipt,
                 expected_capture_receipt_sha256=m.sha(m.canonical(cap.receipt)),
                 expected_live_identity_sha256=LIVE,
                 journal=durable,same_session_known=True)

    async def test_wrong_installed_image_rejected_before_erase(self):
        up=upgrade_inputs()
        rom=FastFakeROM(up["pass1"])
        original=up["installed_plan"].snapshot
        with self.assertRaisesRegex(ValueError,"INSTALLED_STATIC"):
            await capture_known_installed(rom,installed_verified_image=original,
                     expected_identity_sha256=LIVE)
        self.assertFalse(rom.trace)

    async def test_corrupt_single_protected_read_fails_rom_crc(self):
        up=upgrade_inputs()
        rom=FastFakeROM(up["pass1"])
        original=rom.read_flash
        async def corrupt(addr,length):
            raw=await original(addr,length)
            return (bytes([raw[0]^1])+raw[1:]) if addr==0xA4000 else raw
        rom.read_flash=corrupt
        with self.assertRaisesRegex(ValueError,"PROTECTED_READ_CRC_FAILED"):
            await capture_known_installed(rom,installed_verified_image=installed_image(up),
                     expected_identity_sha256=LIVE)
        self.assertFalse(rom.trace)

    async def test_witness_reopen_cannot_make_plan(self):
        up,rom,cap,kw,plan=await self.make()
        rom.writer=object()
        with self.assertRaisesRegex(ValueError,"UART_SESSION_REOPENED"):
            await m.admit_known_r4(rom,plan,expected_plan_sha256=plan.manifest["plan_sha256"],
                  known_capture=cap,expected_live_identity_sha256=LIVE,
                  security_receipt=kw["security_receipt"],
                  expected_security_receipt_sha256=kw["expected_security_receipt_sha256"])
        self.assertFalse(rom.trace)

    async def test_forbid_fake_duplicate_input(self):
        up,rom,cap,kw,plan=await self.make()
        kw["pass2"]=cap.snapshot
        with self.assertRaisesRegex(ValueError,"KNOWN_CAPTURE_MUST_NOT_FAKE_DUPLICATE"):
            m.prepare_upgrade(**kw)
        self.assertFalse(rom.trace)

    async def test_final_corrupt_static_sector_detected(self):
        up,rom,cap,kw,plan=await self.make()
        adm=await m.admit_known_r4(rom,plan,expected_plan_sha256=plan.manifest["plan_sha256"],
                  known_capture=cap,expected_live_identity_sha256=LIVE,
                  security_receipt=kw["security_receipt"],
                  expected_security_receipt_sha256=kw["expected_security_receipt_sha256"])
        old=rom.read
        callcount=0
        async def sabotage(addr,length):
            nonlocal callcount
            result=await old(addr,length)
            # Corrupt unchanged app 0x80000 AFTER write phase, while final SHA
            # reads from 0x0 upwards. This must never produce success.
            if addr==0x80000 and any(x[0]=="packet" for x in rom.trace):
                return bytes([result[0]^1])+result[1:]
            return result
        rom.read=sabotage
        async def durable(_):return True
        with self.assertRaisesRegex(ValueError,"INDEPENDENT_READBACK_CRC_DISAGREES|FINAL_ALL88_PARITY"):
            await m.execute(rom,plan,adm,
                 expected_plan_sha256=plan.manifest["plan_sha256"],
                 expected_admission_sha256=adm["admission_sha256"],
                 capture_receipt=cap.receipt,
                 expected_capture_receipt_sha256=m.sha(m.canonical(cap.receipt)),
                 expected_live_identity_sha256=LIVE,
                 journal=durable,same_session_known=True)

if __name__=="__main__":
    unittest.main()
