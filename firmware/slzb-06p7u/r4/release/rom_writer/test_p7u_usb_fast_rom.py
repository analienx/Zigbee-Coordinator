"""USB ROM fast-read protocol regression; no hardware calls."""
import asyncio
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from p7u_usb_fast_rom import SafeFastUsbRom, STATUS_INTERVAL
from p7u_rom_lowlevel import RomWireError, MEMORY_READ, GET_STATUS, SECTOR_ERASE

class FakeWriter:
    def is_closing(self):return False

class SafeFastUsbReadTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.rom=SafeFastUsbRom()
        self.rom.reader=object()
        self.rom.writer=FakeWriter()
        self.calls=[]
        self.badlen=False
        self.fail_status=False
        async def send(op,**kwargs):
            self.calls.append(("SEND",op,kwargs))
        async def ack():
            self.calls.append(("ACK",))
        async def receive():
            self.calls.append(("DATA",))
            words=self.calls[-3][2]["extra"][1]
            return b"\x7a"*(4*words-4 if self.badlen else 4*words)
        async def call(op,**kwargs):
            self.calls.append(("CALL",op))
            if op==GET_STATUS:
                return 0x41 if self.fail_status else 0x40
            return True
        async def chip():
            self.calls.append(("CHIP_ID",))
            return 0xf000
        self.rom._send=send
        self.rom._ack=ack
        self.rom._receive=receive
        self.rom._call=call
        self.rom.get_chip_id=chip

    async def test_mutating_packet_status_redundancy_only_exact_adapter(self):
        import sys
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
        from r4_stock20260311_transition import _verified_wire_status_embedded
        from p7u_stock20260311_rom_adapter import Stock20260311ROM
        self.assertTrue(_verified_wire_status_embedded(self.rom))
        self.assertTrue(_verified_wire_status_embedded(Stock20260311ROM()))
        class ForeignChild(SafeFastUsbRom):
            pass
        self.assertFalse(_verified_wire_status_embedded(ForeignChild()))
        class Tampered(SafeFastUsbRom):
            async def _call(self,*args,**kwargs):return True
        self.assertFalse(_verified_wire_status_embedded(Tampered()))

    async def test_initial_disabled_and_explicit_enable(self):
        self.assertFalse(self.rom.fast_read_enabled)
        await self.rom.enable_fast_reads()
        self.assertTrue(self.rom.fast_read_enabled)
        self.assertIn(("CHIP_ID",),self.calls)

    async def test_32_reads_save_31_status_roundtrips(self):
        await self.rom.enable_fast_reads()
        for n in range(STATUS_INTERVAL):
            data=await self.rom.read(n*240,240)
            self.assertEqual(data,b"\x7a"*240)
        self.assertEqual(self.rom.read_packets,32)
        self.assertEqual(self.rom.read_status_checks,1)
        self.assertEqual(sum(x[1]==GET_STATUS for x in self.calls if x[0]=="CALL"),1)
        self.assertEqual(sum(x[1]==MEMORY_READ for x in self.calls if x[0]=="SEND"),32)
        await self.rom.assert_read_status()
        self.assertEqual(self.rom.read_status_checks,2)

    async def test_bulk_read_8192_uses_two_status_or_less(self):
        await self.rom.enable_fast_reads()
        self.assertEqual(await self.rom.read(0,8192),b"\x7a"*8192)
        self.assertEqual(self.rom.read_packets,35)
        self.assertEqual(self.rom.read_status_checks,1)

    async def test_malformed_read_latches_poison_and_prevents_erase(self):
        await self.rom.enable_fast_reads()
        self.badlen=True
        with self.assertRaises(RomWireError):
            await self.rom.read(0,240)
        self.assertTrue(self.rom._faulted)
        with self.assertRaises(RomWireError):
            await self.rom.erase_sector(0)
        self.assertFalse(any(x[1]==SECTOR_ERASE for x in self.calls if x[0]=="CALL"))

    async def test_periodic_bad_status_latches_poison(self):
        await self.rom.enable_fast_reads()
        self.fail_status=True
        with self.assertRaises(RomWireError):
            await self.rom.read(0,240*STATUS_INTERVAL)
        self.assertTrue(self.rom._faulted)
        with self.assertRaises(RomWireError):
            await self.rom.assert_read_status()

    async def test_strict_protected_bounds(self):
        await self.rom.enable_fast_reads()
        for address,length in [(0xAFFFF,4),(0xAFFFC,8),(-4,4),(0,0),(2,4)]:
            with self.assertRaises(RomWireError):
                await self.rom.read(address,length)
        self.assertEqual(self.rom.read_packets,0)

    async def test_direct_ha_usb_only_115200_no_autodiscovery(self):
        from unittest.mock import AsyncMock, patch
        from p7u_rom_lowlevel import RomSerial
        exact="/dev/serial/by-id/usb-SMLIGHT_SMLIGHT_SLZB-06p7U_SLZB-06p7U115236-if00"
        with patch.object(RomSerial,"open",new_callable=AsyncMock) as opening:
            await self.rom.open(exact)
            self.assertEqual(opening.await_args.args,(self.rom,exact,115200))
            with self.assertRaises(RomWireError):
                await self.rom.open(exact,460800)
            self.assertEqual(opening.await_count,1)
        for bad in ("/dev/ttyACM0","/dev/serial/by-id/not-a-coordinator",
                    exact+";reboot","/dev/serial/by-id/usb-SMLIGHT_other"):
            with self.assertRaises(RomWireError):
                await self.rom.open(bad)

    async def test_cannot_enable_during_download_or_fault(self):
        self.rom._download_remaining=4
        with self.assertRaises(RomWireError):
            await self.rom.enable_fast_reads()
        self.rom._download_remaining=0
        self.rom._faulted=True
        with self.assertRaises(RomWireError):
            await self.rom.enable_fast_reads()

if __name__=="__main__": unittest.main()
