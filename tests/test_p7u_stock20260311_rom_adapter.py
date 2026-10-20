"""No-hardware protocol and negative-window tests for stock20260311 ROM adapter."""
import asyncio
import hashlib
import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1] / "firmware/slzb-06p7u/r4/release/rom_writer"
sys.path.insert(0, str(ROOT))
SPEC = importlib.util.spec_from_file_location("stock20260311_rom", ROOT / "p7u_stock20260311_rom_adapter.py")
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)

CCFG = bytes.fromhex(
    "000080011000c0fffdff5800ffc1b9f1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc50ffec5ffffffff00ffffff00c5c5ff000000ff00c00a00ffffffffffffffff")


class FakeWire(m.Stock20260311ROM):
    def __init__(self):
        super().__init__()
        self.flash = bytearray((i % 251 for i in range(m.FLASH)))
        self.flash[m.CCFG:] = CCFG
        self.rom_words = {m.FCFG_ICEPICK: bytes.fromhex("0070b70b"),
                          m.FLASH_SIZE_REG: bytes.fromhex("58000000"),
                          m.FCFG_IEEE: bytes.fromhex("01020304"),
                          m.FCFG_IEEE+4: bytes.fromhex("05060708")}
        self.calls = []
        self.cursor = self.end = None
        self.fail_send = False
        self.fail_status = False

    async def get_chip_id(self):
        return 0x2652

    async def _call(self, opcode, *, address=None, length=None, payload=b"", extra=b""):
        self.calls.append((opcode, address, length, len(payload), extra))
        if opcode == m.MEMORY_READ:
            count = extra[1]
            if address in self.rom_words:
                return self.rom_words[address]
            return bytes(self.flash[address:address+4*count])
        if opcode == m.GET_STATUS:
            return 0x44 if self.fail_status else 0x40
        if opcode == m.SECTOR_ERASE:
            self.flash[address:address+m.SECTOR] = b"\xff"*m.SECTOR
            return True
        if opcode == m.DOWNLOAD:
            self.cursor, self.end = address, address+length
            return True
        if opcode == 0x24:
            if self.fail_send:
                raise m.RomWireError("SIMULATED_UNCERTAIN_PACKET")
            assert self.cursor is not None and self.cursor+len(payload) <= self.end
            self.flash[self.cursor:self.cursor+len(payload)] = payload
            self.cursor += len(payload)
            return True
        raise AssertionError("unexpected opcode")


class AdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_batched_read_and_bounded_full_sector(self):
        r = FakeWire()
        section = await r.read(0x2000, m.SECTOR)
        self.assertEqual(section, bytes(r.flash[0x2000:0x4000]))
        calls = [c for c in r.calls if c[0] == m.MEMORY_READ]
        self.assertEqual(len(calls), 35)
        self.assertEqual(calls[0][-1], b"\x01\x3c")
        self.assertEqual(calls[-1][-1], b"\x01\x08")
        self.assertTrue(all(0 < c[-1][1] <= 60 for c in calls))
        for address, length in ((-4, 4), (m.FLASH, 4), (m.FLASH-4, 8), (0, 3), (0, 0)):
            with self.subTest(address=address, length=length), self.assertRaisesRegex(m.RomWireError, "FLASH_READ_BOUNDS"):
                await r.read(address, length)

    async def test_identity_checks_silicon_and_factory_ccfg_fresh(self):
        r = FakeWire()
        identity = await r.identity_sha256()
        self.assertEqual(len(identity), 64)
        self.assertNotEqual(identity, hashlib.sha256(bytes(r.flash)).hexdigest())
        r.flash[-1] ^= 1
        with self.assertRaisesRegex(m.RomWireError, "FACTORY_CCFG_CHANGED"):
            await r.identity_sha256()
        r.flash[-1] ^= 1
        r.rom_words[m.FLASH_SIZE_REG] = b"\x57\x00\x00\x00"
        with self.assertRaisesRegex(m.RomWireError, "NOT_CC26X2X7"):
            await r.identity_sha256()

    async def test_only_app_full_sector_and_boot_tail_then_vectors(self):
        r = FakeWire()
        with self.assertRaisesRegex(m.RomWireError, "DOWNLOAD_OUTSIDE"):
            await r.begin_download(0x2000, m.SECTOR)
        for address in (0xA0000, 0xA4000, 0xAE000, m.CCFG, m.FLASH):
            with self.subTest(address=address), self.assertRaisesRegex(m.RomWireError, "ERASE_PROTECTED_RANGE"):
                await r.erase_sector(address)
        await r.erase_sector(0x2000)
        with self.assertRaisesRegex(m.RomWireError, "DOWNLOAD_OUTSIDE"):
            await r.begin_download(0x2004, 4)
        await r.begin_download(0x2000, m.SECTOR)
        for length in (252, 252, 252):
            await r.send_data(b"\x00"*length)
        self.assertEqual(r._download_remaining, m.SECTOR - 756)
        with self.assertRaisesRegex(m.RomWireError, "DOWNLOAD_STATE_INVALID"):
            await r.begin_download(0x2000, m.SECTOR)
        for address in (m.BOOT, 0xA4000):
            with self.subTest(address=address), self.assertRaisesRegex(m.RomWireError, "DOWNLOAD_IN_PROGRESS|ERASE_PROTECTED_RANGE"):
                await r.erase_sector(address)

        s = FakeWire()
        await s.erase_sector(m.BOOT)
        with self.assertRaisesRegex(m.RomWireError, "DOWNLOAD_OUTSIDE"):
            await s.begin_download(m.BOOT, 8)
        await s.begin_download(m.BOOT+8, m.SECTOR-8)
        remaining = m.SECTOR-8
        while remaining:
            piece = min(252, remaining)
            await s.send_data(b"\x55"*piece)
            remaining -= piece
        self.assertTrue(s._boot_tail_sent)
        self.assertEqual(s.flash[m.BOOT:m.BOOT+8], b"\xff"*8)
        await s.begin_download(m.BOOT, 8)
        await s.send_data(b"\x22"*8)
        self.assertEqual(s.flash[m.BOOT:m.BOOT+8], b"\x22"*8)
        self.assertEqual(s._erased_target, None)
        self.assertFalse(any(c[0] in (0x2C, 0x2B, 0x25, 0x2D) for c in s.calls))

    async def test_uncertain_packet_and_status_poison_future_writes(self):
        r = FakeWire()
        await r.erase_sector(0x2000)
        await r.begin_download(0x2000, m.SECTOR)
        r.fail_send = True
        with self.assertRaisesRegex(m.RomWireError, "SIMULATED_UNCERTAIN_PACKET"):
            await r.send_data(b"\x00"*4)
        with self.assertRaisesRegex(m.RomWireError, "SESSION_POISONED"):
            await r.erase_sector(0x4000)
        s = FakeWire()
        s.fail_status = True
        self.assertFalse(await s.status())
        with self.assertRaisesRegex(m.RomWireError, "SESSION_POISONED"):
            await s.erase_sector(0x2000)

    async def test_no_auto_usb_reconnect_or_network_endpoint(self):
        r = FakeWire()
        for endpoint in ("socket://192.0.2.1:6638", "COM0", "\\\\.\\COM6", "", "localhost"):
            with self.subTest(endpoint=endpoint), self.assertRaisesRegex(m.RomWireError, "EXPLICIT_WINDOWS_COM_ONLY"):
                await r.open(endpoint)


if __name__ == "__main__":
    unittest.main()
