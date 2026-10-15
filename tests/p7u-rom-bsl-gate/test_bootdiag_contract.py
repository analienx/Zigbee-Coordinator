#!/usr/bin/env python3
"""Exact 24-sector diagnostic/stock cleanup contract; no hardware."""
import argparse
import asyncio
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import AsyncMock

BASE = Path(__file__).resolve().parents[2] / "firmware/slzb-06p7u/qualification"
sys.path.insert(0, str(BASE))
import p7u_bootdiag as bd
import p7u_strict_sector_writer as core
from p7u_rom_lowlevel import RomSerial, RomWireError, SECTOR_ERASE, DOWNLOAD
from test_strict_sector_writer import FakeROM


def app_data(tail=False):
    data = {i: (i * 17) % 251 for i in range(1600)}
    data.update(enumerate((0x20024000).to_bytes(4, "little") + (0x101).to_bytes(4, "little")))
    if tail: data[0x2FFFF] = 0x5A
    return data


class ContractTests(unittest.IsolatedAsyncioTestCase):
    async def test_24th_sector_requires_separate_adapter_and_default_stays_23(self):
        for method, values in (("erase_sector", (0x2E000,)), ("begin_download", (0x2E000, 8192))):
            with self.assertRaises(RomWireError): await getattr(RomSerial(), method)(*values)
        rom = bd.BootdiagRom()
        rom._call = AsyncMock(return_value=True)
        self.assertTrue(await rom.erase_sector(0x2E000))
        rom._call.assert_awaited_with(SECTOR_ERASE, address=0x2E000)
        self.assertTrue(await rom.begin_download(0x2E000, 8192))
        rom._call.assert_awaited_with(DOWNLOAD, address=0x2E000, length=8192)
        calls = rom._call.await_count
        for addr in (0x30000, 0xA4000, 0xAA000, 0xAE000, 0xAFFA8, 0xB0000, -8192, 0x2E004):
            with self.assertRaises(RomWireError): await rom.erase_sector(addr)
            with self.assertRaises(RomWireError): await rom.begin_download(addr, 8192)
        for length in (0, 4, 4096, 16384):
            with self.assertRaises(RomWireError): await rom.begin_download(0x2E000, length)
        self.assertEqual(rom._call.await_count, calls)
        self.assertFalse(hasattr(rom, "erase_bank"))

    async def test_diagnostic_write_and_paired_stock_cleanup_preserve_nv_ccfg_and_gap(self):
        candidate = bd.bundle(app_data(True), {"fixture": True})
        baseline_blocks = list(candidate.sectors[:23])
        addr, block = baseline_blocks[0]
        old = bytearray(block); old[1000] ^= 1
        baseline_blocks[0] = (addr, bytes(old))
        baseline = core.Bundle("p7u-cap192-f07", "a" * 64, "b" * 64, tuple(baseline_blocks))
        rom = FakeROM()
        for addr, data in baseline.sectors: rom.flash[addr:addr+8192] = data
        rom.flash[core.gate.NV5_BASE:core.gate.CCFG_SECTOR] = b"\x69" * (5 * 8192)
        rom.flash[0x30000] = 0x31
        protected = bytes(rom.flash[0x30000:])
        identity = await core.observe(rom)
        pins = {"radio_" + key: identity[key] for key in ("factory_id_digest", "ccfg_sha256")}
        plan = await bd.inspect(rom, candidate, baseline, "fixture", pins, diagnostic=True)
        self.assertEqual(len(plan["sectors"]), 24)
        self.assertEqual(rom.erases, [])
        result = await bd.execute(rom, candidate, baseline, "fixture", pins, plan,
                                  plan["approval_digest"], diagnostic=True)
        self.assertEqual(rom.erases, [0x2E000, 0])
        self.assertTrue(result["nv5_unchanged"])
        self.assertEqual(bytes(rom.flash[0x30000:]), protected)
        self.assertEqual(rom.flash[0x2FFFF], 0x5A)
        fallback = bd.bundle(app_data(), {"fixture_stock": True})
        recovery = await bd.inspect(rom, fallback, baseline, "fixture", pins, diagnostic=False)
        await bd.execute(rom, fallback, baseline, "fixture", pins, recovery,
                         recovery["approval_digest"], diagnostic=False)
        self.assertEqual(rom.flash[:bd.END], b"".join(data for _, data in fallback.sectors))
        self.assertEqual(rom.flash[0x2C000:bd.END], b"\xff" * (2 * 8192))
        self.assertEqual(bytes(rom.flash[0x30000:]), protected)

    async def test_changed_nv_or_wrong_radio_cannot_reach_erase(self):
        candidate = bd.bundle(app_data(True), {"fixture": True})
        baseline = core.Bundle("p7u-cap192-f07", "a" * 64, "b" * 64, candidate.sectors[:23])
        rom = FakeROM()
        for addr, data in baseline.sectors: rom.flash[addr:addr+8192] = data
        identity = await core.observe(rom)
        pins = {"radio_" + key: identity[key] for key in ("factory_id_digest", "ccfg_sha256")}
        wrong = dict(pins); wrong["radio_factory_id_digest"] = "f" * 64
        with self.assertRaisesRegex(core.StrictError, "BOOTDIAG_NOT_ORIGINAL_CAPTURED_RADIO"):
            await bd.inspect(rom, candidate, baseline, "fixture", wrong, diagnostic=True)
        plan = await bd.inspect(rom, candidate, baseline, "fixture", pins, diagnostic=True)
        rom.flash[core.gate.NV5_BASE] ^= 1
        with self.assertRaisesRegex(core.StrictError, "BOOTDIAG_NV_CHANGED_SINCE_INSPECT"):
            await bd.execute(rom, candidate, baseline, "fixture", pins, plan,
                             plan["approval_digest"], diagnostic=True)
        self.assertEqual(rom.erases, [])

    async def test_unmatched_r2_or_extra_sector_contents_are_preserved(self):
        candidate = bd.bundle(app_data(True), {"fixture": True})
        baseline = core.Bundle("p7u-cap192-f07", "a" * 64, "b" * 64, candidate.sectors[:23])
        rom = FakeROM()
        for addr, data in baseline.sectors: rom.flash[addr:addr+8192] = data
        identity = await core.observe(rom)
        pins = {"radio_" + key: identity[key] for key in ("factory_id_digest", "ccfg_sha256")}
        rom.flash[0x2E000] = 0
        with self.assertRaisesRegex(core.StrictError, "BOOTDIAG_ADDITIONAL_SECTOR_NOT_ORIGINAL_BLANK"):
            await bd.inspect(rom, candidate, baseline, "fixture", pins, diagnostic=True)
        rom.flash[0x2000] = 0
        with self.assertRaisesRegex(core.StrictError, "BOOTDIAG_INSTALLED_R2_DIFFERS"):
            await bd.inspect(rom, candidate, baseline, "fixture", pins, diagnostic=True)
        self.assertEqual(rom.erases, [])

    async def test_native_loader_and_bundle_reject_wrong_commit_or_protected_bytes(self):
        with self.assertRaisesRegex(core.StrictError, "BOOTDIAG_EXACT_COMMIT_REQUIRED"):
            bd.paired_images(Path("absent"), b"", None, "not-a-commit")
        for address in (0x30000, core.gate.NV5_BASE, core.gate.CCFG_START):
            data = app_data(); data[address] = 1
            with self.assertRaisesRegex(core.StrictError, "BOOTDIAG_APP_OUTSIDE_24_SECTORS"):
                bd.bundle(data, {})
        bad = core.Bundle(core.BOOTDIAG_PROFILE, "a" * 64, "b" * 64,
                          ((0, b"\xff" * 8192), (0x30000, b"\xff" * 8192)))
        with self.assertRaisesRegex(core.StrictError, "BOOTDIAG_REQUIRES_EXACT_24_APP_SECTORS"):
            core.validate_approval(bad, {}, "", "fixture")

    async def test_pinned_vendor_stock_has_both_tail_cleanup_sectors(self):
        if ARGS.vendor is None: self.skipTest("pinned vendor supplied in separate CI job")
        data, source, plan, receipt = bd.stock.extract_original(ARGS.vendor.read_bytes(), "p7u-cap192-f07")
        fallback = bd.bundle(core.gate.parse_hex(data), {"manufacturer": receipt["manufacturer_container_sha256"]})
        self.assertEqual(len(fallback.sectors), 24)
        self.assertEqual(b"".join(block for _, block in fallback.sectors)[receipt["app_payload_bytes"]:],
                         b"\xff" * (bd.END - receipt["app_payload_bytes"]))
        self.assertEqual(fallback.sectors[-1][0], 0x2E000)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--vendor", type=Path)
    ARGS, remaining = parser.parse_known_args()
    unittest.main(argv=[sys.argv[0], *remaining])
