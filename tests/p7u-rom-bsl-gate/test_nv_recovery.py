#!/usr/bin/env python3
"""Complete-byte fake-ROM NV5 backup, failure and restoration checks. No device."""
import asyncio
import argparse
import binascii
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

BASE = Path(__file__).resolve().parents[2] / "firmware/slzb-06p7u/qualification"
sys.path.insert(0, str(BASE))
import p7u_nv_recovery as n
import p7u_strict_sector_writer as s
from p7u_nv_rom_transport import NvRom
from p7u_rom_lowlevel import (RomSerial, RomWireError, APP_SECTOR_ADDRESSES,
                             SECTOR_ERASE, DOWNLOAD, SEND_DATA)


class FakeROM:
    vendor = None
    def __init__(self):
        # Nonblank, nonuniform bytes across *every* sector, including NV.
        self.flash = bytearray((i * 37 + i // 8192) % 251 for i in range(n.RADIO_BYTES))
        assert self.vendor is not None
        self.flash[:n.stock.APP_BYTES] = self.vendor[28:28 + n.stock.APP_BYTES]
        self.flash[n.stock.APP_BYTES:n.NV_START] = b"\xff" * (n.NV_START - n.stock.APP_BYTES)
        cfg = bytearray(b"\xff" * s.gate.CCFG_SIZE)
        cfg[s.gate.BL_CONFIG_OFFSET:s.gate.BL_CONFIG_OFFSET + 4] = bytes.fromhex("c50ffec5")
        cfg[s.gate.IMAGE_VALID_OFFSET:s.gate.IMAGE_VALID_OFFSET + 4] = b"\0" * 4
        self.flash[s.gate.CCFG_START:s.gate.CCFG_END] = cfg
        self.factory = b"abcdefgh"
        self.erases = []
        self.sent = 0
        self.reads = 0
        self.pending = None
        self.fail_erase = None
        self.fail_send = None
        self.fail_read = None
        self.change_ccfg = False
        self.change_other = False
        self.bad_crc = False

    async def get_chip_id(self):
        return 0xb7

    async def read_word(self, addr):
        self.reads += 1
        if self.reads == self.fail_read:
            raise RuntimeError("injected read disconnect")
        values = {s.FCFG_ICEPICK_ID: bytes((0, 0x70, 0xb7, 0x0b)),
                  s.FLASH_SIZE_REG: bytes((0x58, 0, 0, 0)), s.FCFG_PRIMARY_IEEE: self.factory}
        for start, value in values.items():
            if start <= addr <= start + len(value) - 4:
                return value[addr - start:addr - start + 4]
        return bytes(self.flash[addr:addr + 4])

    async def crc32(self, addr, length):
        return 42 if self.bad_crc else binascii.crc32(self.flash[addr:addr + length]) & 0xffffffff

    async def erase_sector(self, addr):
        assert addr in n.NV_SECTORS
        self.erases.append(addr)
        self.flash[addr:addr + n.SECTOR] = b"\xff" * n.SECTOR
        if self.change_ccfg:
            self.flash[s.gate.CCFG_START] ^= 1
        if self.change_other:
            self.flash[0x100] ^= 1
        if addr == self.fail_erase:
            return False  # May already have erased: uncertain outcome must stop.
        return True

    async def begin_download(self, addr, length):
        assert addr in n.NV_SECTORS and length == n.SECTOR
        self.pending = (addr, 0)
        return True

    async def send_data(self, data):
        self.sent += 1
        if self.sent == self.fail_send:
            return False
        addr, at = self.pending
        assert 0 < len(data) <= 252 and len(data) % 4 == 0 and at + len(data) <= n.SECTOR
        self.flash[addr + at:addr + at + len(data)] = data
        self.pending = addr, at + len(data)
        return True


async def rejected(coro, reason=None):
    try:
        await coro
    except (s.StrictError, RomWireError) as exc:
        if reason:
            assert str(exc) == reason, (str(exc), reason)
    else:
        raise AssertionError("expected rejection: " + str(reason))


def rejected_sync(call, reason=None):
    try:
        call()
    except s.StrictError as exc:
        if reason:
            assert str(exc) == reason, (str(exc), reason)
    else:
        raise AssertionError("expected offline rejection")


async def tests(vendor):
    n.stock.extract(vendor, "p7u-cap192-f07")
    FakeROM.vendor = vendor
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        original = root / "private-original"
        original.mkdir()
        rom = FakeROM()
        pristine = bytes(rom.flash)
        descriptor = n.target_descriptor(n.MODEL, "physical-rev-test", "test-host", "01:23:45:67:89:AB")
        sample = FakeROM()
        sampled = await n.probe(sample, "COM31", descriptor)
        assert sampled["page_sha256"] == s.sha(pristine[:n.SECTOR])
        assert sampled["page_crc32"] == n.crc(pristine[:n.SECTOR])
        assert sampled["scalar_read_transactions_for_page"] == 4096
        assert sample.reads == 4096 + sampled["additional_scalar_identity_reads"]
        assert sampled["page_double_read_elapsed_seconds"] > 0
        assert sampled["projected_88_sector_double_read_seconds"] == sampled["page_double_read_elapsed_seconds"] * 88
        assert sampled["projection_is_estimate_not_full_capture_measurement"] is True
        assert not sampled["write_performed"] and not sample.erases and bytes(sample.flash) == pristine
        events = []
        manifest = await n.capture(rom, original, "COM31", descriptor, event=lambda **e: events.append(e))
        assert bytes(rom.flash) == pristine and not rom.erases
        assert (original / "original.bin").read_bytes() == pristine
        assert len(manifest["sectors"]) == 88
        assert len([e for e in events if e["stage"] == "backup_sector_verified"]) == 88
        assert rom.reads >= 360448  # Honest scalar count, plus identity reads.
        assert n.verify_backup(original)[1] == pristine
        assert n.known_original_application(pristine, vendor)["original_application_rebuildable_by_pinned_app_writer"]
        badapp = bytearray(pristine)
        badapp[12] ^= 1
        rejected_sync(lambda: n.known_original_application(bytes(badapp), vendor),
                      "NV_CAPTURED_ORIGINAL_APP_NOT_PINNED_STOCK")
        badapp = bytearray(pristine)
        badapp[0x90000] = 0
        rejected_sync(lambda: n.known_original_application(bytes(badapp), vendor),
                      "NV_CAPTURED_ORIGINAL_HAS_UNRECOVERABLE_APP_GAP_DATA")
        rejected_sync(lambda: n.known_original_application(pristine, vendor[:-1]),
                      "STOCK_VENDOR_SOURCE_HASH_MISMATCH")
        duplicate = root / "independent-copy"
        shutil.copytree(original, duplicate)
        assert n.verified_pair(original, duplicate)[0] == manifest
        rejected_sync(lambda: n.verified_pair(original, original), "NV_INDEPENDENT_COPY_REQUIRED")
        alias = root / "alias-copy"
        alias.mkdir()
        os.link(original / "original.bin", alias / "original.bin")
        rejected_sync(lambda: n.verified_pair(original, alias), "NV_COPY_IS_SAME_FILE")
        cli = subprocess.run([sys.executable, str(BASE / "p7u_nv_recovery.py"),
                              "--backup-dir", str(original), "--backup-copy-dir", str(duplicate)],
                             capture_output=True, text=True)
        assert cli.returncode == 0 and json.loads(cli.stdout)["hardware_contacted"] is False
        assert not cli.stderr
        cli = subprocess.run([sys.executable, str(BASE / "p7u_nv_recovery.py"), "inspect",
                              "--backup-dir", str(original), "--device", "COM31", "--unused-p7u",
                              "--already-in-rom-bsl"], capture_output=True, text=True)
        assert cli.returncode == 2 and json.loads(cli.stdout)["error_code"] == "NV_MANAGEMENT_MAC_REQUIRED"
        assert not cli.stderr

        # An interrupted read preserves completed immutable pages and resumes
        # with fresh independent reads. A prior page must not be overwritten.
        partial = root / "partial"
        partial.mkdir()
        failed = FakeROM()
        failed.fail_read = 7000
        try:
            await n.capture(failed, partial, "COM31", descriptor)
        except RuntimeError:
            pass
        else:
            raise AssertionError("disconnect not injected")
        kept = (partial / "sector-00000.bin").read_bytes()
        assert not (partial / "manifest.json").exists() and not failed.erases
        failed.fail_read = None
        assert await n.capture(failed, partial, "COM31", descriptor, resume=True) == manifest
        assert (partial / "sector-00000.bin").read_bytes() == kept
        changed = FakeROM()
        changed.flash[0] ^= 1
        await rejected(n.capture(changed, partial, "COM31", descriptor, resume=True), "NV_CAPTURE_SECTOR_CHANGED")
        assert (partial / "original.bin").read_bytes() == pristine

        # Tampering with any raw byte, manifest or independent copy blocks
        # preparation offline, before even observing the radio.
        blob = bytearray((duplicate / "original.bin").read_bytes())
        blob[n.NV_START] ^= 1
        (duplicate / "original.bin").write_bytes(blob)
        rejected_sync(lambda: n.verified_pair(original, duplicate), "NV_BACKUP_CONTENT_OR_CAPTURE_INVALID")
        (duplicate / "original.bin").write_bytes(pristine)
        badmanifest = copy.deepcopy(manifest)
        badmanifest["sectors"][0]["sha256"] = "0" * 64
        (duplicate / "manifest.json").write_text(json.dumps(badmanifest))
        rejected_sync(lambda: n.verified_pair(original, duplicate), "NV_DOCUMENT_DIGEST_CHANGED")
        (duplicate / "manifest.json").write_text(json.dumps(manifest))

        plan = await n.inspect(rom, original, duplicate, "COM31", "prepare-nv5", vendor)
        assert [r["address"] for r in plan["sectors"]] == list(n.NV_SECTORS)
        assert len(plan["outside_nv_crc32"]) == 83
        tampered = copy.deepcopy(plan)
        tampered["sectors"][0]["address"] = n.NV_END
        await rejected(n.execute(rom, original, duplicate, "COM31", tampered, plan["digest"], n.QUIESCENT, vendor),
                       "NV_DOCUMENT_DIGEST_CHANGED")
        await rejected(n.execute(rom, original, duplicate, "COM31", plan, plan["digest"], "", vendor),
                       "NV_COUNTER_ROLLBACK_DECLARATION_REQUIRED")
        other = FakeROM()
        other.factory = b"another!"
        await rejected(n.execute(other, original, duplicate, "COM31", plan, plan["digest"], n.QUIESCENT, vendor),
                       "NV_TARGET_NOT_CAPTURED_DEVICE")
        assert not other.erases
        stale = FakeROM()
        stale.flash[n.NV_START] ^= 1
        await rejected(n.execute(stale, original, duplicate, "COM31", plan, plan["digest"], n.QUIESCENT, vendor),
                       "NV_CHANGED_SINCE_INSPECT")
        assert not stale.erases
        stale = FakeROM()
        stale.flash[0x100] ^= 1
        await rejected(n.execute(stale, original, duplicate, "COM31", plan, plan["digest"], n.QUIESCENT, vendor),
                       "NV_OUTSIDE_CHANGED_SINCE_INSPECT")
        assert not stale.erases

        result = await n.execute(rom, original, duplicate, "COM31", plan, plan["digest"], n.QUIESCENT, vendor)
        assert rom.erases == list(n.NV_SECTORS) and rom.sent == 0
        assert rom.flash[n.NV_START:n.NV_END] == b"\xff" * (5 * n.SECTOR)
        assert rom.flash[:n.NV_START] == pristine[:n.NV_START]
        assert rom.flash[n.NV_END:] == pristine[n.NV_END:]
        assert result["post_flash_radio_reset_issued"] is False
        restore = await n.inspect(rom, original, duplicate, "COM31", "restore-original-nv5", vendor)
        custom = FakeROM()
        custom.flash[0x100] ^= 1
        await rejected(n.inspect(custom, original, duplicate, "COM31", "restore-original-nv5", vendor),
                       "NV_RESTORE_REQUIRES_ORIGINAL_STOCK_APPLICATION_FIRST")
        await rejected(n.execute(custom, original, duplicate, "COM31", restore, restore["digest"], n.QUIESCENT, vendor),
                       "NV_RESTORE_REQUIRES_ORIGINAL_STOCK_APPLICATION_FIRST")
        assert not custom.erases
        await n.execute(rom, original, duplicate, "COM31", restore, restore["digest"], n.QUIESCENT, vendor)
        assert bytes(rom.flash) == pristine, "all 704KiB, including original NV, must round-trip exactly"
        assert (original / "original.bin").read_bytes() == pristine

        for failure in ("erase", "send", "read", "ccfg", "outside"):
            damaged = FakeROM()
            # Restore original pages over deliberately blank NV.
            damaged.flash[n.NV_START:n.NV_END] = b"\xff" * (5 * n.SECTOR)
            restore = await n.inspect(damaged, original, duplicate, "COM31", "restore-original-nv5", vendor)
            if failure == "erase":
                damaged.fail_erase = n.NV_SECTORS[1]
                expected = "NV_SECTOR_ERASE_FAILED"
            elif failure == "send":
                damaged.fail_send = 37
                expected = "NV_SEND_FAILED"
            elif failure == "read":
                # All initial five-page checks pass, fail on erase readback.
                damaged.fail_read = damaged.reads + 26 + 20480 + 1
                expected = None
            elif failure == "ccfg":
                damaged.change_ccfg = True
                expected = "NV_CCFG_OR_IDENTITY_CHANGED"
            else:
                damaged.change_other = True
                expected = "NV_OUTSIDE_CHANGED_DURING_WRITE"
            captured = []
            try:
                await n.execute(damaged, original, duplicate, "COM31", restore, restore["digest"],
                                n.QUIESCENT, vendor, event=lambda **e: captured.append(e))
            except (s.StrictError, RuntimeError) as exc:
                if expected:
                    assert str(exc) == expected, (failure, str(exc), expected)
            else:
                raise AssertionError("fault was ignored: " + failure)
            assert all(a in n.NV_SECTORS for a in damaged.erases)
            assert captured and captured[0]["stage"] == "nv_erase_about_to_start"
            assert (original / "original.bin").read_bytes() == pristine
            if failure != "ccfg":
                assert damaged.flash[n.NV_END:] == pristine[n.NV_END:]
            # No blind retry: get a fresh inspect/plan for the interrupted state.
            if failure in ("erase", "send", "read"):
                damaged.fail_erase = damaged.fail_send = damaged.fail_read = None
                recovery = await n.inspect(damaged, original, duplicate, "COM31", "restore-original-nv5", vendor)
                await n.execute(damaged, original, duplicate, "COM31", recovery, recovery["digest"], n.QUIESCENT, vendor)
                assert bytes(damaged.flash) == pristine

        mismatch = FakeROM()
        mismatch.bad_crc = True
        await rejected(n.checked_page(mismatch, n.NV_START), "NV_READ_ROM_CRC_MISMATCH")

        # Separate backend means neither writer silently gains the other scope.
        app = RomSerial()
        nv = NvRom()
        for addr in n.NV_SECTORS:
            await rejected(app.erase_sector(addr), "BSL_ERASE_NOT_IN_P7U_APP_ALLOWLIST")
            await rejected(app.begin_download(addr, n.SECTOR), "BSL_DOWNLOAD_PROTECTED_RANGE")
        for addr in (*APP_SECTOR_ADDRESSES, n.NV_END, n.NV_START + 4, 0xB0000):
            await rejected(nv.erase_sector(addr), "NV_ERASE_OUTSIDE_FIVE_SECTORS")
            await rejected(nv.begin_download(addr, n.SECTOR), "NV_DOWNLOAD_OUTSIDE_FIVE_SECTORS")
        for length in (4, 8191, 8193, True):
            await rejected(nv.begin_download(n.NV_START, length), "NV_DOWNLOAD_OUTSIDE_FIVE_SECTORS")
        assert nv.writer is None and app.writer is None
        wire = []
        async def call(opcode, **values):
            wire.append((opcode, values))
            return True
        nv._call = call
        for addr in n.NV_SECTORS:
            assert await nv.erase_sector(addr)
            assert await nv.begin_download(addr, n.SECTOR)
            assert await nv.send_data(b"\x12" * 252)
        assert wire == [row for addr in n.NV_SECTORS for row in (
            (SECTOR_ERASE, {"address": addr}),
            (DOWNLOAD, {"address": addr, "length": n.SECTOR}),
            (SEND_DATA, {"payload": b"\x12" * 252}))]
        print("P7U_NV5_FULL_RAW_BACKUP_AND_SAME_DEVICE_RESTORE_FAULT_TEST_PASS_NO_DEVICE")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--vendor", type=Path, required=True)
    asyncio.run(tests(parser.parse_args().vendor.read_bytes()))
