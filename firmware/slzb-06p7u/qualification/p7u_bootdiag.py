#!/usr/bin/env python3
"""Temporary diagnostic artifact loader and exactly-24-sector app adapter.

Normal R2/RC packages retain their 23-sector contract. This separate profile
admits one additional application sector only with a paired stock cleanup.
Never resets, initializes NV, or writes NV/CCFG. No bank-erase implementation.
"""
from __future__ import annotations
import binascii
import re
from pathlib import Path
import sys

import p7u_strict_sector_writer as core
import p7u_stock_rollback as stock
from p7u_rom_lowlevel import RomSerial, RomWireError, SECTOR_ERASE, DOWNLOAD

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "slzb-06p7/ti832/g6"))
from elf_load_hex import load_bytes

END = 0x30000


def bundle(data, evidence):
    core.check(data and min(data) == 0 and max(data) < END and
               all(a in data for a in range(8)), "BOOTDIAG_APP_OUTSIDE_24_SECTORS")
    application = core.gate.application_only_hex(data, "p7u-cap192-f07")
    sectors = []
    for addr in core.BOOTDIAG_SECTOR_ADDRESSES:
        sectors.append((addr, bytes(data.get(i, 0xff) for i in range(addr, addr + core.gate.SECTOR))))
    plan = {"schema": "p7u-temporary-bootdiag24-plan-v1", "application_end": END,
            "sector_addresses": list(core.BOOTDIAG_SECTOR_ADDRESSES),
            "app_hex_sha256": core.sha(application), "evidence": evidence,
            "temporary_instrumentation": True, "flash_authorized": False}
    return core.Bundle(core.BOOTDIAG_PROFILE, core.sha(application),
                       core.sha(core.canonical(plan)), tuple(sectors))


def paired_images(native: Path, vendor: bytes, baseline: core.Bundle, expected_commit: str):
    core.check(re.fullmatch(r"[0-9a-f]{40}", expected_commit) is not None,
               "BOOTDIAG_EXACT_COMMIT_REQUIRED")
    core.check((native / "candidate-sha.txt").read_text().strip() == expected_commit,
               "BOOTDIAG_NATIVE_COMMIT_MISMATCH")
    report = core.load_json(native / "BOOTDIAG-LINKED.json")
    full = (native / "DIAG-NOT-FLASHABLE.hex").read_bytes()
    memory = core.gate.parse_hex(full)
    elf = (native / "DIAG-NOT-FLASHABLE.out").read_bytes()
    core.check(memory == load_bytes(elf), "BOOTDIAG_HEX_NOT_EXACT_NATIVE_ELF")
    audit = core.gate.candidate_audit(memory, "p7u-cap192-f07")
    application = core.gate.application_only_hex(memory, "p7u-cap192-f07")
    core.check(report.get("schema") == "p7u-temporary-bootdiag-linked-v1"
               and report.get("bootdiag_full_hex_sha256") == core.sha(full)
               and report.get("bootdiag_app_hex_sha256") == core.sha(application)
               and report.get("stack_bytes") == 4096
               and report.get("required_application_sectors") in (23, 24)
               and report.get("release_candidate") is False
               and report.get("flash_authorized") is False, "BOOTDIAG_NATIVE_REPORT_MISMATCH")
    core.check(baseline.hex_sha256 ==
               "16837972afeb3a502e03505e2998c5d2b2b8a1ce61ce91450f5999e175e908de",
               "BOOTDIAG_NOT_BASED_ON_INSTALLED_R2")
    app = {a: b for a, b in memory.items() if a < core.gate.NV5_BASE}
    candidate = bundle(app, {"native_commit": expected_commit, "full_hex_sha256": core.sha(full),
                             "elf_sha256": core.sha(elf), "ccfg_sha256": audit["ccfg_sha256"]})
    # Re-derive original stock from the separately hash-pinned vendor container.
    # Every byte after its actual app, including both tail sectors, is FF.
    image, _source, _plan, receipt = stock.extract_original(vendor, "p7u-cap192-f07")
    original = core.gate.parse_hex(image)
    fallback = bundle(original, {"manufacturer_sha256": receipt["manufacturer_container_sha256"],
                                 "cleanup_end": END})
    core.check(candidate.sectors[-1][0] == fallback.sectors[-1][0] == 0x2E000
               and fallback.sectors[-1][1] == b"\xff" * core.gate.SECTOR
               and fallback.sectors[-2][1] == b"\xff" * core.gate.SECTOR,
               "BOOTDIAG_STOCK_CLEANUP_NOT_PAIRED_24_SECTORS")
    return candidate, fallback


class BootdiagRom(RomSerial):
    """A separate exact 24-sector adapter; default RomSerial remains 23 only."""
    async def erase_sector(self, addr):
        self._download_remaining = 0
        if type(addr) is not int or addr not in core.BOOTDIAG_SECTOR_ADDRESSES:
            raise RomWireError("BOOTDIAG_ERASE_OUTSIDE_24_APP_SECTORS")
        return bool(await self._call(SECTOR_ERASE, address=addr))

    async def begin_download(self, addr, length):
        self._download_remaining = 0
        if (type(addr) is not int or addr not in core.BOOTDIAG_SECTOR_ADDRESSES
                or type(length) is not int or length != core.gate.SECTOR):
            raise RomWireError("BOOTDIAG_DOWNLOAD_OUTSIDE_24_APP_SECTORS")
        ok = bool(await self._call(DOWNLOAD, address=addr, length=length))
        if ok: self._download_remaining = length
        return ok


class Session:
    def __init__(self, device):
        core.check(re.fullmatch(r"COM[0-9]+|/dev/tty(?:ACM|USB|S)[0-9]+", device) is not None,
                   "BOOTDIAG_ALREADY_IN_BSL_USB_REQUIRED")
        self.device, self.rom = device, None

    async def __aenter__(self):
        self.rom = BootdiagRom()
        try:
            await self.rom.open(self.device, 115200)
            core.check(await self.rom.synchronize() is True, "BOOTDIAG_ROM_SYNC_FAILED")
        except BaseException:
            await self.rom.close()
            raise
        return self.rom

    async def __aexit__(self, *exc):
        await self.rom.close()
        return False


async def nv_crcs(rom):
    rows = []
    for addr in range(core.gate.NV5_BASE, core.gate.CCFG_SECTOR, core.gate.SECTOR):
        value = await rom.crc32(addr, core.gate.SECTOR)
        core.check(type(value) is int and 0 <= value <= 0xffffffff, "BOOTDIAG_NV_CRC_INVALID")
        rows.append({"address": addr, "crc32": f"{value:08x}"})
    return rows


async def inspect(rom, selected, baseline, endpoint, pins, *, diagnostic):
    result = await core.preflight(rom, selected, endpoint)
    for key in ("factory_id_digest", "ccfg_sha256"):
        core.check(result["identity"].get(key) == pins.get("radio_" + key),
                   "BOOTDIAG_NOT_ORIGINAL_CAPTURED_RADIO")
    if diagnostic:
        core.check(await core.read_exact(rom, 0, 8) == baseline.sectors[0][1][:8],
                   "BOOTDIAG_INSTALLED_VECTOR_DIFFERS")
        for (addr, data), row in zip(baseline.sectors, result["sectors"]):
            core.check(row["address"] == f"0x{addr:05X}" and row["before_crc32"] ==
                       f"{binascii.crc32(data) & 0xffffffff:08x}",
                       "BOOTDIAG_INSTALLED_R2_DIFFERS_PRESERVE_AND_INVESTIGATE")
        core.check(result["sectors"][-1]["before_crc32"] ==
                   f"{binascii.crc32(bytes([255]) * core.gate.SECTOR) & 0xffffffff:08x}",
                   "BOOTDIAG_ADDITIONAL_SECTOR_NOT_ORIGINAL_BLANK")
    result.pop("approval_digest")
    result.update(nv5_before_crc32=await nv_crcs(rom),
                  baseline_app_sha256=baseline.hex_sha256, temporary_diagnostic_profile=True,
                  selected_image="diagnostic" if diagnostic else "original_stock_24_sector_cleanup")
    result["approval_digest"] = core.sha(core.canonical(result))
    return result


async def execute(rom, selected, baseline, endpoint, pins, plan, digest, *, diagnostic):
    core.validate_approval(selected, plan, digest, endpoint)
    core.check(plan.get("baseline_app_sha256") == baseline.hex_sha256
               and plan.get("temporary_diagnostic_profile") is True
               and plan.get("selected_image") == ("diagnostic" if diagnostic else "original_stock_24_sector_cleanup"),
               "BOOTDIAG_PLAN_IMAGE_MISMATCH")
    for key in ("factory_id_digest", "ccfg_sha256"):
        core.check(plan["identity"].get(key) == pins.get("radio_" + key),
                   "BOOTDIAG_PLAN_NOT_ORIGINAL_CAPTURED_RADIO")
    core.check(await nv_crcs(rom) == plan["nv5_before_crc32"], "BOOTDIAG_NV_CHANGED_SINCE_INSPECT")
    result = await core.write_checked(rom, selected, plan, digest, endpoint)
    core.check(await nv_crcs(rom) == plan["nv5_before_crc32"], "BOOTDIAG_NV_CHANGED_DURING_APP_WRITE")
    return {**result, "application_sectors": 24, "application_end": END,
            "nv5_unchanged": True, "temporary_diagnostic_profile": True,
            "release_candidate": False}
