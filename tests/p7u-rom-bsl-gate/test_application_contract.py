#!/usr/bin/env python3
"""Exercise the preserved app envelope and matching stock cleanup, no hardware."""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]/"firmware/slzb-06p7u/qualification"))
import p7u_strict_sector_writer as s
from p7u_rom_lowlevel import APP_SECTOR_ADDRESSES
from test_strict_sector_writer import FakeROM, make_bundle
APP_ERASE_END = APP_SECTOR_ADDRESSES[-1] + s.gate.SECTOR


async def main():
    assert APP_ERASE_END == 0x2E000 and len(APP_SECTOR_ADDRESSES) == 23
    _, raw, source, _ = make_bundle()
    data = s.gate.parse_hex(raw)
    for address in APP_SECTOR_ADDRESSES:
        if address:
            data[address] = 0x42
    raw = s.gate.application_only_hex(data, "p7u-cap192-f07")
    source = {**source, "derived_app_only_hex_sha256": s.sha(raw)}
    plan = s.sector.plan(raw, source)
    bundle = s.load_bundle(raw, source, plan)
    rom = FakeROM()
    outside = bytes(rom.flash[APP_ERASE_END:])
    approval = await s.preflight(rom, bundle, "COM31")
    result = await s.write_checked(rom, bundle, approval, approval["approval_digest"], "COM31")
    assert result["sectors_written"] == 23
    assert rom.erases == list(APP_SECTOR_ADDRESSES[1:])+[0]
    assert rom.flash[0x2C000] == 0x42 and bytes(rom.flash[APP_ERASE_END:]) == outside
    # A populated custom tail must be removed in its entirety by paired cleanup.
    cleanup = dict(data)
    for address in range(0x2C000, APP_ERASE_END):
        cleanup.pop(address, None)
    for address in APP_SECTOR_ADDRESSES:
        if address >= 0x2C000:
            cleanup[address] = 0xff
    rollback = s.gate.application_only_hex(cleanup, "p7u-cap192-f07")
    evidence = {**source, "derived_app_only_hex_sha256": s.sha(rollback)}
    stock = s.load_bundle(rollback, evidence, s.sector.plan(rollback, evidence))
    approval = await s.preflight(rom, stock, "COM31")
    await s.write_checked(rom, stock, approval, approval["approval_digest"], "COM31")
    assert rom.flash[0x2C000:APP_ERASE_END] == b"\xff"*(APP_ERASE_END-0x2C000)
    assert bytes(rom.flash[APP_ERASE_END:]) == outside
    # Neither a self-consistent HEX nor its digest may extend this contract.
    data[APP_ERASE_END] = 0x42
    bad = s.gate.application_only_hex(data, "p7u-cap192-f07")
    try:
        s.sector.plan(bad, {**source, "derived_app_only_hex_sha256": s.sha(bad)})
    except ValueError as exc:
        assert str(exc) == "PLAN_OUTSIDE_REVIEWED_23_SECTOR_APPLICATION_CONTRACT"
    else:
        raise AssertionError("Application boundary bypassed")
    print("P7U_APP23_AND_STOCK_TAIL_ROUNDTRIP_PASS_NO_DEVICE")


if __name__ == "__main__":
    asyncio.run(main())
