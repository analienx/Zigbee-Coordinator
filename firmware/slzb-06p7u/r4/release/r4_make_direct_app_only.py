#!/usr/bin/env python3
"""Build a strictly APP-ONLY direct-ROM P7U R4 HEX from genuine native evidence.

The native TI HEX also embeds compiler-generated CCFG. NEVER send that full
native HEX to the flasher: it might erase/rewrite the final CCFG sector.
This offline tool extracts ONLY linked addresses 0x00000..0x2DFFF and checks
that native ELF/HEX/BIN/layout have already passed the independent audit.

No hardware access, CCFG patch, reset, programmer, credentials or flash grant.
"""
from __future__ import annotations

import argparse
import binascii
import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1] / "b0" / "tools"
sys.path.insert(0, str(HERE))
from b0_image_audit import _parse_intel_hex, audit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from r4_flash_preflight import image_check

SECTOR = 0x2000
APP_END = 0x2E000
MAX_NATIVE = 0xB0000
NAME = "R4-DIRECT-ROM-APP-ONLY-NOT-FLASH-AUTHORIZED.hex"
RECEIPT = "r4-direct-app-only-receipt.json"


def deny(reason: str):
    raise ValueError("R4_DIRECT_APP_ONLY_BLOCKED_" + reason)


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def record(kind: int, addr: int, payload: bytes) -> str:
    if not (0 <= kind <= 5 and 0 <= addr < 0x10000 and len(payload) <= 255):
        deny("INTEL_HEX_RECORD_INVALID")
    body = bytes((len(payload), addr >> 8, addr & 255, kind)) + payload
    check = (-sum(body)) & 255
    return ":" + (body + bytes((check,))).hex().upper()


def serialize_app(data: dict[int, int]) -> bytes:
    if not isinstance(data, dict) or not data:
        deny("APP_EMPTY")
    if any(type(a) is not int or type(v) is not int or not 0 <= a < APP_END
           or not 0 <= v < 256 for a,v in data.items()):
        deny("APP_ADDRESS_OUTSIDE_23_SECTORS")
    if not set(range(0, 0x3C)).issubset(data):
        deny("APP_VECTORS_INCOMPLETE")
    starts = sorted({a // SECTOR * SECTOR for a in data})
    if starts != list(range(0, APP_END, SECTOR)):
        deny("APP_NOT_EXACT_23_SECTORS")
    addresses = sorted(data)
    result = []
    last_hi = None
    i = 0
    while i < len(addresses):
        base = addresses[i]
        hi = base >> 16
        if hi != last_hi:
            result.append(record(4, 0, hi.to_bytes(2, "big")))
            last_hi = hi
        group = [data[base]]
        i += 1
        while (i < len(addresses) and len(group) < 16
               and addresses[i] == base + len(group)
               and addresses[i] >> 16 == hi):
            group.append(data[addresses[i]])
            i += 1
        result.append(record(0, base & 0xFFFF, bytes(group)))
    result.append(record(1, 0, b""))
    return ("\n".join(result) + "\n").encode("ascii")


def isolate(native: dict[int, int]) -> tuple[bytes, dict]:
    if not native or min(native) != 0 or max(native) >= MAX_NATIVE:
        deny("NATIVE_ADDRESS_UNEXPECTED")
    if not set(range(0xAFFA8, MAX_NATIVE)).issubset(native):
        deny("NATIVE_CCFG_MISSING")
    if any(0xA0000 <= a < 0xAFFA8 for a in native):
        deny("NATIVE_WRITES_NV_OR_BOOT_SECTOR")
    app = {a:v for a,v in native.items() if a < 0xA0000}
    payload = serialize_app(app)
    stack = int.from_bytes(bytes(app.get(i, 0xFF) for i in range(4)), "little")
    reset = int.from_bytes(bytes(app.get(i, 0xFF) for i in range(4, 8)), "little")
    if stack % 8 or not 0x20000000 <= stack <= 0x20024000:
        deny("INVALID_DIRECT_VECTOR_STACK")
    if not (reset & 1 and 0 < (reset & ~1) < APP_END):
        deny("INVALID_DIRECT_VECTOR_RESET")
    sector_crc = {}
    for sector in range(0, APP_END, SECTOR):
        block = bytes(app.get(i, 0xFF) for i in range(sector, sector + SECTOR))
        sector_crc[f"0x{sector:05X}"] = "%08x" % (binascii.crc32(block) & 0xFFFFFFFF)
    return payload, {
        "schema": "r4-p7u-direct-app-extraction-v1",
        "physical_vector_address": "0x00000000",
        "application_range": ["0x00000000", "0x0002E000"],
        "nv_range_excluded": ["0x000A0000", "0x000A4000"],
        "boot_and_ccfg_range_excluded": ["0x000AC000", "0x000B0000"],
        "sectors_to_program": 23,
        "sector_crc32_ff_padded": sector_crc,
        "app_hex_sha256": sha(payload),
        "native_ccfg_is_not_in_payload": True,
        "erase_nv": False,
        "erase_bootloader": False,
        "erase_ccfg": False,
        "bank_or_chip_erase": False,
        "flash_performed": False,
        "flash_authorized": False,
    }


def prepare(artifacts: Path, out: Path) -> dict:
    if out.exists() or out.is_symlink():
        deny("OUTPUT_EXISTS")
    source, ccfg = image_check(artifacts, resident_vectors=False)
    if source["expected_vector_offset"] != "0x0":
        deny("WRONG_IMAGE_VECTOR")
    if source["application_sectors"] != [hex(i) for i in range(0, APP_END, SECTOR)]:
        deny("NATIVE_23_SECTORS_MISMATCH")
    base = Path(__file__).resolve().parents[1] / "b0"
    passed, msg = audit(base, artifacts, direct_rom_boot=True)
    if passed != 0:
        deny("ELF_XML_NATIVE_AUDIT_" + re.sub(r"[^A-Z0-9]", "_", msg.upper())[:60])
    manifest = json.loads((artifacts / "manifest.json").read_text())
    name = manifest["files"]["hex"]["file"]
    native, err = _parse_intel_hex(artifacts / name)
    if err or not native:
        deny("NATIVE_HEX_INVALID")
    payload, receipt = isolate(native)
    # Independently parse the generated HEX. Every source app address must
    # roundtrip and nothing in NV/CCFG/MCUboot may be present.
    import tempfile
    with tempfile.TemporaryDirectory() as scratch:
        temporary = Path(scratch) / "app.hex"
        temporary.write_bytes(payload)
        parsed, parse_error = _parse_intel_hex(temporary)
        if parse_error or parsed != {a:v for a,v in native.items() if a < 0xA0000}:
            deny("OUTPUT_ROUNDTRIP_MISMATCH")
    receipt["source_native_hex_sha256"] = source["native_hex_sha256"]
    receipt["native_elf_xml_audit"] = "PASS"
    receipt["source_manifest_schema"] = manifest["schema"]
    receipt["output_hex"] = NAME
    out.mkdir(parents=True)
    (out / NAME).write_bytes(payload)
    (out / RECEIPT).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    return receipt


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--artifacts", type=Path, required=True)
    p.add_argument("--out-dir", type=Path, required=True)
    args = p.parse_args()
    print(json.dumps(prepare(args.artifacts, args.out_dir), sort_keys=True))


if __name__ == "__main__":
    main()
