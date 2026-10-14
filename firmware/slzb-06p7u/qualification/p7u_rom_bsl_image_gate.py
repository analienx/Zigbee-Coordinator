#!/usr/bin/env python3
"""Read-only CC2652P7U HEX / ROM BSL / protected-sector preflight.

Never invokes a flasher. This checks only source-image geometry and CCFG.
It deliberately NEVER grants permission to erase or program the target.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

RADIO_SIZE = 0xB0000
SECTOR = 0x2000
CCFG_SECTOR = 0xAE000
CCFG_START = 0xAFFA8
CCFG_SIZE = 88
CCFG_END = CCFG_START + CCFG_SIZE
NV2_BASE = 0xAA000
NV5_BASE = 0xA4000
VENDOR_CCFG_SHA256 = "1defedbd2f474ee8b7385476801a63de95f55c3dd51115e29f97c69196049af7"
BL_CONFIG_OFFSET = 0x30  # CCFG 0xFD8 - 0xFA8, pinned CC13x2x7 TI register layout
ERASE_CONF_OFFSET = 0x34
IMAGE_VALID_OFFSET = 0x44
MAX_HEX_SIZE = 12 * 1024 * 1024

class PreflightError(ValueError):
    """Bounded reject code, never includes sensitive bytes or original paths."""

def require(test: bool, code: str) -> None:
    if not test:
        raise PreflightError(code)

def parse_hex(raw: bytes) -> dict[int, int]:
    require(len(raw) <= MAX_HEX_SIZE, "HEX_TOO_LARGE")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise PreflightError("HEX_NON_ASCII") from exc
    require(bool(lines), "HEX_EMPTY")
    data: dict[int, int] = {}
    base = 0
    eof = False
    for line in lines:
        require(bool(line) and line.startswith(":"), "HEX_BAD_RECORD")
        require(not eof, "HEX_AFTER_EOF")
        try:
            record = bytes.fromhex(line[1:])
        except ValueError as exc:
            raise PreflightError("HEX_BAD_HEX") from exc
        require(len(record) >= 5, "HEX_RECORD_SHORT")
        size = record[0]
        require(len(record) == size + 5, "HEX_RECORD_LENGTH")
        require((sum(record) & 255) == 0, "HEX_CHECKSUM")
        offset = (record[1] << 8) | record[2]
        kind = record[3]
        payload = record[4:-1]
        if kind == 0x00:
            require(offset + size <= 0x10000, "HEX_RECORD_CROSSES_WINDOW")
            at = base + offset
            require(at + size <= RADIO_SIZE, "HEX_OUT_OF_RADIO_FLASH")
            for i, b in enumerate(payload):
                address = at + i
                require(address not in data, "HEX_DUPLICATE_BYTE")
                data[address] = b
        elif kind == 0x01:
            require(size == 0 and offset == 0, "HEX_BAD_EOF")
            eof = True
        elif kind == 0x04:
            require(size == 2 and offset == 0, "HEX_BAD_ELA")
            base = int.from_bytes(payload, "big") << 16
        elif kind == 0x02:
            # Standard Intel HEX legacy segment-base addressing.
            require(size == 2 and offset == 0, "HEX_BAD_SEGMENT_BASE")
            base = int.from_bytes(payload, "big") << 4
        elif kind in (0x03, 0x05):
            # Entry-point metadata is not accepted: ROM uses CCFG vector authority.
            raise PreflightError("HEX_ENTRY_POINT_UNSUPPORTED")
        else:
            raise PreflightError("HEX_UNSUPPORTED_RECORD_TYPE")
    require(eof, "HEX_NO_EOF")
    require(bool(data), "HEX_NO_IMAGE_BYTES")
    return data

def candidate_audit(data: dict[int, int], profile: str,
                    expected_ccfg_digest: str = VENDOR_CCFG_SHA256,
                    installed_ccfg: bytes | None = None) -> dict:
    require(profile in ("p7u-f07-stock", "p7u-cap192-f07"), "P7U_PROFILE_MISMATCH")
    require(bool(data), "EMPTY_IMAGE")
    limit = NV2_BASE if profile == "p7u-f07-stock" else NV5_BASE
    region = sorted(data)
    require(all(addr < limit or CCFG_START <= addr < CCFG_END for addr in region),
            "IMAGE_WRITES_NV_OR_PROTECTED_FLASH")
    require(all(i in data for i in range(CCFG_START, CCFG_END)),
            "IMAGE_MISSING_EXACT_CCFG")
    ccfg = bytes(data[i] for i in range(CCFG_START, CCFG_END))
    require(hashlib.sha256(ccfg).hexdigest() == expected_ccfg_digest,
            "IMAGE_CCFG_VENDOR_HASH_MISMATCH")
    bl = struct.unpack_from("<I", ccfg, BL_CONFIG_OFFSET)[0]
    erase = struct.unpack_from("<I", ccfg, ERASE_CONF_OFFSET)[0]
    vector_base = struct.unpack_from("<I", ccfg, IMAGE_VALID_OFFSET)[0]
    require((bl & 0xFF) == 0xC5 and ((bl >> 24) & 0xFF) == 0xC5,
            "ROM_BOOTLOADER_DISABLED")
    require(((bl >> 8) & 0xFF) == 15 and not ((bl >> 16) & 1),
            "ROM_BACKDOOR_WRONG_DIO_OR_POLARITY")
    require((erase & 1) == 1, "ROM_BANK_ERASE_DISABLED")
    require(vector_base < limit and vector_base % 4 == 0, "ROM_VECTOR_OUTSIDE_APP")
    require(all((vector_base + i) in data for i in range(8)),
            "IMAGE_VECTOR_NOT_LOADED")
    sp = int.from_bytes(bytes(data[vector_base + i] for i in range(4)), "little")
    reset = int.from_bytes(bytes(data[vector_base + 4 + i] for i in range(4)), "little")
    require(0x20000000 <= sp < 0x20080000 and sp % 8 == 0,
            "IMAGE_INITIAL_STACK_UNPLAUSIBLE")
    require((reset & 1) == 1 and (reset & ~1) < limit,
            "IMAGE_RESET_HANDLER_OUTSIDE_APP")
    require(sum(addr < limit for addr in region) > 1024, "IMAGE_APP_TOO_SMALL")
    require(sum(CCFG_SECTOR <= addr < CCFG_START for addr in region) == 0,
            "IMAGE_TOUCHES_UNKNOWN_CCFG_SECTOR")
    if installed_ccfg is not None:
        require(len(installed_ccfg) == CCFG_SIZE, "INSTALLED_CCFG_BAD_LENGTH")
        # Prevent overwriting unknown per-device CCFG/IEEE words under a
        # misleading presumption that vendor sample CCFG == actual installed.
        require(installed_ccfg == ccfg, "INSTALLED_CCFG_DIFFERS_STOP")
    touched = sorted({addr // SECTOR * SECTOR for addr in region})
    require(CCFG_SECTOR in touched, "IMAGE_CCFG_SECTOR_MISSING")
    require(not any(NV5_BASE <= x < CCFG_SECTOR for x in touched),
            "IMAGE_ERASE_TOUCHES_NV")
    return {
        "target": "SLZB-06P7U_CC2652P7_RADIO_ONLY",
        "profile": profile,
        "source_image_sha256": hashlib.sha256(bytes(data[a] for a in region)).hexdigest(),
        "loaded_byte_count": len(region),
        "loaded_app_byte_count": sum(x < limit for x in region),
        "ccfg_sha256": hashlib.sha256(ccfg).hexdigest(),
        "ccfg_88_bytes_exact_vendor": True,
        "bootloader_enabled": True,
        "rom_backdoor_enabled": True,
        "backdoor_ti_dio": 15,
        "backdoor_active_low": True,
        "bank_erase_command_enabled": True,
        "nv_loaded_bytes": 0,
        "nv2_nv5_overlap": True,
        "ccfg_sector_touched": True,
        "CCFG_SECTOR_READBACK_AND_ROLLBACK_REQUIRED": True,
        "sectors_that_would_be_touched": len(touched),
        "flasher_erase_policy_verified": False,
        "target_bsl_entry_verified": False,
        "esp_slzb_os_unmodified_by_this_tool": True,
        "rollback_with_vendor_image_verified": False,
        "flash_authorized": False,
        "no_write_operations": True,
    }

def application_only_hex(data: dict[int, int], profile: str) -> bytes:
    """Generate a valid Intel HEX without *any* CCFG or NV bytes.

    An app-only source image is NOT SAFE to flash with a whole-bank-erase tool.
    It is for controlled sector-aware recovery evaluation only.
    """
    limit = NV2_BASE if profile == "p7u-f07-stock" else NV5_BASE
    require(profile in ("p7u-f07-stock", "p7u-cap192-f07"), "P7U_PROFILE_MISMATCH")
    addresses = sorted(x for x in data if x < limit)
    require(bool(addresses), "IMAGE_APP_TOO_SMALL")
    def emit(address: int, kind: int, payload: bytes = b"") -> str:
        header = bytes((len(payload), (address >> 8) & 255,
                        address & 255, kind))
        content = header + payload
        return ":" + (content + bytes((-sum(content) & 255,))).hex().upper()
    lines: list[str] = []
    upper = -1
    pos = 0
    while pos < len(addresses):
        start = addresses[pos]
        hi = start >> 16
        if hi != upper:
            lines.append(emit(0, 4, hi.to_bytes(2, "big")))
            upper = hi
        chunk = [start]
        pos += 1
        while (pos < len(addresses) and
               addresses[pos] == chunk[-1] + 1 and
               len(chunk) < 16 and addresses[pos] >> 16 == upper):
            chunk.append(addresses[pos])
            pos += 1
        lines.append(emit(start & 65535, 0, bytes(data[x] for x in chunk)))
    lines.append(emit(0, 1))
    result = ("\\n".join(lines) + "\\n").encode("ascii")
    # Double-parse our own output before publishing any derived bytes.
    roundtrip = parse_hex(result)
    require(roundtrip == {a:data[a] for a in addresses},
            "APP_ONLY_ROUNDTRIP_CHANGED_BYTES")
    require(max(roundtrip) < limit, "APP_ONLY_CROSSES_NV")
    return result


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--hex", required=True, type=Path)
    p.add_argument("--profile", required=True, choices=["p7u-f07-stock","p7u-cap192-f07"])
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--installed-ccfg", type=Path, help="Optional private read-only 88-byte device snapshot")
    p.add_argument("--app-only-out", type=Path, help="Optional derived CCFG-free HEX, NOT FLASHABLE without approved sector-aware backend")
    a = p.parse_args()
    try:
        audit = candidate_audit(
            parse_hex(a.hex.read_bytes()), a.profile,
            installed_ccfg=a.installed_ccfg.read_bytes() if a.installed_ccfg else None)
        if a.app_only_out:
            application = application_only_hex(parse_hex(a.hex.read_bytes()), a.profile)
            a.app_only_out.parent.mkdir(parents=True, exist_ok=True)
            a.app_only_out.write_bytes(application)
            audit["derived_app_only_hex_sha256"] = hashlib.sha256(application).hexdigest()
            audit["derived_app_only_never_flash_with_bank_erase"] = True
        status = "SOURCE_HEX_BSL_GEOMETRY_PASS_NOT_FLASHABLE"
    except (PreflightError, OSError) as exc:
        reason = str(exc) if isinstance(exc, PreflightError) else "INPUT_UNREADABLE"
        audit = {"flash_authorized": False, "no_write_operations": True,
                 "qualification": "REJECT", "reason": reason}
        status = "FAIL_CLOSED"
    audit["qualification"] = audit.get("qualification", status)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(audit, indent=2, sort_keys=True) + "\n", encoding="utf8")
    print(json.dumps(audit, sort_keys=True))
    if status == "FAIL_CLOSED":
        raise SystemExit(2)

if __name__ == "__main__":
    main()
