#!/usr/bin/env python3
"""Package a CC2674P10 Intel HEX into the reviewed SMLIGHT two-segment container.

This is a pure byte-preserving transform. It accepts only:
- application bytes below the fixed P10 NV region (0x000FD800), and
- the complete 0x7c-byte CCFG segment at 0x50000000.

It never emits NV bytes. Gaps inside the application span are padded with 0xff.
"""
from __future__ import annotations

import argparse
import binascii
import hashlib
import json
from pathlib import Path
import struct

NV_BASE = 0x000FD800
CCFG_BASE = 0x50000000
CCFG_SIZE = 0x7C


def ihex(raw: bytes) -> dict[int, int]:
    memory: dict[int, int] = {}
    upper = 0
    ended = False
    for line in raw.decode("ascii").splitlines():
        if not line.strip():
            continue
        if ended or not line.startswith(":"):
            raise ValueError("invalid HEX framing")
        row = bytes.fromhex(line[1:])
        if len(row) < 5 or len(row) != row[0] + 5 or sum(row) & 0xFF:
            raise ValueError("invalid HEX checksum/length")
        count = row[0]
        address = int.from_bytes(row[1:3], "big")
        kind = row[3]
        data = row[4:-1]
        if kind == 0:
            for index, value in enumerate(data):
                target = upper + address + index
                if target in memory:
                    raise ValueError("overlapping HEX records")
                memory[target] = value
        elif kind == 1 and count == 0 and address == 0:
            ended = True
        elif kind == 4 and count == 2 and address == 0:
            upper = int.from_bytes(data, "big") << 16
        elif kind == 2 and count == 2 and address == 0:
            upper = int.from_bytes(data, "big") << 4
        elif kind in (3, 5) and count == 4 and address == 0:
            pass
        else:
            raise ValueError("unsupported HEX record")
    if not ended or not memory:
        raise ValueError("incomplete HEX")
    return memory


def slzb(raw: bytes) -> tuple[dict[int, int], list[dict[str, object]]]:
    if raw[:4] != b"SLZB" or len(raw) < 28:
        raise ValueError("unsupported SLZB container")
    memory: dict[int, int] = {}
    cursor = 28
    descriptors: list[dict[str, object]] = []
    for offset in (4, 16):
        address, size, crc = struct.unpack(">III", raw[offset:offset + 12])
        segment = raw[cursor:cursor + size]
        if len(segment) != size:
            raise ValueError("SLZB segment extent mismatch")
        if binascii.crc32(segment) & 0xFFFFFFFF != crc:
            raise ValueError("SLZB segment CRC mismatch")
        for index, value in enumerate(segment):
            target = address + index
            if target in memory:
                raise ValueError("SLZB segment overlap")
            memory[target] = value
        descriptors.append({
            "address": f"0x{address:08x}",
            "size": size,
            "crc32": f"0x{crc:08x}",
        })
        cursor += size
    if cursor != len(raw):
        raise ValueError("trailing SLZB bytes")
    if [x["address"] for x in descriptors] != ["0x00000000", "0x50000000"]:
        raise ValueError("unexpected SLZB segment geometry")
    return memory, descriptors


def management_container(memory: dict[int, int]) -> tuple[bytes, list[dict[str, object]], int]:
    app = {a: v for a, v in memory.items() if 0 <= a < NV_BASE}
    cfg = {a: v for a, v in memory.items() if CCFG_BASE <= a < CCFG_BASE + CCFG_SIZE}
    expected_cfg = set(range(CCFG_BASE, CCFG_BASE + CCFG_SIZE))

    if not app or min(app) != 0:
        raise ValueError("application must start at address zero")
    if set(cfg) != expected_cfg:
        raise ValueError("complete CCFG segment required")
    if len(app) + len(cfg) != len(memory):
        raise ValueError("unsupported address or NV record in source image")

    app_bytes = bytes(app.get(address, 0xFF) for address in range(max(app) + 1))
    cfg_bytes = bytes(cfg[address] for address in range(CCFG_BASE, CCFG_BASE + CCFG_SIZE))
    segments = ((0, app_bytes), (CCFG_BASE, cfg_bytes))
    payload = (
        b"SLZB"
        + b"".join(
            struct.pack(">III", address, len(data), binascii.crc32(data) & 0xFFFFFFFF)
            for address, data in segments
        )
        + app_bytes
        + cfg_bytes
    )

    unpacked, descriptors = slzb(payload)
    if any(unpacked[address] != value for address, value in memory.items()):
        raise ValueError("container changed an addressed source byte")
    padding = set(unpacked) - set(memory)
    if any(address >= NV_BASE or unpacked[address] != 0xFF for address in padding):
        raise ValueError("unsafe container padding")
    return payload, descriptors, len(padding)


def package(hex_path: Path, output_path: Path, manifest_path: Path | None = None) -> dict[str, object]:
    raw = hex_path.read_bytes()
    memory = ihex(raw)
    payload, segments, padding = management_container(memory)
    output_path.write_bytes(payload)
    evidence: dict[str, object] = {
        "source_hex": hex_path.name,
        "source_hex_sha256": hashlib.sha256(raw).hexdigest(),
        "upload_file": output_path.name,
        "upload_sha256": hashlib.sha256(payload).hexdigest(),
        "upload_bytes": len(payload),
        "format": "SLZB / two big-endian address-length-CRC32 descriptors",
        "segments": segments,
        "addressed_bytes_equal": True,
        "added_erased_padding_bytes": padding,
        "nv_programmed_bytes": sum(NV_BASE <= address < 0x00100000 for address in memory),
    }
    if evidence["nv_programmed_bytes"] != 0:
        raise ValueError("source image contains NV bytes")
    if manifest_path is not None:
        manifest_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hex", dest="hex_path", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    print(json.dumps(package(args.hex_path, args.output, args.manifest), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
