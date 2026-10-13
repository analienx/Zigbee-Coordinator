#!/usr/bin/env python3
"""Export all initialized ARM ELF32 PT_LOAD bytes, including segment padding.

This producer makes no board-map or NV exceptions. Independent G2/G3 image
audits must accept its output before an artifact is published. NOLOAD memory
(p_memsz minus p_filesz) is never synthesized or exported.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path


def load_bytes(blob: bytes) -> dict[int, int]:
    if len(blob) < 52 or blob[:7] != b"\x7fELF\x01\x01\x01":
        raise ValueError("EXPECTED_ELF32_LE_V1")
    fields = struct.unpack_from("<HHIIIIIHHHHHH", blob, 16)
    etype, machine, version = fields[:3]
    phoff, ehsize, phsize, phnum = fields[4], fields[7], fields[8], fields[9]
    if (etype, machine, version, ehsize, phsize) != (2, 40, 1, 52, 32):
        raise ValueError("EXPECTED_ARM_EXECUTABLE_HEADERS")
    if not 1 <= phnum <= 64 or phoff < 52 or phoff + phsize * phnum > len(blob):
        raise ValueError("INVALID_PROGRAM_HEADER_TABLE")
    memory: dict[int, int] = {}
    for idx in range(phnum):
        typ, offset, _, address, size, memsize, _, _ = struct.unpack_from(
            "<8I", blob, phoff + idx * phsize)
        if typ != 1:
            continue
        if size > memsize or address + memsize > 0x100000000:
            raise ValueError("INVALID_LOAD_RANGE")
        if offset + size > len(blob):
            raise ValueError("TRUNCATED_LOAD_PAYLOAD")
        for delta, value in enumerate(blob[offset:offset + size]):
            target = address + delta
            if target in memory:
                raise ValueError("OVERLAPPING_INITIALIZED_LOADS")
            memory[target] = value
    if not memory:
        raise ValueError("NO_INITIALIZED_LOAD_BYTES")
    return memory


def record(kind: int, address: int, data: bytes) -> str:
    body = bytes([len(data)]) + address.to_bytes(2, "big") + bytes([kind]) + data
    return ":" + (body + bytes([(-sum(body)) & 0xff])).hex().upper()


def convert(blob: bytes) -> tuple[str, int]:
    memory = load_bytes(blob)
    addresses = sorted(memory)
    lines: list[str] = []
    pos, upper = 0, None
    while pos < len(addresses):
        start = addresses[pos]
        page = start >> 16
        if page != upper:
            lines.append(record(4, 0, page.to_bytes(2, "big")))
            upper = page
        payload = bytearray()
        while (pos < len(addresses) and len(payload) < 16 and
               addresses[pos] == start + len(payload) and
               addresses[pos] >> 16 == page):
            payload.append(memory[addresses[pos]])
            pos += 1
        lines.append(record(0, start & 0xffff, bytes(payload)))
    lines.append(record(1, 0, b""))
    return "\n".join(lines) + "\n", len(memory)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", required=True, type=Path)
    parser.add_argument("--hex", required=True, type=Path)
    args = parser.parse_args()
    source = args.elf.read_bytes()
    output, count = convert(source)
    args.hex.write_text(output, encoding="ascii")
    print(json.dumps({"producer": "ARM_ELF32_INITIALIZED_PT_LOAD_V1",
                      "elf_sha256": hashlib.sha256(source).hexdigest(),
                      "hex_sha256": hashlib.sha256(output.encode("ascii")).hexdigest(),
                      "initialized_bytes": count,
                      "noload_memory_exported": False}, sort_keys=True))
