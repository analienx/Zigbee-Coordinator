#!/usr/bin/env python3
"""Read linked CAP192 capacities and recorded compiler defaults, not runtime NV.

TI's ROM model encodes zgConcentrator* initializers in compressed .cinit;
their NOLOAD RAM bytes cannot establish a runtime concentrator setting.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
from pathlib import Path
import xml.etree.ElementTree as ET

EXPECTED = {"gMAX_RTG_SRC_ENTRIES": 192, "gMAX_NEIGHBOR_ENTRIES": 64,
            "gMAX_RTG_ENTRIES": 128, "gMAX_RREQ_ENTRIES": 16,
            "gMAX_SOURCE_ROUTE": 12, "gMAX_BCAST": 9,
            "gMAX_BROADCAST_QUEUED": 10, "gNWK_MAX_BINDING_ENTRIES": 4,
            "gNWK_MAX_DATABUFS_WAITING": 8, "gNWK_MAX_DATABUFS_SCHEDULED": 5,
            "gNWK_MAX_DATABUFS_TOTAL": 12, "gNWK_INDIRECT_MSG_MAX_ALL": 9}
DEFAULTS = {"MAX_RTG_SRC_ENTRIES": 192, "MAX_NEIGHBOR_ENTRIES": 64,
            "CONCENTRATOR_ENABLE": 1,
            "CONCENTRATOR_ROUTE_CACHE": 1, "CONCENTRATOR_DISCOVERY_TIME": 60}
TABLES = {"rtgSrcTable": (192 * 8, "SOURCE_ROUTE"),
          "neighborTable": (64 * 28, "NEIGHBOR"),
          "rtgSrcRelayList": (12 * 2, "SOURCE_RELAY")}


def must(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def linked_values(blob: bytes) -> dict:
    must(len(blob) >= 52 and blob[:7] == b"\x7fELF\x01\x01\x01", "EXPECTED_ELF32_LE")
    h = struct.unpack_from("<HHIIIIIHHHHHH", blob, 16)
    must(h[:3] == (2, 40, 1) and (h[7], h[8], h[10]) == (52, 32, 40),
         "EXPECTED_ARM_EXECUTABLE_HEADERS")
    must(0 < h[9] <= 64 and 52 <= h[4] and h[4] + h[9] * 32 <= len(blob),
         "INVALID_PROGRAM_HEADER_TABLE")
    must(0 < h[11] <= 4096 and 52 <= h[5] and h[5] + h[11] * 40 <= len(blob),
         "INVALID_SECTION_HEADER_TABLE")
    loads = []
    for i in range(h[9]):
        p = struct.unpack_from("<8I", blob, h[4] + i * 32)
        if p[0] == 1:
            must(p[4] <= p[5] and p[1] + p[4] <= len(blob) and
                 p[2] + p[5] <= 2**32 and p[3] + p[5] <= 2**32,
                 "INVALID_LOAD_RANGE")
            loads.append(p)
    sections = [struct.unpack_from("<10I", blob, h[5] + i * 40)
                for i in range(h[11])]
    symbols = {}
    for section in sections:
        if section[1] != 2:  # SHT_SYMTAB, not text output from nm/map.
            continue
        must(section[9] == 16 and section[5] % 16 == 0 and
             section[4] + section[5] <= len(blob) and section[6] < len(sections),
             "INVALID_SYMBOL_TABLE")
        strings = sections[section[6]]
        must(strings[1] == 3 and strings[4] + strings[5] <= len(blob),
             "INVALID_STRING_TABLE")
        names = blob[strings[4]:strings[4] + strings[5]]
        for offset in range(section[4], section[4] + section[5], 16):
            symbol = struct.unpack_from("<IIIBBH", blob, offset)
            must(symbol[0] < len(names), "INVALID_SYMBOL_NAME")
            end = names.find(b"\0", symbol[0])
            must(end >= 0, "UNTERMINATED_SYMBOL_NAME")
            name = names[symbol[0]:end].decode("ascii", errors="replace")
            if name in EXPECTED or name in TABLES:
                must(name not in symbols, "DUPLICATE_SYMBOL_" + name)
                symbols[name] = symbol
    values = {}
    for name in (*EXPECTED, *TABLES):
        must(name in symbols, "MISSING_SYMBOL_" + name)
        _, address, size, info, _, index = symbols[name]
        must(info & 15 == 1 and 0 < index < len(sections), "INVALID_OBJECT_" + name)
        section = sections[index]
        must(section[2] & 2 and section[3] <= address and
             address + size <= section[3] + section[5], "OBJECT_OUT_OF_SECTION_" + name)
        if name in TABLES:
            expected_size, label = TABLES[name]
            must(size == expected_size, label + "_TABLE_SIZE_MISMATCH")
            must(any(p[2] <= address and address + size <= p[2] + p[5]
                     for p in loads), label + "_TABLE_NOT_ALLOCATED")
            continue
        must(size == 1 and section[1] == 1, "EXPECTED_INITIALIZED_BYTE_" + name)
        matches = [p for p in loads if p[2] <= address and address + size <= p[2] + p[4]]
        must(len(matches) == 1, "INITIALIZED_LOAD_NOT_UNIQUE_" + name)
        p = matches[0]
        offset = p[1] + address - p[2]
        must(offset == section[4] + address - section[3], "SECTION_LOAD_MISMATCH_" + name)
        value = blob[offset]
        must(value == EXPECTED[name], "CAPACITY_MISMATCH_" + name)
        values[name] = value
    return {"linked_initial_values": values,
            **{name + "_bytes": symbols[name][2] for name in TABLES}}


def compiler_defaults(projectspec: str) -> dict:
    root = ET.fromstring(projectspec)
    options = [node.attrib["compilerBuildOptions"] for node in root.iter()
               if "compilerBuildOptions" in node.attrib]
    must(len(options) == 1, "EXPECTED_ONE_COMPILER_OPTIONS_ATTRIBUTE")
    for name, value in DEFAULTS.items():
        definitions = re.findall(r"(?:^|\s)-D\s*" + re.escape(name) +
                                 r"(?:=([^\s]+))?(?=\s|$)", options[0])
        must(definitions == [str(value)], "COMPILER_DEFAULT_MISMATCH_" + name)
        must(not re.search(r"(?:^|\s)-U\s*" + re.escape(name) + r"(?=\s|$)", options[0]),
             "COMPILER_DEFAULT_UNDEFINED_" + name)
    return dict(DEFAULTS)


def verify(elf: bytes, projectspec: bytes) -> dict:
    result = linked_values(elf)
    result.update({"status": "CAP192_LINKED_CAPACITY_PASS",
                   "compiler_defaults": compiler_defaults(projectspec.decode("utf-8")),
                   "concentrator_runtime_verified": False,
                   "network_behavior_verified": False,
                   "source_only_constants": {"NWK_MAX_DATABUFS_CONFIRMED": 5},
                   "source_only_note": "Pinned source default; not required as a linked object because the TI linker discards the unused constant",
                   "compiler_defaults_source": "recorded projectspec; not decoded .cinit or NV",
                   "elf_sha256": hashlib.sha256(elf).hexdigest(),
                   "projectspec_sha256": hashlib.sha256(projectspec).hexdigest()})
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--projectspec", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    report = verify(args.elf.read_bytes(), args.projectspec.read_bytes())
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
