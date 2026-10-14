#!/usr/bin/env python3
"""Hosted bounded format diagnostics only. Does not accept a firmware image."""
import json
import struct
import sys
import zlib
from pathlib import Path

for name in sys.argv[1:]:
    raw = Path(name).read_bytes()
    cursor = 6 if raw.startswith(b"\x01\x03SLZB") else 4 if raw.startswith(b"SLZB") else 0
    rows = []
    while cursor and cursor + 12 <= len(raw) and len(rows) < 8:
        address, size, field = struct.unpack_from(">III", raw, cursor)
        cursor += 12
        if not size or cursor + size > len(raw):
            rows.append({"offset": cursor - 12, "address": address, "size": size, "field": f"0x{field:08x}", "bounded": False})
            break
        data = raw[cursor:cursor + size]
        crc = zlib.crc32(data) & 0xffffffff
        row = {"address": f"0x{address:x}", "size": size, "field": f"0x{field:08x}",
               "field_byte_swapped": f"0x{int.from_bytes(field.to_bytes(4,'big'),'little'):08x}",
               "crc_standard": f"0x{crc:08x}", "crc_no_final_xor": f"0x{crc ^ 0xffffffff:08x}",
               "crc_seed_ffffffff": f"0x{zlib.crc32(data,0xffffffff) & 0xffffffff:08x}"}
        if address == 0:
            row["payload_first8_hex"] = data[:8].hex()  # public vectors/header only
        rows.append(row)
        cursor += size
    print(json.dumps({"file": Path(name).name, "bytes": len(raw), "rows": rows,
                      "bytes_remaining": len(raw)-cursor, "qualification": "FORMAT_DIAGNOSTIC_ONLY"}))
