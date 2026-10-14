#!/usr/bin/env python3
"""Hosted diagnostic ONLY; never modifies or relaxes G6/G7 native acceptance."""
import argparse
import json
import re
import struct
import sys
from pathlib import Path

TI = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TI / "g3"))
sys.path.insert(0, str(TI / "g2"))
from nv5_verify_linked import load_elf as nv5_load_elf
from validate_elf_hex import read_elf as stock_read_elf, read_hex
from verify_vanilla import map_rows

def diagnose(root, profile):
    dis = (root / "DIAG-disassembly.txt").read_text(errors="replace")
    elf = (root / "DIAG-NOT-FLASHABLE.out").read_bytes()
    hexmem = read_hex((root / "DIAG-NOT-FLASHABLE.hex").read_text())
    maptext = (root / "DIAG-NOT-FLASHABLE.map").read_text(errors="replace")
    symbols = list(re.finditer(r"(?m)^\\s*([0-9a-fA-F]+)\\s+<([^>]+)>:", dis))
    caller_sites = []
    for i, match in enumerate(symbols):
        end = symbols[i+1].start() if i+1 < len(symbols) else len(dis)
        code = dis[match.end():end]
        for line in code.splitlines():
            if re.search(r"\\b(?:b(?:\\.[wn])?|bl(?:\\.w)?|blx)\\s+[^\\n]*<p7_g7_service(?:\\+0x[0-9a-f]+)?>", line):
                caller_sites.append({"caller":match.group(2), "instruction":line.strip()[:180]})
    task_functions = sorted(set(m.group(2) for m in symbols if "NPITask" in m.group(2)))
    service_functions = sorted(set(m.group(2) for m in symbols if "p7_g7" in m.group(2)))
    rows = map_rows(maptext)
    app_end = 0xa4000 if profile == "cap192" else 0xaa000
    mem, _ = nv5_load_elf(elf) if profile == "cap192" else stock_read_elf(elf)
    app = {a for a in mem if a < app_end}
    app_hex = {a for a in hexmem if a < app_end}
    flash_used = rows["FLASH"]["used"]
    return {
        "mode": "DIAGNOSTIC_ONLY_UNCHANGED_NATIVE_GATES",
        "profile": profile,
        "compiled_task_functions": task_functions,
        "compiled_g7_functions": service_functions,
        "direct_callers_of_g7_service": caller_sites,
        "disassembly_function_count": len(symbols),
        "map_FLASH_used": flash_used,
        "unique_ELF_app_programmed_bytes": len(app),
        "unique_HEX_app_programmed_bytes": len(app_hex),
        "map_minus_ELF_app_bytes": flash_used - len(app),
        "ELF_HEX_app_addresses_equal": app == app_hex,
        "ELF_HEX_app_content_equal": app == app_hex and all(mem[a] == hexmem[a] for a in app),
        "map_region_flash": rows["FLASH"],
        "flash_map_section_samples": [line.strip()[:160] for line in maptext.splitlines()
                                      if re.search(r"(?i)\\b(fill|padding|hole|noload|align)\\b", line)][:30],
    }

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--candidate", type=Path, required=True)
    p.add_argument("--profile", choices=("stock", "cap192"), required=True)
    args = p.parse_args()
    print(json.dumps(diagnose(args.candidate, args.profile), indent=2, sort_keys=True))
