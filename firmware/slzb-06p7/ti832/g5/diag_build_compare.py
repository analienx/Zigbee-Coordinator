#!/usr/bin/env python3
"""Compare pinned P7 BASE vs DIAG CCS linker maps + symbol evidence.

Linked evidence only: proves the DIAG ELF contains the flight-recorder
symbols and reports text/data/bss + FLASH/SRAM/stack deltas from the
two linker maps. It proves nothing about runtime behaviour, stack
high-water, or hardware. NOT_FLASHABLE for both builds.
"""
from __future__ import annotations
import argparse, hashlib, json, re
from pathlib import Path

DIAG_SYMBOLS = ["p7_diag_record", "p7_diag_record_isr", "p7_diag_seal_retained",
                "p7_diag_init", "p7_diag_snapshot", "p7_diag_state", "p7_diag_ring"]

def must(v: bool, m: str) -> None:
    if not v: raise ValueError(m)

def parse_map(text: str) -> dict:
    regions = {}
    in_mem = False
    for line in text.splitlines():
        if "MEMORY CONFIGURATION" in line: in_mem = True; continue
        if in_mem:
            m = re.match(r"\s*(FLASH|FLASH_NV|FLASH_LAST|SRAM|GPRAM)\s+([0-9A-Fa-f]{8})\s+([0-9A-Fa-f]{8})\s+([0-9A-Fa-f]{8})\s+([0-9A-Fa-f]{8})", line)
            if m:
                regions[m.group(1).lower() + "_used"] = int(m.group(4), 16)
                regions[m.group(1).lower() + "_size"] = int(m.group(3), 16)
            elif regions and "SECTION ALLOCATION" in line: break
    must("flash_used" in regions and "sram_used" in regions, "MAP_REGIONS_MISSING")
    sections = {}
    for name in (".text", ".data", ".bss", ".stack"):
        m = re.search(r"(?m)^" + re.escape(name) + r"\s+0\s+([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)\s", text)
        if m: sections[name[1:]] = int(m.group(2), 16)
    stack = None
    m = re.search(r"(?m)^\s*[0-9A-Fa-f]{8}\s+__STACK_SIZE\s*$", text)
    sm = re.search(r"(?m)^\s*([0-9A-Fa-f]{8})\s+__STACK_SIZE\s*$", text)
    if sm: stack = int(sm.group(1), 16)
    return {"regions": regions, "sections": sections, "stack_reserved_bytes": stack}

def symbols(text: str) -> set[str]:
    out = set()
    for line in text.splitlines():
        parts = line.split()
        if parts: out.add(parts[-1])
    return out

def compare(base_map: str, diag_map: str, base_syms: str, diag_syms: str,
            base_elf_size: int, diag_elf_size: int) -> dict:
    b, d = parse_map(base_map), parse_map(diag_map)
    bs, ds = symbols(base_syms), symbols(diag_syms)
    for s in DIAG_SYMBOLS:
        must(s in ds, "DIAG_SYMBOL_MISSING_" + s)
        must(s not in bs, "BASE_SYMBOL_PRESENT_" + s)
    delta = {}
    for k in sorted(set(b["regions"]) | set(d["regions"])):
        if k in b["regions"] and k in d["regions"]: delta[k] = d["regions"][k] - b["regions"][k]
    for k in sorted(set(b["sections"]) | set(d["sections"])):
        if k in b["sections"] and k in d["sections"]: delta[k] = d["sections"][k] - b["sections"][k]
    return {"qualification": "G5_BASE_VS_DIAG_LINKED_EVIDENCE_NOT_FLASHABLE",
      "runtime_qualified": False, "hardware_qualified": False, "flash_authorized": False,
      "base": b, "diag": d, "delta_diag_minus_base": delta,
      "elf_size_bytes": {"base": base_elf_size, "diag": diag_elf_size,
                         "delta": diag_elf_size - base_elf_size},
      "diag_symbols_present": [s for s in DIAG_SYMBOLS if s in ds],
      "base_symbols_absent": [s for s in DIAG_SYMBOLS if s not in bs]}

def selftest() -> None:
    def fixture(flash, sram, text):
        return ("MEMORY CONFIGURATION\n"
          f" FLASH              00000000 000AA000 {flash:08X} 00000000\n"
          f" SRAM               20000000 00024000 {sram:08X} 00000000\n"
          "SECTION ALLOCATION MAP\n"
          f".text           0    00000000    {text:08X}     r-x\n"
          ".data           0    20000000    00000100     rw-\n"
          ".bss            0    20000100    00000200     rw-\n"
          "GLOBAL SYMBOLS: SORTED ALPHABETICALLY BY Name\n20024000  __STACK_TOP\n00000400  __STACK_SIZE\n")
    base = fixture(1000, 2000, 900)
    diag = fixture(1400, 2900, 1250)
    bs = "00000000 main\n"; ds = "\n".join(f"20000000 {s}" for s in DIAG_SYMBOLS) + "\n"
    r = compare(base, diag, bs, ds, 10000, 11000)
    must(r["delta_diag_minus_base"]["flash_used"] == 400, "FLASH_DELTA")
    must(r["delta_diag_minus_base"]["text"] == 350, "TEXT_DELTA")
    must(r["elf_size_bytes"]["delta"] == 1000, "ELF_DELTA")
    negatives = [
        lambda: compare(base, diag, bs, ds.replace("p7_diag_record\n", ""), 1, 1),
        lambda: compare(base, diag, ds, ds, 1, 1),  # symbols leaked into BASE
        lambda: compare("no regions", diag, bs, ds, 1, 1),
    ]
    for fn in negatives:
        try: fn()
        except ValueError: continue
        raise AssertionError("COMPARE_NEGATIVE_ACCEPTED")
    print("PASS P7 G5 BASE-vs-DIAG compare; linked evidence only")

def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--base-map", type=Path); p.add_argument("--diag-map", type=Path)
    p.add_argument("--base-symbols", type=Path); p.add_argument("--diag-symbols", type=Path)
    p.add_argument("--base-elf", type=Path); p.add_argument("--diag-elf", type=Path)
    p.add_argument("--out", type=Path); p.add_argument("--selftest", action="store_true")
    a = p.parse_args()
    if a.selftest: selftest()
    if a.base_map:
        must(all([a.diag_map, a.base_symbols, a.diag_symbols, a.base_elf, a.diag_elf, a.out]), "REQUIRE_ALL_INPUTS")
        r = compare(a.base_map.read_text(errors="replace"), a.diag_map.read_text(errors="replace"),
                    a.base_symbols.read_text(errors="replace"), a.diag_symbols.read_text(errors="replace"),
                    a.base_elf.stat().st_size, a.diag_elf.stat().st_size)
        r["map_sha256"] = {"base": hashlib.sha256(a.base_map.read_bytes()).hexdigest(),
                           "diag": hashlib.sha256(a.diag_map.read_bytes()).hexdigest()}
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(json.dumps(r, indent=2, sort_keys=True) + "\n")
        print(json.dumps(r, indent=2, sort_keys=True))

if __name__ == "__main__": main()
