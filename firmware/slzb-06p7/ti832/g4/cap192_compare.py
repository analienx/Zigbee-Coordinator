#!/usr/bin/env python3
"""BASE vs CAP192 linked-map delta + heap-span proof (linked evidence only)."""
from __future__ import annotations
import argparse, hashlib, json, re
from pathlib import Path
def must(v: bool, m: str) -> None:
    if not v: raise ValueError(m)
def parse_map(text: str) -> dict:
    regions, in_mem = {}, False
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
    heap = None
    hs = re.findall(r"(?m)^\s*([0-9A-Fa-f]{8})\s+heapStart\s*$", text)
    he = re.findall(r"(?m)^\s*([0-9A-Fa-f]{8})\s+heapEnd\s*$", text)
    if len(hs) == 1 and len(he) == 1: heap = int(he[0], 16) - int(hs[0], 16)
    return {"regions": regions, "sections": sections, "heap_span_bytes": heap}
def compare(base: str, cand: str, base_elf: int, cand_elf: int) -> dict:
    b, c = parse_map(base), parse_map(cand)
    delta = {k: c["regions"][k] - b["regions"][k]
             for k in sorted(set(b["regions"]) & set(c["regions"]))}
    delta.update({k: c["sections"][k] - b["sections"][k]
                  for k in sorted(set(b["sections"]) & set(c["sections"]))})
    return {"qualification": "G4_CAP192_LINKED_EVIDENCE_NOT_FLASHABLE",
      "runtime_qualified": False, "flash_authorized": False, "base": b, "candidate": c,
      "delta_candidate_minus_base": delta,
      "elf_size_bytes": {"base": base_elf, "candidate": cand_elf, "delta": cand_elf - base_elf},
      "heap_at_least_32kib": {"base": (b["heap_span_bytes"] or 0) >= 32768,
                              "candidate": (c["heap_span_bytes"] or 0) >= 32768}}
def selftest() -> None:
    def fx(flash, nv, sram, text, heap):
        return ("MEMORY CONFIGURATION\n"
          f" FLASH 00000000 000AA000 {flash:08X} 00000000\n"
          f" FLASH_NV 000AA000 00004000 {nv:08X} 00000000\n"
          f" SRAM 20000000 00024000 {sram:08X} 00000000\nSECTION ALLOCATION MAP\n"
          f".text 0 00000000 {text:08X} r-x\n.data 0 20000000 00000100 rw-\n"
          ".bss 0 20000100 00000200 rw-\n"
          f"20006030 heapStart\n{0x20006030+heap:08X} heapEnd\n")
    r = compare(fx(1000, 16384, 2000, 900, 121808), fx(1400, 40960, 2900, 1250, 121772), 10000, 11500)
    must(r["delta_candidate_minus_base"]["flash_nv_used"] == 24576, "NV_DELTA")
    must(r["heap_at_least_32kib"]["candidate"] is True, "HEAP_PROOF")
    try: compare("no regions", fx(1, 1, 1, 1, 1), 1, 1)
    except ValueError: pass
    else: raise AssertionError("COMPARE_NEGATIVE_ACCEPTED")
    print("PASS P7 CAP192 map compare; linked evidence only")
def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--base-map", type=Path); p.add_argument("--cand-map", type=Path)
    p.add_argument("--base-elf", type=Path); p.add_argument("--cand-elf", type=Path)
    p.add_argument("--out", type=Path); p.add_argument("--selftest", action="store_true")
    a = p.parse_args()
    if a.selftest: selftest()
    if a.base_map:
        must(all([a.cand_map, a.base_elf, a.cand_elf, a.out]), "REQUIRE_ALL_INPUTS")
        r = compare(a.base_map.read_text(errors="replace"), a.cand_map.read_text(errors="replace"),
                    a.base_elf.stat().st_size, a.cand_elf.stat().st_size)
        r["map_sha256"] = {"base": hashlib.sha256(a.base_map.read_bytes()).hexdigest(),
                           "candidate": hashlib.sha256(a.cand_map.read_bytes()).hexdigest()}
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(json.dumps(r, indent=2, sort_keys=True) + "\n")
        print(json.dumps(r, indent=2, sort_keys=True))
if __name__ == "__main__": main()
