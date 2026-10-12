#!/usr/bin/env python3
"""Read-only G3 memory/NV headroom profile from a REAL pinned P7 TI linker map.

No hardware access, no build, no Zigbee traffic, no flash or NV operations.
Runtime heap high-water, fragmentation, route-table usage and 192-key
persistence are deliberately UNKNOWN; hypothetical scenarios are not proofs.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
from pathlib import Path
import sys

G2 = Path(__file__).resolve().parents[1] / "g2"
sys.path.insert(0, str(G2))
from verify_vanilla import verify_map, APP_END, NV_BEGIN, NV_END, LAST_BEGIN, FLASH_END

EXPECTED_REFERENCE_ELF_SHA256 = "90b44e59af383d79dd90ae63a8d00013a07017343611a34afb52dcb587c04d24"
STABLE_CC = "TI_LP_CC1352P7_4_REFERENCE_ONLY_NOT_SMLIGHT"


def must(test: bool, message: str) -> None:
    if not test:
        raise ValueError(message)


def symbol_address(data: str, symbol: str) -> int:
    anchor = "GLOBAL SYMBOLS: SORTED ALPHABETICALLY BY Name"
    must(anchor in data, "NO_GLOBAL_SYMBOL_SECTION")
    # TI ARM Clang repeats every global symbol in a second address-sorted
    # table. Restrict lookups to the first alphabetic symbol table only.
    text = data.split(anchor, 1)[1].split(
        "GLOBAL SYMBOLS: SORTED BY Symbol Address", 1)[0]
    # Stop at subsequent symbol tables so duplicate listings do not fail G3.
    pattern = re.compile(
        r"^\s*([0-9A-Fa-f]{8})\s+" + re.escape(symbol) +
        r"\s*$", re.MULTILINE)
    matches = pattern.findall(text)
    must(len(matches) == 1, f"GLOBAL_SYMBOL_NOT_UNIQUE_{symbol}")
    return int(matches[0], 16)


def analyze(text: str) -> dict:
    regions = verify_map(text)
    start = symbol_address(text, "heapStart")
    stop = symbol_address(text, "heapEnd")
    stack_start = symbol_address(text, "__STACK_END") - symbol_address(text, "__STACK_SIZE")
    stack_top = symbol_address(text, "__STACK_TOP")
    stack_size = symbol_address(text, "__STACK_SIZE")
    mem_start, mem_end = 0x20000000, 0x20024000
    must(mem_start <= start < stop <= stack_start < stack_top == mem_end,
         "HEAP_STACK_BAD_BOUNDARY_OR_OVERLAP")
    must(stack_size == stack_top - stack_start and 0 < stack_size <= 16384,
         "STACK_SIZE_MISMATCH")
    must(regions["flash_used"] == 176396 and regions["sram_used"] == 18848,
         "NOT_THE_PINNED_G2_MEMORY_BASELINE")
    must(regions["nv_used"] == NV_END-NV_BEGIN and
         regions["ccfg_sector_used"] == 88, "NV_CCFG_BASELINE_DRIFT")
    must(regions["gpram_used"] == 0, "GPRAM_MODE_NOT_QUALIFIED")
    # Do not call contiguous address range 'available runtime free heap.'
    size = stop - start
    stack_free = stack_top - stack_start
    scenarios=[]
    # These are deliberately illustrative per-key memory costs. They cannot
    # be used to derive real OSAL allocation or persistent NV footprint.
    for records in (60, 100, 192):
        for assumed_bytes in (24, 48, 96):
            hypot = records * assumed_bytes
            scenarios.append({
                "hypothetical_record_count":records,
                "hypothetical_ram_bytes_per_record":assumed_bytes,
                "hypothetical_total_ram_bytes":hypot,
                "fraction_of_linked_heap_address_range":round(hypot/size, 5),
                "proves_cap192_runtime_fit":False,
            })
    nv_sector = 8192
    nv_scenarios = [
        {"assumed_serialized_record_bytes":n,
         "hypothetical_80pct_single_sector_record_budget":(nv_sector*80//100)//n,
         "assumption_only_not_capacity_proof":True}
        for n in (32,48,64,96,128)
    ]
    return {
        "qualification":STABLE_CC,
        "app_flash_link_used_bytes":regions["flash_used"],
        "app_flash_link_capacity_bytes":APP_END,
        "app_flash_link_remaining_bytes":regions["flash_unused"],
        "sram_link_used_bytes":regions["sram_used"],
        "sram_capacity_bytes":0x24000,
        "sram_link_remaining_bytes":regions["sram_unused"],
        "heap_link_start":f"0x{start:08x}",
        "heap_link_end_exclusive":f"0x{stop:08x}",
        "heap_link_address_span_bytes":size,
        "stack_start":f"0x{stack_start:08x}",
        "stack_end_exclusive":f"0x{stack_top:08x}",
        "stack_reserved_bytes":stack_free,
        "nv_sector_bytes":nv_sector,
        "nv_sector_count":2,
        "nv_bytes_programmed_by_reference_hex":0,
        "ccfg_sector_start":f"0x{LAST_BEGIN:08x}",
        "ccfg_sector_end_exclusive":f"0x{FLASH_END:08x}",
        "ccfg_occupied_bytes":regions["ccfg_sector_used"],
        "runtime_high_water_mark_measured":False,
        "runtime_heap_fragmentation_measured":False,
        "nv_compaction_and_power_loss_tested":False,
        "security_counter_persistence_tested":False,
        "reference_elf_sha256_pin":EXPECTED_REFERENCE_ELF_SHA256,
        "reference_elf_hash_verified_by_this_tool":False,
        "cap192_runtime_qualified":False,
        "hardware_qualified":False,
        "flash_authorized":False,
        "hypothetical_ram_scenarios":scenarios,
        "hypothetical_nv_scenarios":nv_scenarios,
        "mandatory_later_hardware_tests":[
            "peak heap allocation/high-water under >=192 table entries",
            "stack low-water per task and ISR stress; no overflow",
            "key create/update/delete and two-sector NV compaction to 192 slots",
            "interrupt power between sector copy/write/erase and verify data integrity",
            "restore coordinator/security counters from validated backups",
            "60+ router sustained operation with real traffic and route repair",
        ]
    }


def fixture() -> str:
    lines = ["MEMORY CONFIGURATION"]
    for name,start,size,used in [
        ("FLASH",0,0xAA000,176396),("FLASH_NV",0xAA000,0x4000,0x4000),
        ("FLASH_LAST",0xAE000,0x2000,88),
        ("SRAM",0x20000000,0x24000,18848),
        ("GPRAM",0x11000000,0x2000,0),
    ]:
        lines.append(f" {name:<18} {start:08X} {size:08X} {used:08X} {size-used:08X}")
    lines += [".ccfg", "GLOBAL SYMBOLS: SORTED ALPHABETICALLY BY Name",
              "20006030  heapStart", "20023c00  heapEnd",
              "20024000  __STACK_END", "00000400  __STACK_SIZE",
              "20024000  __STACK_TOP"]
    return "\n".join(lines)


def selftest() -> None:
    test = fixture()
    result = analyze(test)
    must(result["heap_link_address_span_bytes"] == 121808, "HEAP_SIZE_WRONG")
    must(result["stack_reserved_bytes"] == 1024, "STACK_SIZE_WRONG")
    must(len(result["hypothetical_ram_scenarios"])==9, "RAM_SCENARIO_COUNT")
    must(result["reference_elf_sha256_pin"]==EXPECTED_REFERENCE_ELF_SHA256, "ELF_PIN_NOT_REPORTED")
    must(result["reference_elf_hash_verified_by_this_tool"] is False, "ELF_PIN_OVERCLAIM")
    mutations = [
        test.replace("20006030  heapStart", "20023D00  heapStart"),
        test.replace("20023c00  heapEnd", "20026000  heapEnd"),
        test.replace("00000400  __STACK_SIZE", "00000000  __STACK_SIZE"),
        test.replace("20024000  __STACK_TOP", "20026000  __STACK_TOP"),
        test.replace("0002B10C", "0002B10D") if "0002B10C" in test else
            test.replace("0002B10C","0002B10D") + "\n20006030  heapStart",
        test.replace("20006030  heapStart",""),
        test.replace("0002B10C","0002B10D"),
        test.replace("00004000 00004000","00004000 00002000"),
        test.replace("GLOBAL SYMBOLS: SORTED ALPHABETICALLY BY Name",""),
    ]
    # Remove mutations that do not change source material.
    mutations = [v for v in mutations if v != test]
    passed=0
    for s in mutations:
        try: analyze(s)
        except (ValueError,KeyError):
            passed+=1
        else:
            raise AssertionError("MEMORY_MUTATION_UNDETECTED")
    print(f"PASS G3 memory and NV static profile, {passed} fail-closed mutations")


def main() -> None:
    ap=argparse.ArgumentParser()
    ap.add_argument("--map", type=Path)
    ap.add_argument("--out",type=Path)
    ap.add_argument("--selftest",action="store_true")
    args=ap.parse_args()
    if args.selftest:
        selftest()
    if args.map:
        must(bool(args.out), "OUTPUT_REQUIRED")
        report=analyze(args.map.read_text(encoding="utf-8",errors="replace"))
        report["link_map_sha256"]=hashlib.sha256(args.map.read_bytes()).hexdigest()
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
        print(json.dumps({k:v for k,v in report.items()
            if k in ("heap_link_address_span_bytes","stack_reserved_bytes",
                     "cap192_runtime_qualified","sram_link_used_bytes")},indent=2))


if __name__=="__main__":
    main()
