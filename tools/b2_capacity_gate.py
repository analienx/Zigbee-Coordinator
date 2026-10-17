#!/usr/bin/env python3
"""B2 synthetic arithmetic checker for a claimed memory ledger.

This reads *self-declared* JSON (no actual ELF) and cannot independently
attest a native build. Genuine linked proof belongs to b2_collect_native_evidence
and b2_compare_native, following the B0 native binary image audit.
"""
import argparse
import json
from pathlib import Path

REQUIRED_TABLES = ("source_routes", "neighbors", "nwk_routes", "children")
BASE_COMMIT = "1baefbee8e4de2c9d28c5e1a7c339cf2025a2afe"

class EvidenceError(ValueError):
    pass

def positive_int(value, label, zero_ok=False):
    if type(value) is not int or value < (0 if zero_ok else 1):
        raise EvidenceError(f"{label}: expected {'nonnegative' if zero_ok else 'positive'} integer")
    return value

def validate(data):
    if data.get("base_commit") != BASE_COMMIT:
        raise EvidenceError("wrong B0 ancestry")
    for field in ("source_sha", "sdk_sha", "elf_sha256", "map_sha256", "compiler"):
        if not isinstance(data.get(field), str) or not data[field].strip():
            raise EvidenceError(f"missing provenance: {field}")
    if data.get("source_sha") != data.get("build_source_sha"):
        raise EvidenceError("source SHA does not match native build")
    if data.get("measurement_kind") != "HOSTED_NATIVE_LINKED":
        raise EvidenceError("linked evidence required; synthetic or source macros insufficient")
    sram = positive_int(data.get("sram_bytes"), "sram_bytes")
    static = positive_int(data.get("static_allocated_bytes"), "static_allocated_bytes", True)
    stack = positive_int(data.get("c_irq_stack_bytes"), "c_irq_stack_bytes")
    tasks = data.get("task_stack_bytes")
    if not isinstance(tasks, dict) or not tasks:
        raise EvidenceError("task stack ledger missing")
    task_total = sum(positive_int(n, f"task_stack_bytes.{k}") for k,n in tasks.items())
    heap = positive_int(data.get("heap_arena_bytes"), "heap_arena_bytes", True)
    peak = positive_int(data.get("peak_dynamic_route_bytes"), "peak_dynamic_route_bytes", True)
    fragmentation = positive_int(data.get("fragmentation_reserve_bytes"), "fragmentation_reserve_bytes", True)
    if peak + fragmentation > heap:
        raise EvidenceError("route dynamic peak plus fragmentation exceeds heap arena")
    tables = data.get("tables")
    if not isinstance(tables, dict):
        raise EvidenceError("missing linked table evidence")
    table_totals = {}
    for name in REQUIRED_TABLES:
        table = tables.get(name)
        if not isinstance(table, dict):
            raise EvidenceError(f"{name}: missing")
        count = positive_int(table.get("linked_count"), f"{name}.linked_count")
        size = positive_int(table.get("entry_sizeof"), f"{name}.entry_sizeof")
        total = positive_int(table.get("linked_bytes"), f"{name}.linked_bytes")
        if count * size != total:
            raise EvidenceError(f"{name}: linked size does not match count * sizeof")
        if not all(isinstance(table.get(x),str) and table[x].strip() for x in ("elf_symbol","section","map_reference","source_reference")):
            raise EvidenceError(f"{name}: missing linked symbol/section/map/source")
        table_totals[name] = total
    if sum(table_totals.values()) > static:
        raise EvidenceError("linked table bytes exceed accounted static bytes")
    # A heap arena and task stacks may already be included in .bss. The producer
    # MUST document exclusivity rather than double-counting these allocations.
    if data.get("static_excludes_heap_and_task_stacks") is not True:
        raise EvidenceError("cannot establish disjoint SRAM accounting")
    committed = static + stack + task_total + heap
    if committed > sram:
        raise EvidenceError(f"SRAM_BUDGET_EXCEEDED: committed={committed} available={sram}")
    return {"result":"SYNTHETIC_BUDGET_ARITHMETIC_ONLY",
            "native_artifact_independently_verified":False,
            "runtime_heap_high_water_measured":False,
            "physical_verified":False,
            "sram_headroom_bytes":sram-committed,
            "claimed_table_bytes":table_totals, "claimed_dynamic_peak_bytes":peak}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("evidence",type=Path)
    args = p.parse_args()
    try:
        result=validate(json.loads(args.evidence.read_text(encoding="utf-8")))
    except (EvidenceError,ValueError,KeyError) as e:
        print(json.dumps({"result":"BLOCKED","reason":str(e)}))
        return 1
    print(json.dumps(result,sort_keys=True))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
