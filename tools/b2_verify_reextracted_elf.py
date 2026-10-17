#!/usr/bin/env python3
"""Verify B2 uploaded JSON claims by independently re-reading the raw ELF.

The genuine CCS builds remain under separate B0 image audit. This check
ensures P0/P1 profiles and SRAM values correspond to the actual linked
ELF in each independently downloaded artifact, not just SHA self-claims.
"""
import argparse
import json
from pathlib import Path

FIELDS=("status","b2_repository_sha","github_run_id","sdk_source_sha",
        "artifact_sha256","memory_regions","sram_allocated_sections",
        "linked_heap_address_span","linked_c_irq_stack_size",
        "linked_mto_rreq_limit_ms","concentrator_config_symbols",
        "sram_linker_address_partition","tables")
class RecomputeError(ValueError):pass

def verify(claimed,fresh):
    for key in FIELDS:
        if key not in claimed or key not in fresh or claimed[key]!=fresh[key]:
            raise RecomputeError("native ELF re-extraction disagrees on "+key)
    if claimed["status"]!="HOSTED_NATIVE_LINKED_TABLES":
        raise RecomputeError("linked table completeness required")
    return {
        "status":"B2_NATIVE_CLAIMS_INDEPENDENTLY_REDERIVED",
        "source_sha":fresh["b2_repository_sha"],
        "run_id":fresh["github_run_id"],
        "elf_sha256":fresh["artifact_sha256"]["elf"],
        "linked_tables_verified":sorted(fresh["tables"]),
        "runtime_heap_high_water_measured":False,
        "physical_verified":False,
        "B2_SOURCE_READY":False,
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--claimed",required=True,type=Path)
    p.add_argument("--fresh",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    a=p.parse_args()
    for f in (a.claimed,a.fresh):
        if f.is_symlink() or not f.is_file() or f.stat().st_size>1024*1024:
            p.exit(2,"B2-ELF-REDERIVATION-BLOCKED: unsafe claim file\n")
    try:
        result=verify(json.loads(a.claimed.read_text()),json.loads(a.fresh.read_text()))
    except (ValueError,KeyError,TypeError) as err:
        p.exit(2,"B2-ELF-REDERIVATION-BLOCKED: "+str(err)+"\n")
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(json.dumps(result,sort_keys=True))
if __name__=="__main__":main()
