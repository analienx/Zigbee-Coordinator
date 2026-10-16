#!/usr/bin/env python3
"""Verify exact linked P0/P1 sizes after genuine CCS image audit.

This is a static-evidence gate, never RF proof or heap high-water.
"""
import argparse
import json
from pathlib import Path

BASE={"source_routes":(12,8),"neighbors":(16,28),
      "nwk_routes":(40,8),"children":(21,36),
      "route_requests":(8,10),"relay_path":(12,2)}
TARGET={"source_routes":192,"neighbors":64,"nwk_routes":128}
EXPECTED_P1_DEFINES={"MAX_RTG_SRC_ENTRIES":192,
                     "MAX_NEIGHBOR_ENTRIES":64,"MAX_RTG_ENTRIES":128}
class ProfileError(ValueError):pass

def check(native,overlay,profile):
    if profile not in ("P0","P1"):
        raise ProfileError("unapproved linked candidate")
    if native.get("status")!="HOSTED_NATIVE_LINKED_TABLES":
        raise ProfileError("missing complete linked ELF evidence")
    if overlay.get("profile")!=profile or overlay.get("native_linked_proof")!="REQUIRED_POST_BUILD":
        raise ProfileError("wrong or forged profile overlay receipt")
    if overlay.get("compiler_defines")!=(EXPECTED_P1_DEFINES if profile=="P1" else {}):
        raise ProfileError("wrong compiler override set")
    if overlay.get("tc_nv_security_mto_untouched") is not True:
        raise ProfileError("security or MTO change not authorized")
    changed_bytes=0
    out={}
    for name,(count,size) in BASE.items():
        actual_count=TARGET.get(name,count) if profile=="P1" else count
        item=native.get("tables",{}).get(name,{})
        expect=(actual_count,actual_count*size,size)
        got=(item.get("linked_count"),item.get("linked_bytes"),item.get("entry_sizeof_derived"))
        if got!=expect or item.get("status")!="HOSTED_NATIVE_LINKED":
            raise ProfileError(f"{profile}/{name}: ELF linked counts/bytes wrong: {got} != {expect}")
        changed_bytes+=(actual_count-count)*size
        out[name]={"linked_count":actual_count,"linked_bytes":actual_count*size}
    heap=native.get("linked_heap_address_span")
    if not isinstance(heap,dict) or type(heap.get("span_bytes"))!=int or heap["span_bytes"]<=0:
        raise ProfileError("missing authentic linked heap address span")
    stack=native.get("linked_c_irq_stack_size")
    if not isinstance(stack,dict) or stack.get("size_bytes")!=1024:
        raise ProfileError("C/IRQ linker stack changed (requires separate review)")
    return {
        "result":"NATIVE_STATIC_PROFILE_CONFIRMED",
        "profile":profile,"actual_linked_tables":out,
        "delta_static_table_bytes_vs_p0":changed_bytes,
        "sram_total_bytes":native["memory_regions"]["SRAM"]["size"],
        "linker_heap_address_span_bytes":heap["span_bytes"],
        "dynamic_route_peak_bytes":None,
        "heap_high_water_bytes":None,
        "c_irq_stack_bytes":1024,
        "physical_verified":False,
        "source_ready":False,
        "no_security_or_mto_edits":True,
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--native",type=Path,required=True)
    p.add_argument("--overlay",type=Path,required=True)
    p.add_argument("--profile",choices=("P0","P1"),required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    try:
        result=check(json.loads(a.native.read_text()),json.loads(a.overlay.read_text()),a.profile)
    except (ProfileError,KeyError,OSError,ValueError) as err:
        p.exit(2,"B2-STATIC-PROFILE-BLOCKED: "+str(err)+"\n")
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"result":result["result"],"profile":a.profile,
                      "static_delta":result["delta_static_table_bytes_vs_p0"]}))

if __name__=="__main__":
    main()
