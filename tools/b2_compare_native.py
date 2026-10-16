#!/usr/bin/env python3
"""Compare two independent native B2 P1 builds against the P0 linked baseline.

All three inputs must already have passed B0's native image audit and each
profile's ELF symbol gate. This is static linker proof, NOT runtime/RF proof.
"""
import argparse
import hashlib
import json
from pathlib import Path

EXPECTED=(("source_routes",12,192,8),("neighbors",16,64,28),
          ("nwk_routes",40,128,8),("children",21,21,36),
          ("route_requests",8,8,10),("relay_path",12,12,2))
B0_SHA="1baefbee8e4de2c9d28c5e1a7c339cf2025a2afe"
SDK_SHA="3615ad5d3f4f271258d18a2f5ce1785064ff9a58"
MIN_SRAM=0x24000

class CompareError(ValueError):pass

def read_json(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size>1024*1024:
        raise CompareError("missing/oversized/symlinked native evidence "+str(path))
    return json.loads(path.read_text(encoding="utf-8"))

def read(root,profile):
    out=root/"b0out"
    native=read_json(out/"b2-linked-baseline"/"B2_BASELINE_ELF_SYMBOLS.json")
    receipt=read_json(out/"b2-linked-baseline"/f"B2_PROFILE_{profile}_RECEIPT.json")
    manifest=read_json(out/"manifest.json")
    if manifest.get("schema")!="r4-b0-artifact-manifest-v1":
        raise CompareError("missing native B0 artifact manifest")
    bin_meta=manifest.get("files",{}).get("bin",{})
    name=bin_meta.get("file")
    if not isinstance(name,str) or Path(name).name!=name:
        raise CompareError("unsafe/missing BIN file")
    path=out/name
    if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=bin_meta.get("sha256"):
        raise CompareError("binary image hash mismatch")
    if receipt.get("result")!="NATIVE_STATIC_PROFILE_CONFIRMED" or receipt.get("profile")!=profile:
        raise CompareError("profile linked gate not passed")
    if native.get("status")!="HOSTED_NATIVE_LINKED_TABLES" or native.get("sdk_source_sha")!=SDK_SHA:
        raise CompareError("missing source-pinned ELF proof")
    if receipt.get("physical_verified") is not False or receipt.get("source_ready") is not False:
        raise CompareError("unsafe RF/readiness claim in receipt")
    return native,receipt,manifest

def compute(p0,p1a,p1b):
    n0,r0,m0=p0
    n1,r1,m1=p1a
    n2,r2,m2=p1b
    commits={n["b2_repository_sha"] for n in (n0,n1,n2)}
    if len(commits)!=1 or any("UNKNOWN" in s for s in commits):
        raise CompareError("nonmatching native source checkout commits")
    if {n["memory_regions"]["SRAM"]["size"] for n in (n0,n1,n2)}!={MIN_SRAM}:
        raise CompareError("SRAM geometry drift")
    delta=0
    linked_tables={}
    for name,before,after,size in EXPECTED:
        vals=[]
        for native in (n0,n1,n2):
            t=native.get("tables",{}).get(name,{})
            if t.get("status")!="HOSTED_NATIVE_LINKED":
                raise CompareError("missing ELF linked table "+name)
            vals.append((t.get("linked_count"),t.get("linked_bytes"),t.get("entry_sizeof_derived")))
        if vals!=[(before,before*size,size),(after,after*size,size),(after,after*size,size)]:
            raise CompareError("linked table delta not proven "+name+": "+str(vals))
        delta+=(after-before)*size
        linked_tables[name]={"P0":before,"P1":after,"entry_sizeof":size}
    if delta!=3488 or r0.get("delta_static_table_bytes_vs_p0")!=0:
        raise CompareError("unexpected static delta")
    if any(r.get("delta_static_table_bytes_vs_p0")!=delta for r in (r1,r2)):
        raise CompareError("profile static delta gate disagreement")
    p1bins=[m["files"]["bin"]["sha256"] for m in (m1,m2)]
    if p1bins[0]!=p1bins[1]:
        raise CompareError("P1 native BIN not reproducible across independent hosted builds")
    if m0["files"]["bin"]["sha256"]==p1bins[0]:
        raise CompareError("P1 BIN identical to P0 (suspect no-op changes)")
    partitions=[]
    for n in (n0,n1,n2):
        p=n.get("sram_linker_address_partition")
        if not isinstance(p,dict):
            raise CompareError("missing disjoint linker SRAM partition")
        fields=("below_heap_linker_reserved_span_bytes","heap_linker_address_span_bytes","above_heap_linker_reserved_span_bytes")
        if any(type(p.get(x))!=int or p[x]<0 for x in fields) or sum(p[x] for x in fields)!=MIN_SRAM:
            raise CompareError("invalid linked SRAM geometry")
        partitions.append(p)
    # A high water mark is not measured by this CI test. Static bytes may
    # vary beyond these three tables; report the unattributed delta honestly.
    reserved_p0=partitions[0]["below_heap_linker_reserved_span_bytes"]
    reserved_p1=partitions[1]["below_heap_linker_reserved_span_bytes"]
    unattributed=(reserved_p1-reserved_p0)-delta
    if partitions[1]["heap_linker_address_span_bytes"]!=partitions[2]["heap_linker_address_span_bytes"]:
        raise CompareError("P1 replicas have different linked SRAM heap spans")
    return {
        "status":"B2_NATIVE_CAPACITY_EVIDENCE_COMPLETE_NOT_B2_SOURCE_READY",
        "source_sha":next(iter(commits)),
        "baseline_b0_sha":B0_SHA,"sdk_sha":SDK_SHA,
        "profiles":{"P0":"NATIVE_VALIDATED","P1":"NATIVE_VALIDATED_TWICE"},
        "table_delta_bytes":delta,"table_inventory":linked_tables,
        "linked_sram_partitions":{"P0":partitions[0],"P1a":partitions[1],"P1b":partitions[2]},
        "unattributed_below_heap_delta_bytes":unattributed,
        "binary_reproducible":True,"binary_sha256":{"P0":m0["files"]["bin"]["sha256"],"P1":p1bins[0]},
        "runtime_heap_high_water_bytes":None,"task_stack_peak_bytes":None,
        "physical_verified":False,"B2_SOURCE_READY":False,
        "closed_ti_routing_body_tests":"BLOCKED_SOURCE_UNAVAILABLE",
        "b1_b2_integration":"NOT_RUN",
    }

def main():
    p=argparse.ArgumentParser()
    for name in ("p0","p1a","p1b"):p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    try:
        result=compute(read(a.p0,"P0"),read(a.p1a,"P1"),read(a.p1b,"P1"))
    except (CompareError,KeyError,ValueError,OSError,TypeError) as err:
        p.exit(2,"B2-NATIVE-DELTA-BLOCKED: "+str(err)+"\n")
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"status":result["status"],"source_sha":result["source_sha"],
                      "measured_table_delta":result["table_delta_bytes"],
                      "unattributed_sram_delta":result["unattributed_below_heap_delta_bytes"]}))

if __name__=="__main__":main()
