#!/usr/bin/env python3
"""Inspect genuine B0-linked ELF, TI XML and manifest for B2 baseline tables.

The B0 image audit MUST pass first. This collector reports missing symbols as
UNKNOWN, never as zero. It does not claim dynamic high-water, RF, or B2 readiness.
"""
import argparse
import hashlib
import json
import struct
import xml.etree.ElementTree as ET
from pathlib import Path

TABLES = {
    "source_routes": ("rtgSrcTable", "gMAX_RTG_SRC_ENTRIES"),
    "neighbors": ("neighborTable", "gMAX_NEIGHBOR_ENTRIES"),
    "nwk_routes": ("rtgTable", "gMAX_RTG_ENTRIES"),
    "children": ("AssociatedDevList", "gNWK_MAX_DEVICE_LIST"),
    "route_requests": ("rtDiscTable", "gMAX_RREQ_ENTRIES"),
    "relay_path": ("rtgSrcRelayList", "gMAX_SOURCE_ROUTE"),
}
MAX_ELF = 8 * 1024 * 1024
MAX_XML = 2 * 1024 * 1024

class EvidenceError(ValueError):
    pass

def checked_member(root, name):
    if not isinstance(name,str) or not name or Path(name).name != name:
        raise EvidenceError("artifact path traversal or missing name")
    path = root / name
    if not path.is_file() or path.is_symlink():
        raise EvidenceError("missing or symlinked artifact " + name)
    return path

def load_manifest(root):
    raw = checked_member(root,"manifest.json").read_bytes()
    data=json.loads(raw)
    if data.get("schema") != "r4-b0-artifact-manifest-v1":
        raise EvidenceError("unsupported B0 manifest schema")
    files={}
    for key in ("elf","xml","hex","bin"):
        record=data.get("files",{}).get(key)
        if not isinstance(record,dict) or not isinstance(record.get("sha256"),str):
            raise EvidenceError("missing manifest hash for "+key)
        path=checked_member(root,record.get("file"))
        digest=hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != record["sha256"]:
            raise EvidenceError("B0 artifact hash mismatch "+key)
        files[key]={"path":path,"sha256":digest}
    return files

def parse_elf(path):
    raw=path.read_bytes()
    if len(raw) < 52 or len(raw)>MAX_ELF or raw[:4]!=b"\x7fELF":
        raise EvidenceError("invalid native ELF magic/size")
    if raw[4]!=1 or raw[5]!=1 or struct.unpack_from("<H",raw,18)[0]!=40:
        raise EvidenceError("expected ELF32 little-endian ARM")
    shoff=struct.unpack_from("<I",raw,32)[0]
    entsize=struct.unpack_from("<H",raw,46)[0]
    shnum=struct.unpack_from("<H",raw,48)[0]
    shstridx=struct.unpack_from("<H",raw,50)[0]
    if entsize!=40 or not (0<shnum<=512) or shstridx>=shnum or shoff+entsize*shnum>len(raw):
        raise EvidenceError("malformed ELF section header table")
    sh=[]
    for i in range(shnum):
        values=struct.unpack_from("<10I",raw,shoff+i*entsize)
        sh.append(dict(zip(("name","type","flags","addr","offset","size","link","info","align","entsize"),values)))
    def section_bytes(s):
        if s["type"]==8:
            return b""
        if s["offset"]+s["size"]>len(raw):
            raise EvidenceError("invalid ELF section extent")
        return raw[s["offset"]:s["offset"]+s["size"]]
    names=section_bytes(sh[shstridx])
    def string_at(table,off):
        if off>=len(table):
            raise EvidenceError("invalid ELF string offset")
        end=table.find(b"\x00",off)
        if end<0:
            raise EvidenceError("unterminated ELF string")
        return table[off:end].decode("utf-8","replace")
    for sec in sh:
        sec["section_name"]=string_at(names,sec["name"])
    symbols={}
    for section in sh:
        if section["type"] != 2:
            continue  # Full .symtab, never dynamic .dynsym substitute.
        if section["entsize"]!=16 or section["size"]%16 or section["link"]>=shnum:
            raise EvidenceError("invalid ELF symbol table")
        strings=section_bytes(sh[section["link"]])
        body=section_bytes(section)
        for off in range(0,len(body),16):
            name,value,size,info,other,index=struct.unpack_from("<IIIBBH",body,off)
            if not name:
                continue
            label=string_at(strings,name)
            if label in {v for pair in TABLES.values() for v in pair} and size>0:
                if index>=shnum:
                    raise EvidenceError("symbol section index invalid "+label)
                symbols.setdefault(label,[]).append({
                    "name":label,"address":value,"size_bytes":size,
                    "section":sh[index]["section_name"],"section_index":index,
                    "section_type":sh[index]["type"],"section_offset":sh[index]["offset"],
                    "section_address":sh[index]["addr"],
                    "section_size":sh[index]["size"],
                    "binding":info>>4,
                })
    return raw,sh,symbols

def one_symbol(symbols,label):
    options=symbols.get(label,[])
    # Disallow arbitrary choice where multiple real storage definitions exist.
    if len(options)!=1:
        return None
    return options[0]

def initializer_value(raw,s):
    if s is None or s["size_bytes"] not in (1,2,4) or s["section_type"]!=1:
        return None
    delta=s["address"]-s["section_address"]
    if delta<0 or delta+s["size_bytes"]>s["section_size"]:
        return None
    offset=s["section_offset"]+delta
    if offset+s["size_bytes"]>len(raw):
        return None
    return int.from_bytes(raw[offset:offset+s["size_bytes"]],"little")

def derive(root, source_sha, out, run_id):
    files=load_manifest(root)
    blob,sections,symbols=parse_elf(files["elf"]["path"])
    xml=files["xml"]["path"].read_bytes()
    if len(xml)>MAX_XML or b"<!DOCTYPE" in xml or b"<!ENTITY" in xml:
        raise EvidenceError("unsafe or oversized linker XML")
    linked=ET.fromstring(xml)
    if linked.tag!="link_info" or "3.2.2" not in (linked.findtext("banner") or ""):
        raise EvidenceError("not genuine expected TI Clang linker XML")
    if Path(linked.findtext("output_file") or "").name!=files["elf"]["path"].name:
        raise EvidenceError("ELF/XML output_file mismatch")
    areas={}
    for area in linked.findall("./placement_map/memory_area"):
        name=(area.findtext("name") or "").strip()
        origin=int((area.findtext("origin") or "0"),0)
        size=int((area.findtext("length") or "0"),0)
        if name in areas:
            raise EvidenceError("duplicate linker memory area")
        areas[name]={"base":origin,"size":size}
    if areas.get("SRAM",{}).get("size")!=0x24000:
        raise EvidenceError("unverified P7 SRAM geometry")
    table_result={}
    for key,(array_name,limit_name) in TABLES.items():
        table=one_symbol(symbols,array_name)
        count=one_symbol(symbols,limit_name)
        linked_count=initializer_value(blob,count)
        linked_bytes=table["size_bytes"] if table else None
        entry_size=None
        if table and linked_count is not None and 0<linked_count<=65535:
            if linked_bytes % linked_count==0:
                entry_size=linked_bytes//linked_count
        status=("HOSTED_NATIVE_LINKED" if table and linked_count is not None
                and entry_size is not None and entry_size>0 else "UNKNOWN_LINKED_CAPACITY")
        table_result[key]={
            "status":status,
            "array_symbol":array_name,"capacity_symbol":limit_name,
            "linked_count":linked_count,"linked_bytes":linked_bytes,
            "entry_sizeof_derived":entry_size,
            "array_section":table["section"] if table else None,
            "array_address":table["address"] if table else None,
            "value_section":count["section"] if count else None,
            "reason":None if status=="HOSTED_NATIVE_LINKED" else
                "missing/ambiguous symbol, uninitialized scalar or indivisible extent",
        }
    memory_sections={}
    for s in sections:
        if s["flags"] & 0x2 and s["size"] and 0x20000000<=s["addr"]<0x20024000:
            memory_sections.setdefault(s["section_name"],0)
            memory_sections[s["section_name"]]+=s["size"]
    source_sha=source_sha or "UNKNOWN"
    result={
        "status":"HOSTED_NATIVE_LINKED_PARTIAL"
                 if any(x["status"]!="HOSTED_NATIVE_LINKED" for x in table_result.values())
                 else "HOSTED_NATIVE_LINKED_TABLES",
        "scope":"B0_REFERENCE_ONLY; no B2 tuning, RAM high-water or RF qualification",
        "b2_repository_sha":source_sha,"github_run_id":run_id or "UNKNOWN",
        "sdk_source_sha":"3615ad5d3f4f271258d18a2f5ce1785064ff9a58",
        "artifact_sha256":{k:v["sha256"] for k,v in files.items()},
        "memory_regions":areas,"sram_allocated_sections":memory_sections,
        "tables":table_result,
        "heap_high_water":None,"concurrent_dynamic_route_buffer_peak":None,
        "rtos_task_stacks_total":None,"c_irq_stack_confirmed_bytes":None,
        "safe_sram_headroom_bytes":None,
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/"B2_BASELINE_ELF_SYMBOLS.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    lines=["# B2 actual linked P0 baseline — TI B0 reference",
           "", "**HOSTED_NATIVE**, not B2_SOURCE_READY or physical proof.",
           "B0 native image audit must be independently green.",
           f"Build source commit: \`{source_sha}\`; run: \`{run_id}\`.",
           "", "| Table | Linked count | Linked bytes | Derived entry bytes | ELF section |"]
    lines.append("|---|---:|---:|---:|---|")
    for key,t in table_result.items():
        def x(v):
            return str(v) if v is not None else "UNKNOWN"
        lines.append(f"| {key} | {x(t['linked_count'])} | {x(t['linked_bytes'])} |"
                     f" {x(t['entry_sizeof_derived'])} | {x(t['array_section'])} |")
    lines+=["", "RAM memory sections (raw ELF SHF_ALLOC; may contain overlap/aliases):"]
    lines.extend(f"- \`{n}\`: {v} bytes" for n,v in sorted(memory_sections.items()))
    lines+=["", "A section sum is not a proven free-RAM bound. Tasks, C/IRQ stack,"
            " heap arena and worst-case dynamic occupancy need disjoint proof.",
            "Runtime heap high-water: **UNKNOWN**.",
            "Security/NV layout, physical hardware and RF: **NOT QUALIFIED**."]
    (out/"BASELINE_ELF_SYMBOLS.md").write_text("\n".join(lines)+"\n")
    return result

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--artifacts",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--source-sha",default="")
    p.add_argument("--run-id",default="")
    a=p.parse_args()
    result=derive(a.artifacts,a.source_sha,a.out,a.run_id)
    print(json.dumps({"status":result["status"],
                      "verified_tables":sum(v["status"]=="HOSTED_NATIVE_LINKED" for v in result["tables"].values()),
                      "total_tables":len(TABLES),"source_sha":result["b2_repository_sha"]}))

if __name__=="__main__":
    main()
