#!/usr/bin/env python3
"""OFFLINE, secret-safe CC2674P10 NVOCMP page forensics.

Do not connect to any Zigbee radio, uploader, debugger or bootloader. Input
files may contain network/link keys: keep them in restricted private storage.
Report only region hashes, page-state metadata and aggregate transitions.
No decoded item IDs, keys or individual device identifiers are printed.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

START=0xF8800
PAGE=2048
COUNT=15
SIZE=PAGE*COUNT
STATES={0xff:"inactive",0xfe:"transfer-destination",0x7e:"ready",
        0x7c:"active",0x78:"full",0x70:"transfer-source"}
SIGNATURE=0x96
VERSION=3

def page_metadata(blob:bytes)->dict:
    if len(blob)!=PAGE:
        raise ValueError("expected exactly one 2048-byte CC2674P10 flash page")
    filled=blob==b"\xff"*PAGE
    zero=blob==b"\x00"*PAGE
    if filled:
        return {"condition":"fully_erased","state":"inactive",
                "header":"unformatted","non_ff_bytes":0}
    header_state=STATES.get(blob[0],"invalid")
    header_version=blob[2]>>2
    signature=blob[3]
    version_valid=header_version==VERSION
    signature_valid=signature==SIGNATURE
    format_valid=(header_state!="invalid" and version_valid and signature_valid)
    return {"condition":"zero_filled" if zero else "programmed",
            "state":header_state,
            "header":"valid" if format_valid else "invalid_or_unformatted",
            "non_ff_bytes":PAGE-blob.count(255),
            "version_ok":version_valid,
            "signature_ok":signature_valid,
            "page_state_ok":header_state!="invalid"}

def analyze(data:bytes)->dict:
    if len(data)!=SIZE:
        raise ValueError("expected exact physical 30 KiB P10 NVS region (0xF8800..0xFFFFF)")
    pages=[page_metadata(data[i*PAGE:(i+1)*PAGE]) for i in range(COUNT)]
    states={}
    for p in pages:
        states[p["condition"]]=states.get(p["condition"],0)+1
    return {"region_base":START,"region_size":SIZE,"total_pages":COUNT,
            "global_sha256":hashlib.sha256(data).hexdigest(),
            "conditions":states,"pages":[{"page":i,"address":START+i*PAGE,**v}
                                 for i,v in enumerate(pages)],
            "security_material_logged":False}

def compare_stages(before:bytes,preboot:bytes,after:bytes)->dict:
    a,b,c=[analyze(v) for v in (before,preboot,after)]
    transitions=[]
    for i in range(COUNT):
        a_page=before[i*PAGE:(i+1)*PAGE]
        b_page=preboot[i*PAGE:(i+1)*PAGE]
        c_page=after[i*PAGE:(i+1)*PAGE]
        first=a["pages"][i]["condition"]
        middle=b["pages"][i]["condition"]
        last=c["pages"][i]["condition"]
        if a_page!=b_page or b_page!=c_page:
            transitions.append({
                "page":i,
                "pre_to_preboot_changed":a_page!=b_page,
                "preboot_to_postboot_changed":b_page!=c_page,
                "pre":first,"preboot":middle,"postboot":last})
    preboot_erased=[x["page"] for x in transitions if
                   x["pre"]!="fully_erased" and x["preboot"]=="fully_erased"]
    postboot_erased=[x["page"] for x in transitions if
                    x["preboot"]!="fully_erased" and x["postboot"]=="fully_erased"]
    # These only identify *when* bytes changed; they cannot attribute a
    # physical erase to a particular bootloader instruction without a trace.
    return {"stage_sha256":{
                "before":a["global_sha256"],
                "after_flash_before_app_boot":b["global_sha256"],
                "after_app_boot":c["global_sha256"]},
            "preboot_newly_blank_pages":preboot_erased,
            "postboot_newly_blank_pages":postboot_erased,
            "changed_pages":transitions,
            "preboot_changed_pages":sum(v["pre_to_preboot_changed"] for v in transitions),
            "postboot_changed_pages":sum(v["preboot_to_postboot_changed"] for v in transitions),
            "flash_programming_changed_nvs":before!=preboot,
            "application_boot_changed_nvs":preboot!=after,
            "physical_erase_opcode_proven":False,
            "security_material_logged":False}

def load_private(p:Path)->bytes:
    # Inputs contain secrets. Do not process symlinks to unidentified targets.
    if p.is_symlink() or not p.is_file() or p.stat().st_size!=SIZE:
        raise ValueError("private NVS snapshot missing or wrong size")
    with p.open("rb") as f: return f.read()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--snapshot",type=Path)
    p.add_argument("--before",type=Path)
    p.add_argument("--post-program-preboot",type=Path)
    p.add_argument("--after-boot",type=Path)
    args=p.parse_args()
    if args.snapshot and not any((args.before,args.post_program_preboot,args.after_boot)):
        result=analyze(load_private(args.snapshot))
    elif all((args.before,args.post_program_preboot,args.after_boot)) and not args.snapshot:
        result=compare_stages(load_private(args.before),
                              load_private(args.post_program_preboot),
                              load_private(args.after_boot))
    else: p.error("supply one --snapshot OR all three stages")
    print(json.dumps(result,sort_keys=True,indent=2))

if __name__=="__main__":main()
