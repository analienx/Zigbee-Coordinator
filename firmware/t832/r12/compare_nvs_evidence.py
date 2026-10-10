#!/usr/bin/env python3
"""Offline compare two verified P10 firmware bundles' NVS contracts.
No radio/network access, no raw NVS dumping, no security key processing.
A PASS establishes equivalent static geometry, *never physical preservation*.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

BASE=0xF8800
BYTES=15*2048

def read(path:Path)->dict:
    result=json.loads(path.read_text(encoding="utf8"))
    if not isinstance(result,dict):raise ValueError("JSON object required")
    return result

def sha(path:Path)->str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def check_bundle(directory:Path)->dict:
    manifest=read(directory/"T832-BUILD-MANIFEST.json")
    if manifest.get("sdk_commit")!="6499c3f53fc5fb5806213be695450a7b43fbaf3d":
        raise ValueError("SDK changed")
    geometry=read(directory/"provenance/nv-contract.json")
    layout=read(directory/"provenance/vendor-layout-proof.json")
    ccfg=read(directory/"provenance/ccfg-gate.json")
    if not (geometry.get("nvs_base")==BASE
            and geometry.get("nvs_bytes")==BYTES
            and geometry.get("nvs_end")==0x100000
            and geometry.get("nvs_pages")==15
            and geometry.get("sector_bytes")==2048):
        raise ValueError("unexpected NVS region")
    cand=layout["candidate"]
    if not (cand["nvs_base"]==BASE and cand["nvs_bytes"]==BYTES
            and cand["runtime"]["limit"]==15
            and cand["runtime"]["sector_bytes"]==2048):
        raise ValueError("binary disassembly geometry differs")
    image=directory/(manifest["variant"]+".slzb.bin")
    if not image.is_file() or sha(image)!=cand["candidate_sha256"]:
        raise ValueError("image hash mismatch")
    if image.stat().st_size>=BASE:
        raise ValueError("image overlaps start of reserved NVS")
    if ccfg.get("nv_hex_records")!=0 or ccfg.get("bootloader_enabled") is not True:
        raise ValueError("unexpected NV writes or CCFG bootloader")
    if manifest.get("flash_authorized") is not False:
        raise ValueError("bundle unexpectedly flash authorized")
    return {"nv_contract":geometry,"ccfg_fields":ccfg["fields"],
            "ccfg_other":{k:v for k,v in ccfg.items() if k!="reset_vector"},
            "ccfg_reset_vector":ccfg["reset_vector"],
            "image_revision":manifest.get("sys_version_revision"),
            "image_sha256":sha(image),"image_bytes":image.stat().st_size,
            "source_commit":manifest.get("repository_commit"),
            "sdk_commit":manifest["sdk_commit"],
            "vendor_nvs_base":layout["reference"]["nvs_base"],
            "vendor_nvs_bytes":layout["reference"]["nvs_bytes"]}

def audit(old:Path,new:Path)->dict:
    a,b=check_bundle(old),check_bundle(new)
    if a["nv_contract"]!=b["nv_contract"]:
        raise ValueError("NVS contract drift")
    if a["ccfg_fields"]!=b["ccfg_fields"]:
        raise ValueError("CCFG fields drift")
    if a["ccfg_other"]!=b["ccfg_other"]:
        raise ValueError("CCFG non-reset-vector drift")
    if a["vendor_nvs_base"]!=b["vendor_nvs_base"] or a["vendor_nvs_bytes"]!=b["vendor_nvs_bytes"]:
        raise ValueError("reference geometry drift")
    if (a["image_revision"],b["image_revision"])!=(8320062,8320063):
        raise ValueError("unexpected R12/A1 revisions")
    return {
        "status":"STATIC_NVS_LAYOUT_EQUAL_PHYSICAL_NVS_UNPROVEN",
        "nv_contract_identical":True,
        "all_ccfg_fields_identical":True,
        "reset_vector_changed":a["ccfg_reset_vector"]!=b["ccfg_reset_vector"],
        "nvs_start":BASE,"nvs_end_exclusive":BASE+BYTES,
        "nvs_pages":15,"nvs_page_bytes":2048,
        "image_a":{"revision":a["image_revision"],"sha256":a["image_sha256"],
                   "bytes":a["image_bytes"]},
        "image_b":{"revision":b["image_revision"],"sha256":b["image_sha256"],
                   "bytes":b["image_bytes"]},
        "physical_erasure_determined":False,
        "nvocmp_init_erasure_determined":False,
        "hardware_mutations":0
    }

if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old",required=True,type=Path)
    parser.add_argument("--new",required=True,type=Path)
    args=parser.parse_args()
    print(json.dumps(audit(args.old,args.new),sort_keys=True,indent=2))
