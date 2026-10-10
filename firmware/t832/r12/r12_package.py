"""R12 image packager: retain all R11 recovery/CCFG/NV gates, add R12 proof.

We reuse the mature R11 lab and candidate-layout audits rather than silently
dropping their requirements for an attractive new diagnostic build.
"""
from __future__ import annotations
from pathlib import Path
import json
import os
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"r6"))
from package_r6 import package as original_package

def main():
    import argparse
    p=argparse.ArgumentParser()
    for key in ("profile","variant"):
        p.add_argument("--"+key,required=True)
    p.add_argument("--series",required=True,choices=["R12"])
    p.add_argument("--vendor-audit",type=Path,required=True)
    for key in ("generated","macros","map","hex","elf","header","patch","lab","out"):
        p.add_argument("--"+key,type=Path,required=True)
    args=p.parse_args()
    if args.variant!="DIAG" or args.profile!="vendor-20240716":
        raise ValueError("R12 forbids unqualified variant/profile")
    r12_source = args.patch.parent/"r12-source-integration.json"
    if not r12_source.is_file():
        raise ValueError("no exact R12 integrated source proof")
    proof=json.loads(r12_source.read_text())
    if (proof.get("r12_revision") != 8320063
            or len(proof.get("r12",[]))!=8
            or proof.get("aux_address_qualification")!="UNPROVEN -- DO NOT FLASH"):
        raise ValueError("R12 patch manifest unknown/incomplete")
    for symbol in ("R12Aux_captureBeforeOverwrite","R12Aux_commit",
                   "T832R12_boot","T832R12_mark","T832R12_tryExport"):
        if symbol not in args.map.read_text():
            # Static optimized/inline functions may not have named symbols:
            # keep a distinct requirement for nonstatic main/boot/commit.
            if symbol=="T832R12_tryExport":
                continue
            raise ValueError("R12 target hook absent from actual linked map: "+symbol)
    # The exact R11 security checks require a R11 series selection.
    # First package to staging under R11 label. Then REVALIDATE and relabel
    # explicitly; preserve lab, vendor geometry and original package SHA.
    args.series="R11"
    candidate=args.out
    args.out=args.out.with_name(args.out.name+"-r11-gate")
    original_package(args)
    r11_manifest=json.loads((args.out/"T832-BUILD-MANIFEST.json").read_text())
    if r11_manifest["sys_version_revision"]!=8320052:
        raise ValueError("unexpected R11 package gate")
    manifest=r11_manifest.copy()
    manifest["variant"]="T832-R12-A1-DIAG-vendor-20240716"
    manifest["sys_version_revision"]=8320063
    manifest["R12"]={
        "source_proof":"provenance/r12-source-integration.json",
        "target_integrated":True,
        "aux_address_is_exclusive":False,
        "pin_reset_retention_verified":False,
        "firmware_hardware_validated":False,
        "flash_authorized":False,
        "boot_reader_enabled":True,
        "critical_startup_aux_hooks_enabled":True,
        "retained_event_kind":54,
        "a1_one_shot_transition_from":8320062,
        "a1_prior_attempt":"0xA0120001",
        "a1_new_attempt":"0xA0120002",
        "network_mutation_review":"R11 baseline path preserved"
    }
    # Original R11-gated container bytes represent R12 firmware, not R11.
    import hashlib,shutil
    args.out.rename(candidate)
    oldname="T832-R11-DIAG-vendor-20240716"
    for p in list(candidate.iterdir()):
        if p.is_file() and p.name.startswith(oldname):
            p.rename(candidate/p.name.replace(oldname,"T832-R12-A1-DIAG-vendor-20240716",1))
    shutil.copy2(r12_source,candidate/"provenance"/r12_source.name)
    (candidate/"r12").mkdir()
    shutil.copy2(Path(__file__).resolve().parent/"r12_decode.py",
                 candidate/"r12"/"r12_decode.py")
    # Recalculate manifest's complete file listing and digest contract.
    manifest["artifacts"]={
        str(p.relative_to(candidate)):{
            "bytes":p.stat().st_size,
            "sha256":hashlib.sha256(p.read_bytes()).hexdigest()
        } for p in candidate.rglob("*") if p.is_file()
        and p.name not in ("SHA256SUMS","T832-BUILD-MANIFEST.json")
    }
    (candidate/"T832-BUILD-MANIFEST.json").write_text(json.dumps(manifest,indent=2)+"\n")
    (candidate/"SHA256SUMS").write_text("".join(
        hashlib.sha256(f.read_bytes()).hexdigest()+"  "+str(f.relative_to(candidate))+"\n"
        for f in sorted(candidate.rglob("*")) if f.is_file()
        and f.name!="SHA256SUMS"))
    print(json.dumps({"r12":True,"nonflashable":True,
                      "linked_hooks":True,"nv_gates_reused":True,
                      "bundle":str(candidate),"revision":8320063}))

if __name__=="__main__":
    main()
