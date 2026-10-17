#!/usr/bin/env python3
"""Read-only B1/B2 patch-path compatibility inspection, never integration proof.

Uses sealed B0 as common ancestor. B1 remains a DRAFT PR: this check must
not merge, flash, edit B1, or assert HOLD_NV/HOLD_SECURITY safety.
"""
import argparse
import json
import subprocess
from pathlib import Path

BASE="1baefbee8e4de2c9d28c5e1a7c339cf2025a2afe"
B1_REQUIRED={
    "firmware/slzb-06p7u/r4/b1/b1_admission.c",
    "firmware/slzb-06p7u/r4/b1/b1_admission.h",
    "firmware/slzb-06p7u/r4/b1/tools/apply_b1.py",
}
class CompatibilityError(ValueError):pass

def check_paths(b1_paths,b2_paths):
    if not B1_REQUIRED.issubset(b1_paths):
        raise CompatibilityError("B1 expected hold/admission source not in sibling change set")
    overlap=sorted(b1_paths & b2_paths)
    if overlap:
        raise CompatibilityError("B1/B2 overlapping repo paths: "+str(overlap))
    return {
        "status":"B1_DRAFT_B2_PATHS_DISJOINT_NOT_INTEGRATED",
        "b1_changed_paths":sorted(b1_paths),
        "b2_changed_paths":sorted(b2_paths),
        "overlap_paths":[],
        "structural_imported_sdk_conflicts":"NOT_TESTED",
        "RF_HOLD_NV_SECURITY_GATE":"NOT_TESTED",
        "combined_CCS_link":"NOT_TESTED",
        "B1_SOURCE_READY":False,"B2_SOURCE_READY":False,
        "B1_B2_INTEGRATED_READY":False,
        "physical_verified":False,
    }

def inspect(repo,ref):
    def git(*args):
        return subprocess.check_output(["git","-C",str(repo),*args],text=True).strip()
    a=git("rev-parse",BASE)
    if a!=BASE:raise CompatibilityError("sealed B0 commit unavailable")
    b1sha=git("rev-parse",ref)
    b2sha=git("rev-parse","HEAD")
    for sha in (b1sha,b2sha):
        if subprocess.run(["git","-C",str(repo),"merge-base","--is-ancestor",BASE,sha],
                          capture_output=True).returncode!=0:
            raise CompatibilityError("B1 or B2 does not descend from sealed B0")
    def paths(sha):
        raw=git("diff","--name-status",BASE,sha)
        out=set()
        for line in raw.splitlines():
            cells=line.split("\t")
            if len(cells)!=2 or cells[0] not in ("A","M"):
                raise CompatibilityError("unreviewed B1/B2 deletion/rename/conflict: "+line)
            out.add(cells[1])
        return out
    result=check_paths(paths(b1sha),paths(b2sha))
    result.update({"b0_sha":BASE,"b1_pr_number":93,
                   "b1_sha":b1sha,"b2_sha":b2sha})
    return result

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--repo",type=Path,default=Path("."))
    parser.add_argument("--b1-ref",required=True)
    parser.add_argument("--out",type=Path,required=True)
    args=parser.parse_args()
    try:
        receipt=inspect(args.repo,args.b1_ref)
    except (CompatibilityError,OSError,subprocess.CalledProcessError) as exc:
        parser.exit(2,"B2-B1-PATHS-BLOCKED: "+str(exc)+"\n")
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"status":receipt["status"],"b1_sha":receipt["b1_sha"],
                      "b2_sha":receipt["b2_sha"]}))

if __name__=="__main__":main()
