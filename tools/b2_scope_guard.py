#!/usr/bin/env python3
"""Independent static ownership/secret-path audit for the B2 Git patch.

Does not claim source-route correctness. It prevents B2 from quietly editing
B1/B3-owned files, packaged firmware, NV/CCFG or UART implementation.
"""
import argparse
import json
import re
import subprocess
from pathlib import Path

B0="1baefbee8e4de2c9d28c5e1a7c339cf2025a2afe"
ALLOWED_EXACT=frozenset({
    ".github/workflows/test-r4-b0-native.yml",
})
ALLOWED_PREFIXES=(
    "docs/r4/b2/",
    "firmware/slzb-06p7u/r4/b2/",
)
ALLOWED_PATTERNS=(
    re.compile(r"^tools/b2_[a-z0-9_]+\.py$"),
    re.compile(r"^tests/test_r4_b2_[a-z0-9_]+\.py$"),
    re.compile(r"^\.github/workflows/test-r4-b2-[a-z0-9-]+\.yml$"),
)
FORBIDDEN_SUFFIXES=(".bin",".hex",".out",".elf",".zip",".key",".pem",".p12")
REVIEW_LANES={
    "nwk_source":"All B2 files and issue context are source-owned; no private TI core patched",
    "mac_npi_boundary":"No B0 UART/NPI/MT/RF ownership file mutation; boundary stubs only in host tools",
    "memory_security":"No B1 NV/APS/TCLK/security, CCFG or physical firmware blob mutation",
    "blind_spot_challenger":"Mutation tests and fail-closed comparison are required independently; not a model review",
}
class ScopeError(ValueError):pass

def allowed(path):
    return path in ALLOWED_EXACT or any(path.startswith(p) for p in ALLOWED_PREFIXES) or any(p.fullmatch(path) for p in ALLOWED_PATTERNS)

def evaluate(entries):
    if not entries:raise ScopeError("no branch changes since B0 ancestor")
    issues=[]
    accepted=[]
    for status,path in entries:
        if not isinstance(path,str) or not path or path.startswith("/") or ".." in Path(path).parts:
            issues.append({"path":path,"reason":"invalid relative path"});continue
        if status not in ("A","M"):
            issues.append({"path":path,"reason":"deletion/rename/conflict not authorized"});continue
        if not allowed(path):
            issues.append({"path":path,"reason":"not B2 owned (B1/B3/B0 protection)"});continue
        if path.endswith(FORBIDDEN_SUFFIXES):
            issues.append({"path":path,"reason":"firmware/secret artifact forbidden"});continue
        accepted.append(path)
    return {
        "status":"B2_SCOPE_ACCEPTED" if not issues else "B2_SCOPE_REJECTED",
        "b0_sha":B0,"allowed_changed_files":accepted,
        "rejected":issues,
        "lanes":REVIEW_LANES,
        "independent_human_or_model_reviews":"NOT_ATTESTED",
        "physical_verified":False,
        "B2_SOURCE_READY":False,
    }

def run(root):
    def git(*args):
        return subprocess.check_output(["git","-C",str(root),*args],text=True).strip()
    head=git("rev-parse","HEAD")
    b0=git("rev-parse",B0)
    if b0!=B0:raise ScopeError("sealed B0 SHA mismatch")
    if subprocess.run(["git","-C",str(root),"merge-base","--is-ancestor",B0,head]).returncode!=0:
        raise ScopeError("B2 does not descend from sealed B0")
    data=git("diff","--name-status","--diff-filter=ACDMRT",B0,head)
    changes=[]
    for ln in data.splitlines():
        fields=ln.split("\t")
        if len(fields)!=2:
            raise ScopeError("renamed/unexpected B0 diff syntax: "+ln)
        changes.append(tuple(fields))
    evidence=evaluate(changes)
    if evidence["status"]!="B2_SCOPE_ACCEPTED":
        raise ScopeError("out of scope changes: "+str(evidence["rejected"]))
    evidence["head_sha"]=head
    return evidence

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--repo",type=Path,default=Path("."))
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    try:
        receipt=run(a.repo)
    except (ScopeError,subprocess.CalledProcessError,OSError) as e:
        p.exit(2,"B2-OWNER-SCOPE-BLOCKED: "+str(e)+"\n")
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"status":receipt["status"],"count":len(receipt["allowed_changed_files"]),
                      "head_sha":receipt["head_sha"]}))

if __name__=="__main__":main()
