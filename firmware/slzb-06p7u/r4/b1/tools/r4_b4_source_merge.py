#!/usr/bin/env python3
"""Conflict-denying B1 + B4 NPI/UART source merge (disposable TI SDK only).

Never silently choose one side of an overlapping native C edit. This is a
line-level three-way application of exact original TI -> pinned B4 differences
onto the already patched B1 source, with unique unchanged context for EVERY
change. Ambiguous/conflicting source fails closed. No live device/serial.
"""
import argparse
import difflib
import hashlib
import json
import subprocess
from pathlib import Path

PIN_TI="3615ad5d3f4f271258d18a2f5ce1785064ff9a58"
PATHS=(
    "source/ti/zstack/mt/mt_sys.c",
    "source/ti/zstack/npi/npi_task.c",
    "source/ti/zstack/npi/npi_tl_uart.c",
)

def unique_occurrence(source, needle):
    """str.count misses OVERLAPPING duplicates; find the next start instead."""
    first=source.find(needle)
    return first>=0 and source.find(needle,first+1)<0

def merge_lines(original, b1, b4):
    if original==b4:
        return b1, []
    if original==b1:
        return b4, [{"mode":"UNMODIFIED_B1","lines":len(b4.splitlines())}]
    a=original.splitlines(keepends=True)
    c=b4.splitlines(keepends=True)
    ops=[t for t in difflib.SequenceMatcher(
        None,a,c,autojunk=False).get_opcodes() if t[0]!="equal"]
    text=b1
    receipts=[]
    for mode, i1,i2,j1,j2 in reversed(ops):
        replacement="".join(c[j1:j2])
        matched=False
        # Prefer narrow context but demand unique, byte-exact original anchors.
        # Any B1 insertion in the same block MUST be consciously reconciled.
        for context in (3,5,8,13,20):
            left="".join(a[max(0,i1-context):i1])
            right="".join(a[i2:min(len(a),i2+context)])
            target="".join(a[i1:i2])
            needle=left+target+right
            # The ORIGINAL donor must also identify this hunk uniquely.
            # SequenceMatcher may otherwise align a repeated line at an
            # arbitrary later occurrence and incorrectly call it disjoint.
            if not needle or not unique_occurrence(original, needle) or not unique_occurrence(text, needle):
                continue
            text=text.replace(needle,left+replacement+right,1)
            receipts.append({"mode":mode,"source_start_line":i1+1,
                             "source_end_line":i2,"original_bytes":len(target),
                             "replacement_bytes":len(replacement),
                             "context_lines":context})
            matched=True
            break
        if not matched:
            raise ValueError(
                f"R4_B1_B4_ACTUAL_SOURCE_OVERLAP_OR_AMBIGUITY "
                f"{mode} at TI lines {i1+1}..{i2}; "
                f"B4 source fragment={replacement[:130]!r}")
    if not receipts or text==b1:
        raise ValueError("R4_B1_B4_NO_INSTRUMENTATION_INTEGRATED")
    return text, list(reversed(receipts))

def git(repo,*args):
    return subprocess.check_output(
        ["git","-C",str(repo),*args],text=True).strip()

def apply(sdk, b4_sdk, receipt):
    sdk=Path(sdk).resolve();b4_sdk=Path(b4_sdk).resolve()
    if not sdk.is_relative_to(Path("/tmp")) or not b4_sdk.is_relative_to(Path("/tmp")):
        raise ValueError("R4 B4 only in disposable /tmp SDK source")
    if git(sdk,"rev-parse","HEAD")!=PIN_TI or git(b4_sdk,"rev-parse","HEAD")!=PIN_TI:
        raise ValueError("R4 B4 TI SDK provenance mismatch")
    stages={}
    results={}
    for name in PATHS:
        original=subprocess.check_output(
            ["git","-C",str(sdk),"show",PIN_TI+":"+name])
        b1=(sdk/name).read_bytes();b4=(b4_sdk/name).read_bytes()
        if name.endswith("mt_sys.c") and b1!=original:
            raise ValueError("B1 owns F1 in mt.c; unexpected SYS command source collision")
        if name.endswith("mt_sys.c") and (
                b"case 0xF0:" not in b4 or b"case 0xF2:" not in b4):
            raise ValueError("B4 F0 F2 dispatch not present")
        if name.endswith("npi_task.c") and b"B4_V4BootInitialize" not in b4:
            raise ValueError("B4 F2 boot initialization missing")
        merged, hunks=merge_lines(
            original.decode("utf-8"),b1.decode("utf-8"),b4.decode("utf-8"))
        if name.endswith("npi_task.c"):
            for needle in ("b1_management_transport_failed","B4_NpiSrspDepth",
                           "B4_V4BootInitialize"):
                if needle not in merged:
                    raise ValueError("B1 or B4 NPI source feature lost: "+needle)
        if name.endswith("npi_tl_uart.c"):
            for needle in ("B4_NpiUartTxFinishedCallback","b1_management_transport_failed"):
                if needle not in merged:
                    raise ValueError("B1 or B4 UART feature lost: "+needle)
        stages[name]=merged
        results[name]={"ti_sha256":hashlib.sha256(original).hexdigest(),
                       "b1_sha256":hashlib.sha256(b1).hexdigest(),
                       "b4_sha256":hashlib.sha256(b4).hexdigest(),
                       "merged_sha256":hashlib.sha256(merged.encode()).hexdigest(),
                       "strict_context_hunks":hunks}
    # Every preimage, three-way conflict and source invariant is checked before
    # a single workspace write; never mutate installed coordinator/host.
    if Path(receipt).resolve().is_relative_to(sdk):
        raise ValueError("receipt may not overwrite native SDK")
    for name, merged in stages.items():
        (sdk/name).write_text(merged,encoding="utf-8",newline="")
    receipt=Path(receipt)
    receipt.parent.mkdir(parents=True,exist_ok=True)
    data={"schema":"r4-b1-b4-source-merge-v1",
          "ti_original_sha":PIN_TI,
          "merging":"STRICT_THREE_WAY_UNIQUE_ORIGINAL_CONTEXT_NO_SILENT_CONFLICTS",
          "files":results,"source_ready":False,"flash_authorized":False,
          "physical_verified":False,"linked_elf_proof":"REQUIRED"}
    receipt.write_text(json.dumps(data,indent=2,sort_keys=True)+"\n")
    return data

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--b1-sdk",type=Path,required=True)
    p.add_argument("--b4-sdk",type=Path,required=True)
    p.add_argument("--receipt",type=Path,required=True)
    a=p.parse_args()
    data=apply(a.b1_sdk,a.b4_sdk,a.receipt)
    print("R4_B1_B4_STRICT_SOURCE_MERGE_ONLY: "+str(len(data["files"]))+" TI files; NOT FLASHABLE")
if __name__=="__main__":main()
