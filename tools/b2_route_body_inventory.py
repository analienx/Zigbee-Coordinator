#!/usr/bin/env python3
"""Audit availability of routing C bodies in pinned public TI SDK checkout.

Occurrences in headers/calls are NOT a function implementation. This conservative
scan reports candidate C definitions, not proof of their reachability/linkage.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

from b2_source_evidence import SDK_SHA, validate_pin

ROUTING = (
    "RTG_Init", "RTG_GetRtgEntry", "RTG_RemoveRtgEntry", "RTG_GetNextHop",
    "RTG_ProcessRreq", "RTG_ProcessRrep", "RTG_ProcessRrec",
    "RTG_ProcessRErr", "RTG_TimerEvent", "RTG_SrcGetNextHop",
    "RTG_ValidateSrcRtg", "RTG_GetRtgSrcEntry", "RTG_CheckRtStatus",
    "RTG_AddSrcRtgEntry_Guaranteed", "RTG_MTORouteReq",
    "RTG_RouteMaintanence", "nwkHandleBrokenRoute",
)
# Look for a function declaration/signature ending with a body opener. Cannot
# distinguish all macro-generated bodies; result remains a C-source candidate.
def body_matches(contents, symbol):
    pattern=re.compile(
        r"(?m)^\s*(?:static\s+|extern\s+|inline\s+)*"
        r"(?:[a-zA-Z_]\w*\s*[*\s]+){1,5}"
        +re.escape(symbol)+r"\s*\([^;{}]{0,750}\)\s*\{"
    )
    return [contents.count("\n",0,m.start())+1 for m in pattern.finditer(contents)]

def run(sdk, out):
    validate_pin(sdk, SDK_SHA)
    root=sdk/"source/ti/zstack"
    if not root.is_dir():
        raise ValueError("missing pinned Z-Stack source tree")
    paths=sorted(path for path in root.rglob("*")
                 if path.is_file() and path.suffix in (".c",".h",".inc",".cpp"))
    results={name:{"c_definitions":[],"c_references":[],"header_references":[]}
             for name in ROUTING}
    c_files=0
    for file in paths:
        rel=file.relative_to(sdk).as_posix()
        text=file.read_bytes().decode("utf-8",errors="replace")
        lines=text.splitlines()
        is_impl=file.suffix in (".c",".cpp")
        if is_impl:
            c_files+=1
        for name in ROUTING:
            expr=re.compile(r"\b"+re.escape(name)+r"\s*\(")
            matches=[i for i,line in enumerate(lines,1) if expr.search(line)]
            if not matches:
                continue
            digest=hashlib.sha256(file.read_bytes()).hexdigest()
            kind="c_references" if is_impl else "header_references"
            results[name][kind].extend({"path":rel,"line":i,"sha256":digest} for i in matches)
            if is_impl:
                for line in body_matches(text,name):
                    results[name]["c_definitions"].append(
                        {"path":rel,"line":line,"sha256":digest})
    known_no_body=[name for name,r in results.items() if not r["c_definitions"]]
    data={"status":"SOURCE_BODY_INVENTORY_NOT_LINKAGE_PROOF",
          "sdk_sha":SDK_SHA, "scanned_source_files":len(paths),
          "scanned_implementation_files":c_files,
          "symbols":results,"symbols_without_detected_public_C_body":known_no_body,
          "qualification":"A missing C body may be in binary-only TI libraries or macro-generated code; validate in native XML/map. No closed-function patch claim."}
    out.mkdir(parents=True,exist_ok=True)
    (out/"B2_ROUTE_BODY_AVAILABILITY.json").write_text(json.dumps(data,indent=2,sort_keys=True)+"\n")
    lines=["# Routing implementation availability, exact pinned TI 8.33",
           "",f"SDK: \`{SDK_SHA}\`.",
           f"Scanned {len(paths)} files, including {c_files} C/C++ files.",
           "**This is source availability, not an ELF call graph.**",
           "", "| Routing API | C-body candidates | C call/references |"]
    lines.append("| --- | ---: | ---: |")
    for sym,item in results.items():
        lines.append(f"| \`{sym}\` | {len(item['c_definitions'])} | {len(item['c_references'])} |")
    lines+=["","Functions with no detected C body in the pinned public source:",
            *[f"- \`{name}\`" for name in known_no_body],
            "",
            "**Critical gate:** if routing internals are present only as TI precompiled"
            " libraries, B2 must not claim direct-source changes or compiled-source"
            " hostile tests on those unavailable bodies. Scope may be restricted to"
            " real source-owned arrays/config/host-visible behavior, or require an"
            " alternate legally available donor plus a new reviewed ADR.",
            "Confirm actual supplying archives/objects from native linker XML/map.",
            ""]
    (out/"ROUTING_BODY_AVAILABILITY.md").write_text("\n".join(lines),encoding="utf-8")
    print(json.dumps({"source_scanned":len(paths),"C_files":c_files,
                      "without_body":len(known_no_body)}))
    return data

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--sdk",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    run(a.sdk,a.out)

if __name__=="__main__":
    main()
