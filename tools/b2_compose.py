#!/usr/bin/env python3
"""Guarded, disposable CCS project compiler-options overlay for R4 B2.

Not a firmware installer. No production hardware. No TC/APS/TCLK/NV values
are touched. Input is the copied ZNP Stack/Config/znp_cnf.opts in a throwaway
GitHub-hosted CCS workspace. Verify the actual ELF counters afterward.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

PROFILES = {
    "P0": {},
    "P1": {"MAX_RTG_SRC_ENTRIES": 192,
           "MAX_NEIGHBOR_ENTRIES": 64,
           "MAX_RTG_ENTRIES": 128},
    # P3 uses identical valid route capacities to P1, plus a separate
    # deliberately impossible BSS allocation in ephemeral TI source.
    "P3": {"MAX_RTG_SRC_ENTRIES": 192,
           "MAX_NEIGHBOR_ENTRIES": 64,
           "MAX_RTG_ENTRIES": 128},
}
FORBIDDEN = ("ZDSECMGR_TC_DEVICE_MAX", "NWK_MAX_DEVICE_LIST",
             "NWK_MAX_DEVICES","MAX_DEVICE_TABLE_ENTRIES",
             "NVOCMP_NVPAGES","CONCENTRATOR_ENABLE",
             "CONCENTRATOR_DISCOVERY_TIME","CONCENTRATOR_ROUTE_CACHE",
             "SRC_RTG_EXPIRY_TIME", "NWK_MAX_DATA_RETRIES",
             "APSC_MAX_FRAME_RETRIES")
OVERLAY_MARKER = "-DMAX_RTG_SRC_ENTRIES=192"  # token-only idempotency sentinel; response files reject comments

class ComposeError(ValueError):
    pass

def compose(text, profile):
    if profile not in PROFILES:
        raise ComposeError("profile not approved: "+profile)
    if OVERLAY_MARKER in text:
        raise ComposeError("overlay already applied: fail closed")
    options=PROFILES[profile]
    if not options:
        return text, {}
    # Validate no compiler-defined duplicate exists anywhere in the original
    # options file (including a conflicting unrelated preexisting value).
    for name in options:
        if re.search(r"(?:^|\s)(?:-D|--define=)"+re.escape(name)+r"(?:=|\s|$)",text):
            raise ComposeError("existing project definition: "+name)
    # prohibit B2 profiles ever patching security/NV/MTO fields
    if set(options).intersection(FORBIDDEN):
        raise ComposeError("forbidden B1/B3 security or MTO change")
    for name,value in options.items():
        if type(value)!=int or not 1<=value<=255:
            raise ComposeError("unsafe index width for "+name)
    # TI Clang @response files are token streams; comments become compiler arguments.
    lines=[]
    lines.extend("-D"+name+"="+str(value) for name,value in sorted(options.items()))
    suffix="" if text.endswith("\n") else "\n"
    return text+suffix+"\n".join(lines)+"\n",options

def apply(opts, profile, receipt):
    if opts.name!="znp_cnf.opts" or "Stack/Config" not in opts.as_posix():
        raise ComposeError("only imported Stack/Config/znp_cnf.opts is permitted")
    if opts.is_symlink() or not opts.is_file() or opts.stat().st_size>250000:
        raise ComposeError("missing/untrusted CCS opts file")
    source=opts.read_bytes()
    text=source.decode("utf-8")
    changed,defs=compose(text,profile)
    before=hashlib.sha256(source).hexdigest()
    if defs:
        opts.write_text(changed,encoding="utf-8")
    after=hashlib.sha256(opts.read_bytes()).hexdigest()
    data={"status":"SOURCE_OVERLAY_APPLIED" if defs else "B0_UNCHANGED",
          "profile":profile,"original_sha256":before,"result_sha256":after,
          "compiler_defines":defs,
          "hosted_workspace_only":True,
          "tc_nv_security_mto_untouched":True,
          "native_linked_proof":"REQUIRED_POST_BUILD",
          "dynamic_memory_high_water":"UNKNOWN",
          "physical_radio":"NOT_TESTED"}
    receipt.parent.mkdir(parents=True,exist_ok=True)
    receipt.write_text(json.dumps(data,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    return data

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--opts",type=Path,required=True)
    p.add_argument("--profile",choices=sorted(PROFILES),required=True)
    p.add_argument("--receipt",type=Path,required=True)
    a=p.parse_args()
    try:
        print(json.dumps(apply(a.opts,a.profile,a.receipt),sort_keys=True))
    except (ComposeError,OSError,UnicodeError) as e:
        p.exit(2,"B2-COMPOSE-BLOCKED: "+str(e)+"\n")

if __name__=="__main__":
    main()
