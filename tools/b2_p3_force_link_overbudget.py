#!/usr/bin/env python3
"""Disposable ONLY genuine TI CCS P3 SRAM-overbudget negative control.

Change two already source-owned C files inside /tmp/b0src SDK checkout:
declare >144KiB volatile BSS in nwk_globals.c and force a reference from
main().  The only acceptable outcome is the *actual TI linker* rejecting
SRAM placement.  No usable P3 firmware or modified persisted flash files.
"""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

SDK_SHA="3615ad5d3f4f271258d18a2f5ce1785064ff9a58"
BOMB_BYTES=0x24000  # consumes ALL 144-KiB P7 SRAM before stacks/other globals
MARK="b2_p3_forced_overbudget_sram"

class P3Error(ValueError):pass

def run(sdk,receipt):
    if sdk.name!="cc13xx_cc26xx_sdk" or sdk.is_symlink():
        raise P3Error("P3 only permitted in ephemeral checked-out SDK")
    if "/tmp/b0src/" not in (sdk.resolve().as_posix()+"/"):
        raise P3Error("refuse non-disposable SDK path")
    observed=subprocess.check_output(["git","-C",str(sdk),"rev-parse","HEAD"],text=True).strip()
    if observed!=SDK_SHA:
        raise P3Error("TI SDK commit pin mismatch")
    c_paths=("source/ti/zstack/stack/nwk/nwk_globals.c",
             "source/ti/zstack/startup/main.c")
    originals={}
    for relative in c_paths:
        f=sdk/relative
        if f.is_symlink() or not f.is_file():
            raise P3Error("missing or symlinked exact C file")
        actual=f.read_bytes()
        pristine=subprocess.check_output(["git","-C",str(sdk),"show","HEAD:"+relative])
        if actual!=pristine or MARK.encode() in actual:
            raise P3Error("refuse edited/non-upstream input "+relative)
        originals[relative]=actual
    main=originals[c_paths[1]].decode("utf-8")
    matcher=re.compile(r"(?m)^int main\(\)\s*\{")
    if len(matcher.findall(main))!=1:
        raise P3Error("nonunique TI main() entry point")
    main=matcher.sub(
        "extern volatile unsigned char "+MARK+"[];\nint main()\n{\n"
        "    /* P3-only: linker must retain impossible .bss allocation. */\n"
        "    "+MARK+"[0] = 1;",main,count=1)
    nwk=originals[c_paths[0]].decode("utf-8")
    nwk+="\n/* B2-P3 ONLY: deliberate genuine CCS SRAM-overbudget negative control. */\n"
    nwk+="volatile unsigned char "+MARK+"["+str(BOMB_BYTES)+"];\n"
    (sdk/c_paths[0]).write_text(nwk,encoding="utf-8")
    (sdk/c_paths[1]).write_text(main,encoding="utf-8")
    data={
        "mode":"GITHUB_HOSTED_DISPOSABLE_NEGATIVE_LINK_ONLY",
        "requested_bss_bytes":BOMB_BYTES,"sram_region_bytes":0x24000,
        "sdk_sha":SDK_SHA,"source_sha256_before":{
            p:hashlib.sha256(b).hexdigest() for p,b in originals.items()},
        "source_sha256_after":{p:hashlib.sha256((sdk/p).read_bytes()).hexdigest()
                                  for p in originals},
        "source_inputs_modified_only_in_throwaway_sdk":True,
        "expected":"TI_LINKER_SRAM_OVERFLOW_NOT_CPP_OR_COMPILER_ERROR",
        "linked_image_available":False,
        "physical_qualified":False,
    }
    receipt.parent.mkdir(parents=True,exist_ok=True)
    receipt.write_text(json.dumps(data,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    return data

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--sdk",type=Path,required=True)
    p.add_argument("--receipt",type=Path,required=True)
    a=p.parse_args()
    print(json.dumps(run(a.sdk,a.receipt),sort_keys=True))

if __name__=="__main__":
    main()
