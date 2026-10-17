#!/usr/bin/env python3
"""P3 must FAIL at the real TI linker for SRAM excess, not at compilation.

A GitHub Actions job executing CCS can record PASS only when native link
diagnostics prove SRAM placement failed on the deliberate >SRAM .bss.
"""
import argparse
import json
import re
from pathlib import Path

class P3ValidationError(ValueError):pass

def validate(log, exit_code, injection):
    if exit_code == 0:
        raise P3ValidationError("P3 unexpectedly linked; negative control escaped")
    if injection.get("expected")!="TI_LINKER_SRAM_OVERFLOW_NOT_CPP_OR_COMPILER_ERROR":
        raise P3ValidationError("not the pinned disposable SRAM bomb")
    if injection.get("requested_bss_bytes") != 0x24000 or injection.get("sram_region_bytes")!=0x24000:
        raise P3ValidationError("invalid linker counterexample capacity")
    if injection.get("sdk_sha")!="3615ad5d3f4f271258d18a2f5ce1785064ff9a58":
        raise P3ValidationError("TI SDK pin mismatch")
    if injection.get("source_inputs_modified_only_in_throwaway_sdk") is not True:
        raise P3ValidationError("negative control source safety not established")
    if not re.search(r"Invoking:\s*Arm Linker",log):
        raise P3ValidationError("CCS linker never executed")
    if not re.search(r"(?:error\s*#10099-D:|error\s*#10099:)[\s\S]{0,240}?program will not fit into available\s+memory",log,re.I):
        raise P3ValidationError("missing genuine TI memory placement diagnostic #10099")
    # A real #10099 on FLASH or CCFG is not an SRAM-overbudget success.
    # Bind the *same TI diagnostic* to the CC2652P7 SRAM geometry, rather
    # than accepting a stray "SRAM" reference elsewhere in the compiler log.
    if not re.search(r"error\\s*#10099-D:[\\s\\S]{0,500}?Available memory ranges:\\s*SRAM\\s+size:\\s*0x24000\\b",log,re.I):
        raise P3ValidationError("failure not demonstrated in SRAM placement")
    # TI Clang reports the linker failure twice: the real #10099-D from
    # tiarmlnk, then its own expected "tiarmlnk command failed" wrapper.
    # Reject ALL OTHER compiler diagnostics, including nonexistent files,
    # undefined symbols, and C semantic errors; do not mistake a wrapper
    # around a genuine linker error for a separate failure.
    for line in log.splitlines():
        if re.search(r"tiarmclang:\s*error:",line,re.I):
            if not re.search(r"tiarmclang:\s*error:\s*tiarmlnk command failed with exit code 1",line,re.I):
                raise P3ValidationError("non-memory compiler/link error contaminates negative control")
    if re.search(r"no such file or directory|undefined symbol|unresolved symbols|error:\s*expected expression",log,re.I):
        raise P3ValidationError("non-memory compiler/link error contaminates negative control")
    return {
        "status":"HOSTED_NATIVE_LINKER_OVERBUDGET_REJECTED",
        "reason":"TI_CLANG_CCS_ERROR_10099_SRAM_EXHAUSTION",
        "linker_exit_status":exit_code,"sram_bytes":0x24000,
        "test_only_bss_bytes":0x24000,
        "usable_firmware_produced":False,
        "TI_SDK_PIN":injection["sdk_sha"],
        "physical_verified":False,
        "B2_SOURCE_READY":False,
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--build-log",type=Path,required=True)
    p.add_argument("--injection",type=Path,required=True)
    p.add_argument("--exit-code",type=int,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    if not a.build_log.is_file() or a.build_log.stat().st_size>20*1024*1024:
        p.exit(2,"B2-P3-BLOCKED: no actual native build log\n")
    try:
        result=validate(a.build_log.read_text(errors="replace"),a.exit_code,json.loads(a.injection.read_text()))
    except (P3ValidationError,OSError,ValueError) as err:
        p.exit(2,"B2-P3-BLOCKED: "+str(err)+"\n")
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(json.dumps(result,sort_keys=True))

if __name__=="__main__":main()
