#!/usr/bin/env python3
"""Fail-closed proof NVOCMP driver actually compiles for 5 physical 8KiB pages.

ELF+MAP layout independently validated by nv5_verify_linked.py. This auditor
proves the matching SDK8.32 *compiled NVOCMP source option* and actual TI
SysConfig-generated internal NVS driver HWAttrs. Pure offline inspection.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

EXPECTED_PAGES=5
EXPECTED_REGION=0xA000
EXPECTED_ORIGIN=0xA4000
MATCHING_NV5_STATUS="NV5_NATIVE_ELF_HEX_LINKER_GEOMETRY_PASS"
PASS="G3_NV5_EFFECTIVE_NVOCMP_AND_NVS_DRIVER_PASS"

def require(value:bool,error:str)->None:
    if not value:raise ValueError(error)

def check_generated_config(text:str)->dict:
    r=re.findall(
        r"static\s+const\s+NVSCC26XX_HWAttrs\s+nvsCC26XXHWAttrs\[1\]\s*=\s*\{(.*?)\n\};",
        text,re.S)
    require(len(r)==1,"EXPECTED_ONE_INTERNAL_NVSCC26XX_HWATTRS")
    block=r[0]
    bases=re.findall(r"\.regionBase\s*=\s*\(void\s*\*\)\s*(\w+)",block)
    sizes=re.findall(r"\.regionSize\s*=\s*(0x[0-9a-fA-F]+|\d+)",block)
    require(bases==["flashBuf0"],"INTERNAL_DRIVER_NOT_LINKER_FLASHBUF0")
    require(len(sizes)==1 and int(sizes[0],0)==EXPECTED_REGION,
            "GENERATED_INTERNAL_NV_NOT_FIVE_PAGES")
    count=re.findall(r"#define\s+CONFIG_NVS_COUNT\s+(\d+)",text)
    require(count==["2"],"TI_REFERENCE_NVS_DRIVER_COUNT_CHANGED")
    return {"internal_driver_flash_symbol":"flashBuf0",
            "internal_driver_region_size_bytes":EXPECTED_REGION,
            "nv_pages":EXPECTED_PAGES}

def check_nv_compiler(log:str)->dict:
    # Attribute the macro to the actual nvocmp.c compilation invocation,
    # rather than accepting a summary mention or some unrelated TU's -D.
    commands=[line for line in log.splitlines() if
              "source/ti/common/nv/nvocmp.c" in line and
              "tiarmclang" in line and "-c " in line]
    require(len(commands)==1,"MISSING_OR_AMBIGUOUS_NVOCMP_C_COMPILE_COMMAND")
    options=commands[0]
    require("-DNVOCMP_NVPAGES=5" in options,
            "NVOCMP_ACTUAL_COMPILE_NOT_FIVE_PAGES")
    require("-DNVOCMP_NVPAGES=2" not in options,
            "INCONSISTENT_OR_DUAL_NV_DEFINE")
    require('"-o' in options or ' -o' in options,
            "NOT_NATIVE_COMPILE_COMMAND")
    link=[line for line in log.splitlines() if
          "NVOCMP_NVPAGES=5" in line and
          "--define=NVOCMP_NVPAGES=5" in line]
    require(len(link)>=1,"LINKER_NVOCMP_MACRO_NOT_EFFECTIVE")
    return {"nvocmp_c_compiled_with_pages":5,
            "linker_nvocmp_define":5,
            "compiler_command_sha256":hashlib.sha256(options.encode()).hexdigest()}

def check_linked_proof(proof:dict)->None:
    require(proof["status"]==MATCHING_NV5_STATUS,"LINKED_PROOF_NOT_PASSED")
    require(proof["nv_reserved_bytes"]==EXPECTED_REGION,"LINKED_NV_MISMATCH")
    require(proof["nv_region_start"]==hex(EXPECTED_ORIGIN),"LINKED_NV_BASE_MISMATCH")
    require(proof["nv_image_loaded_bytes"]==0,"INITIALIZED_NV_DATA_FOUND")
    require(proof["flash_authorized"] is False,"FLASH_AUTHORIZED")

def audit(config:str,log:str,proof:dict)->dict:
    a=check_generated_config(config)
    b=check_nv_compiler(log)
    check_linked_proof(proof)
    return {"status":PASS,"source_scope":"TI LP_CC1352P7_4 not SMLIGHT board",
            "compiled_driver":b,"generated_internal_nvs":a,
            "linked_nv_bytes":proof["nv_reserved_bytes"],
            "nv_base":proof["nv_region_start"],
            "nv_migration_qualified":False,
            "runtime_nv_compaction_qualified":False,
            "flash_authorized":False,
            "smlight_board_qualified":False}

def fixture()->tuple[str,str,dict]:
    config="""static const NVSCC26XX_HWAttrs nvsCC26XXHWAttrs[1] = {
     /* CONFIG_NVSINTERNAL */
     { .regionBase = (void *) flashBuf0, .regionSize = 0xa000 },
};
#define CONFIG_NVS_COUNT 2"""
    log=(
        '"/opt/ti/bin/tiarmclang" -c -DNVOCMP_NVPAGES=5 -o"nvocmp.o" '
        '"/sdk/source/ti/common/nv/nvocmp.c"\n'
        '"/opt/ti/bin/tiarmclang" --define=NVOCMP_NVPAGES=5 znp.o\n')
    proof={"status":MATCHING_NV5_STATUS,"nv_reserved_bytes":EXPECTED_REGION,
           "nv_region_start":"0xa4000","nv_image_loaded_bytes":0,
           "flash_authorized":False}
    return config,log,proof

def selftest()->None:
    a,b,c=fixture()
    require(audit(a,b,c)["status"]==PASS,"POSITIVE_GENERATED_AND_COMPILER_PROOF")
    negatives=[
        (a.replace("0xa000","0x4000"),b,c),
        (a.replace("flashBuf0","flashBuf1"),b,c),
        (a.replace("NVS_COUNT 2","NVS_COUNT 1"),b,c),
        (a.replace("nvsCC26XXHWAttrs[1]","nvsCC26XXHWAttrs[2]"),b,c),
        (a,b.replace("-DNVOCMP_NVPAGES=5","-DNVOCMP_NVPAGES=2",1),c),
        (a,b.replace("common/nv/nvocmp.c","common/nv/other.c"),c),
        (a,b.replace("--define=NVOCMP_NVPAGES=5","--define=NVOCMP_NVPAGES=2"),c),
        (a,b,{**c,"nv_reserved_bytes":0x4000}),
        (a,b,{**c,"nv_region_start":"0xaa000"}),
        (a,b,{**c,"nv_image_loaded_bytes":1}),
        (a,b,{**c,"flash_authorized":True}),
    ]
    for i,args in enumerate(negatives):
        try:audit(*args)
        except (ValueError,KeyError):continue
        raise AssertionError(f"NV5_EFFECTIVE_CONTROL_{i}_ACCEPTED")
    print(f"PASS G3 NV5 effective compile/HWAttrs cross-check; {len(negatives)} failures rejected")

def main()->None:
    p=argparse.ArgumentParser()
    for field in ("generated","compiler-log","linked-proof","out"):
        p.add_argument("--"+field,type=Path)
    p.add_argument("--selftest",action="store_true")
    a=p.parse_args()
    if a.selftest:selftest()
    if a.generated or a.compiler_log or a.linked_proof or a.out:
        require(bool(a.generated and a.compiler_log and a.linked_proof and a.out),
                "NEED_ALL_INPUTS")
        result=audit(a.generated.read_text(encoding="utf-8"),
                     a.compiler_log.read_text(encoding="utf-8",errors="replace"),
                     json.loads(a.linked_proof.read_text()))
        result["inputs_sha256"]={
            "generated":hashlib.sha256(a.generated.read_bytes()).hexdigest(),
            "compiler_log":hashlib.sha256(a.compiler_log.read_bytes()).hexdigest(),
            "linked_proof":hashlib.sha256(a.linked_proof.read_bytes()).hexdigest(),
        }
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
        print(json.dumps(result,indent=2))
if __name__=="__main__":
    main()
