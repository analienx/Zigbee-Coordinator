#!/usr/bin/env python3
"""Extract genuine composed TI ZDApp_SaveNwkKey C body for cross-phase HOST tests.

Run after immutable B1/B3/B2/B4 source stage in throwaway TI SDK. Real TI
function under test; only NV/SSP, IRQ, and RF boundary are simulated.
No physical device, keys, radio, reset, or release authority.
"""
import argparse
import hashlib
import json
from pathlib import Path

NAME="void ZDApp_SaveNwkKey( void )"
TI="source/ti/zstack/stack/zdo/zd_app.c"
REQUIRED=(
    "if (b1_nv_runtime_hold_active()) return;",
    "b1_security_runtime_hold_latch();",
    "if (nwkSecMaterialDesc.FrameCounter > keyItems.frameCounter)",
    "A populated foreign PAN is not disposable counter storage",
    "OsalPort_memcmp(nwkSecMaterialDesc.extendedPanID,",
    "osal_nv_write_ex(",
    "osal_nv_read_ex(",
    "osal_nv_write(ZCD_NV_NWKKEY",
    "osal_nv_read(ZCD_NV_NWKKEY",
)
def take(c):
    anchor=NAME+"\n{"
    if c.count(anchor)!=1:raise ValueError("actual TI save definition not unique")
    start=c.index(anchor);opening=start+len(NAME)+1;depth=0
    for i in range(opening,len(c)):
        if c[i]=="{":depth+=1
        elif c[i]=="}":
            depth-=1
            if depth==0:return c[start:i+1]
    raise ValueError("unbalanced TI save function")
def extract(path,output,receipt):
    if path.is_symlink() or not path.is_file():
        raise ValueError("untrusted source path")
    raw=path.read_bytes();c=take(raw.decode("utf-8"))
    for marker in REQUIRED:
        if marker not in c:raise ValueError("B1+B3 fused source C HOLD marker missing "+marker)
    if c.count("if (nwkSecMaterialDesc.FrameCounter > keyItems.frameCounter)")!=2:
        raise ValueError("both active and generic persisted floors required")
    if c.count("b1_security_runtime_hold_latch();")<4:
        raise ValueError("B1 HOLD missing from original security checkpoints")
    output.write_text('#include "b3_nwk_stub.h"\n#include "b1_management.h"\n'
                      'extern int b1_nv_runtime_hold_active(void);\n'
                      +c+"\n",encoding="utf-8")
    result={"schema":"r4-actual-TI-B1-B3-NWK-save-HOLD-source-v1",
            "source":TI,"patched_ti_zdo_sha256":hashlib.sha256(raw).hexdigest(),
            "extracted_c_sha256":hashlib.sha256(c.encode()).hexdigest(),
            "all_end_to_end_RF_covered":False,"physical_verified":False,
            "flash_authorized":False}
    receipt.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(json.dumps(result,sort_keys=True))
if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--source",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    p.add_argument("--receipt",required=True,type=Path)
    a=p.parse_args();extract(a.source,a.out,a.receipt)
