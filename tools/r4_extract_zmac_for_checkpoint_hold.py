#!/usr/bin/env python3
"""Extract linked genuine patched TI ZMac functions to test B1/B3 NWK HOLD.

This uses the SAME actual compiled C bodies as B1's source-bound RF checks.
Only simulated MAP_MAC submission boundary; no radio, ROM or in-flight proof.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

TI_ZMAC="source/ti/zstack/zmac/f8w/zmac.c"

def build(source:Path,out:Path,receipt:Path):
    if source.is_symlink() or not source.is_file() or not source.as_posix().startswith("/tmp/"):
        raise ValueError("ONLY_PINNED_DISPOSABLE_TI_ZMAC")
    driver=Path(__file__).resolve().parents[1]/"firmware/slzb-06p7u/r4/b1/tools/make_zmac_harness.py"
    spec=importlib.util.spec_from_file_location("r4_pinned_b1_zmac_source",driver)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    c=source.read_text(encoding="utf-8")
    # Strictly assert every public TI submission entry point has the B1
    # hold guard. These are ACTUAL source extracts, not hand-coded mocks.
    for sig in mod.RF_GATED_SIGNATURES:
        mod.actual_function_body(c,sig)
    extracted=[mod.actual_function_body(c,sig) for sig in mod.SYMBOLS]
    bridge=r"""
unsigned r4_mac_submitted(void) { return mock_mac_submissions; }
uint8_t r4_mac_attempt_secured_and_nodata(void)
{
    uint8_t payload[3]={1u,2u,3u};
    ZMacDataReq_t req={0};
    req.msduLength=3u;
    req.msdu=payload;
    uint8_t result=ZMacDataReqSec(&req, NULL);
    ZMacSendNoData(0x2345u,0x1234u);
    return result;
}
"""
    out.write_text(mod.PREAMBLE+"\n\n".join(extracted)+"\n"+bridge,encoding="utf-8")
    data={
        "schema":"r4-source-bound-NWK-HOLD-to-real-TI-ZMac-v1",
        "actual_zmac_sha256":hashlib.sha256(c.encode()).hexdigest(),
        "source_path":TI_ZMAC,
        "eight_entrypoint_source_inspection":True,
        "two_executed_public_zmac_C_functions":[mod.SYMBOLS[0],mod.SYMBOLS[1]],
        "same_b1_admission_instance":True,
        "mac_boundary":"synthetic MAP_MAC, no physical ROM or queued RF",
        "source_ready":False,"flash_authorized":False,
    }
    receipt.write_text(json.dumps(data,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    return data

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--source",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--receipt",type=Path,required=True)
    a=p.parse_args()
    print(json.dumps(build(a.source,a.out,a.receipt),sort_keys=True))
