#!/usr/bin/env python3
"""Compile real TI 8.33 guarded security transports and the TC seed derivation."""
import argparse
from pathlib import Path

SIGNATURES = (
    "ZStatus_t ZDSecMgrGenerateKeyFromSeed(uint8_t *extAddr, uint8_t shift, uint8_t *key)",
    "void ZDSecMgrTclkReq( ZDO_RequestKeyInd_t* ind )",
    "ZStatus_t ZDSecMgrSendNwkKey( ZDSecMgrDevice_t* device )",
)

def function_body(source, signature):
    if source.count(signature) != 1:
        raise ValueError("TI SDK signature missing/ambiguous: " + signature)
    start = source.index(signature)
    opening = source.index("{", start + len(signature))
    depth = 0
    for pos in range(opening, len(source)):
        depth += (source[pos] == "{") - (source[pos] == "}")
        if depth == 0:
            return source[start:pos+1]
    raise ValueError("Unbalanced TI source body")

def extract(source, header):
    bodies = [function_body(source, sig) for sig in SIGNATURES]
    if "osal_nv_read(ZCD_NV_TCLK_SEED, 0, SEC_KEY_LEN, tempKey) != SUCCESS" not in bodies[0]:
        raise ValueError("Missing TC seed read guard")
    if "ZDSecMgrGenerateKeyFromSeed(" not in bodies[1] or "!= ZSuccess" not in bodies[1]:
        raise ValueError("Missing TC transport denial")
    if "NLME_ReadNwkKeyInfo(" not in bodies[2] or "return ZFailure;" not in bodies[2]:
        raise ValueError("Missing NWK transport denial")
    decl="extern ZStatus_t ZDSecMgrGenerateKeyFromSeed(uint8_t *extAddr, uint8_t shift, uint8_t *key);"
    if header.count(decl) != 1:
        raise ValueError("Public TI header mismatch")
    return '#include "b3_transport_stub.h"\n' + "\n\n".join(bodies) + "\n"

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--sdk-stack", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    a.out.write_text(extract(
        (a.sdk_stack / "zdo/zd_sec_mgr.c").read_text(),
        (a.sdk_stack / "zdo/zd_sec_mgr.h").read_text()))
    print("B3_EXACT_TI_TC_SEED_AND_NWK_TRANSPORT_FUNCTIONS_EXTRACTED")
