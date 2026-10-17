#!/usr/bin/env python3
"""Compile pinned TI NWK security save/restore bodies, never replacement stubs."""
import argparse
from pathlib import Path
import hashlib

SIGNATURES = (
    "void ZDApp_SaveNwkKey( void )",
    "void ZDApp_RestoreNwkSecMaterial(void)",
)

def extract(source):
    output = ['#include "b3_nwk_stub.h"']
    for sig in SIGNATURES:
        if source.count(sig) != 1:
            raise ValueError("Missing unique TI NWK function")
        pos = source.index(sig)
        begin = source.index("{", pos)
        depth = 0
        for end in range(begin, len(source)):
            if source[end] == "{":
                depth += 1
            elif source[end] == "}":
                depth -= 1
                if depth == 0:
                    output.append(source[pos:end + 1])
                    break
        else:
            raise ValueError("Unbalanced TI function")
    combined = "\n\n".join(output) + "\n"
    if combined.count("nwkFrameCounterChanges = 0;") != 2:
        raise ValueError("NWK security acknowledgment drift")
    if combined.count("osal_nv_write_ex") != 3:
        raise ValueError("Expected two source-path writes")
    return combined

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--source", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args()
    raw = Path(args.source).read_bytes()
    Path(args.out).write_text(extract(raw.decode("utf-8")))
    print("B3_REAL_TI_NWK_SOURCE_SHA256", hashlib.sha256(raw).hexdigest())
