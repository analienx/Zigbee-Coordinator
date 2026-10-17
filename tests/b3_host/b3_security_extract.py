#!/usr/bin/env python3
"""Extract two ACTUAL TI SDK 8.33 security functions for host compilation.

A function-body harness cannot prove the closed SDK's RF counter call ordering.
Only donor and overlay fingerprints accepted; no synthetic replacement body.
"""
import argparse
import hashlib
import pathlib

STARTS = (
    "void ZDSecMgrSaveApsLinkKey(void)",
    "void ZDSecMgrSaveTCLinkKey(void)",
)

def extract(source):
    output = ['#include "b3_security_stub.h"']
    for head in STARTS:
        if source.count(head) != 1:
            raise ValueError("missing or ambiguous TI security function: " + head)
        at = source.index(head)
        start = source.find("{", at + len(head))
        if start < 0:
            raise ValueError("function body absent")
        depth = 0
        end = None
        for i in range(start, len(source)):
            if source[i] == "{":
                depth += 1
            elif source[i] == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        if end is None:
            raise ValueError("unbalanced original function")
        body = source[at:end]
        if body.count("osal_nv_write_ex") != 1 or body.count("pendingFlag = FALSE;") != 1:
            raise ValueError("security write precondition drift")
        if "if (osal_nv_write_ex" not in body:
            raise ValueError("status validation missing from source overlay")
        output.append(body)
    return "\n\n".join(output) + "\n"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--out", required=True)
    a = parser.parse_args()
    raw = pathlib.Path(a.source).read_bytes()
    text = raw.decode("utf-8")
    generated = extract(text)
    pathlib.Path(a.out).write_text(generated)
    print("B3_EXACT_TI_SECURITY_BODIES_COMPILED_SOURCE_SHA256",
          hashlib.sha256(raw).hexdigest())
if __name__ == "__main__":
    main()
