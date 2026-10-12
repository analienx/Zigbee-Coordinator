#!/usr/bin/env python3
"""Prepare a narrow, opt-in P7 UART buffer type correction.

Do not edit the pinned SDK checkout until AFTER G2 vanilla evidence is
produced; patch the isolated CI working tree only for a separate G3 candidate.
No runtime behavior or network change implied by a warning-free compilation.
"""
from __future__ import annotations
import argparse
import hashlib
import re
from pathlib import Path

PINNED_SOURCE = "source/ti/zstack/npi/npi_tl.c"
BUFS = ("npiRxBuf", "npiTxBuf")
DECLARATION = "static Char {name}[NPI_TL_BUF_SIZE];"
CORRECTION = "static uint8_t {name}[NPI_TL_BUF_SIZE];"

def transform(source: str) -> str:
    # The caller must provide the pinned SDK source and first verify git HEAD.
    # Fail closed on any unrecognized upstream edits or duplicate declarations.
    if "transportInit(npiRxBuf,npiTxBuf, NPITL_transmissionCallBack);" not in source:
        raise ValueError("UNKNOWN_NPI_TRANSPORT_CALL")
    result=source
    for name in BUFS:
        original=DECLARATION.format(name=name)
        corrected=CORRECTION.format(name=name)
        if result.count(original)!=1 or corrected in result:
            raise ValueError("UPSTREAM_UART_BUFFER_DECLARATION_DRIFT_"+name)
        result=result.replace(original,corrected)
    # Enforce no other change and documented two-symbol-only type correction.
    if transform_back(result)!=source:
        raise ValueError("NONREVERSIBLE_UART_PATCH")
    return result

def transform_back(source: str) -> str:
    out=source
    for name in BUFS:
        new=CORRECTION.format(name=name)
        if out.count(new)!=1:
            raise ValueError("MISSING_PATCHED_BUFFER_"+name)
        out=out.replace(new,DECLARATION.format(name=name))
    return out

def selftest() -> None:
    fixture="\n".join([DECLARATION.format(name=n) for n in BUFS]+
         ["void f(void) { transportInit(npiRxBuf,npiTxBuf, NPITL_transmissionCallBack); }"])
    patched=transform(fixture)
    assert patched.count("static uint8_t")==2
    assert transform_back(patched)==fixture
    negatives=[
        fixture.replace("static Char npiRxBuf","static uint16_t npiRxBuf"),
        fixture+"\n"+DECLARATION.format(name=BUFS[0]),
        fixture.replace("transportInit(npiRxBuf,npiTxBuf, NPITL_transmissionCallBack);","transportInit(0,0,0);"),
        patched
    ]
    for idx,bad in enumerate(negatives):
        try: transform(bad)
        except ValueError: continue
        raise AssertionError(f"UART_NEGATIVE_{idx}_ACCEPTED")
    print("PASS G3 exact-buffer unsigned-byte source transformation and 4 negatives")

def main() -> None:
    p=argparse.ArgumentParser()
    p.add_argument("--input",type=Path)
    p.add_argument("--output",type=Path)
    p.add_argument("--selftest",action="store_true")
    args=p.parse_args()
    if args.selftest: selftest()
    if args.input or args.output:
        if not args.input or not args.output:
            p.error("input and output required")
        if args.input.resolve()==args.output.resolve():
            p.error("never patch the authoritative source in-place")
        text=args.input.read_text(encoding="utf-8")
        changed=transform(text)
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(changed,encoding="utf-8")
        print("SOURCE_SHA256",hashlib.sha256(text.encode()).hexdigest())
        print("CANDIDATE_SHA256",hashlib.sha256(changed.encode()).hexdigest())
        print("CANDIDATE_ONLY_NOT_FLASHABLE")

if __name__=="__main__":
    main()
