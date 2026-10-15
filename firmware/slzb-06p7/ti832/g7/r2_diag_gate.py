#!/usr/bin/env python3
"""Fail-closed linked/source proof for the EXISTING G6 SYS 0xF0 endpoint.

No firmware patch: G6 already implements versioned P7G6 v1 SREQ/response.
Checks the actual R2 CCS call chain without being fooled by local ARM $t labels.
"""
from __future__ import annotations
import argparse
import re
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
G6=ROOT/"g6"

def require(ok,reason):
    if not ok: raise ValueError(reason)

def source_check() -> None:
    header=(G6/"p7_g6.h").read_text()
    impl=(G6/"p7_g6.c").read_text()
    overlay=(G6/"g6_overlay.py").read_text()
    require("#define P7_G6_CMD 0xF0u" in header,"EXISTING_OPCODE_CHANGED")
    require("#define P7_G6_VERSION 1u" in header,"EXISTING_ABI_CHANGED")
    require("case P7_G6_CMD:" in overlay and "p7_g6_response(" in overlay,
            "EXISTING_SYS_DISPATCH_MISSING")
    for text in ("else if (len!=2 || !req)","req[0]!=P7_G6_VERSION",
                 "req[1]!=0","p7_diag_snapshot("):
        require(text in impl,"READ_ONLY_G6_PARSER_CHANGED_"+text)
    for illegal in ("NVOCMP_write","nvFps.deleteItem","erase_sector","flash_erase"):
        require(illegal not in impl,"SIDE_EFFECT_IN_DIAG_IMPLEMENTATION")

def symbols_map(raw: str) -> dict[str,tuple[int,str]]:
    result={}
    for line in raw.splitlines():
        match=re.match(r"^([0-9a-fA-F]+)\s+([Tt])\s+(\S+)$",line)
        if match:result[match[3]]=(int(match[1],16),match[2])
    return result

def native_check(disassembly: str, symbols: str) -> None:
    funcs=symbols_map(symbols)
    for name in ("MT_SysCommandProcessing","p7_g6_response","p7_diag_snapshot"):
        require(name in funcs,"LINKED_SYMBOL_MISSING_"+name)
    starts=sorted(addr for addr,_ in funcs.values())
    def has_call(caller,callee):
        origin=funcs[caller][0]
        ends=[addr for addr in starts if addr>origin]
        require(bool(ends),"NO_NEXT_FUNCTION_"+caller)
        end=min(ends)
        candidates=[(int(addr,16),target) for addr,target in
                    re.findall(r"(?m)^\s*([0-9a-fA-F]+):[^\n]*\bbl(?:\.w)?\s+[^\n]*<([^>]+)>",disassembly)]
        return any(origin<=addr<end and target==callee for addr,target in candidates)
    require(has_call("MT_SysCommandProcessing","p7_g6_response"),
            "EXISTING_SYS_F0_NOT_REACHING_G6")
    require(has_call("p7_g6_response","p7_diag_snapshot"),
            "G6_RESPONSE_NOT_REACHING_RECORDER")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--disassembly",type=Path)
    p.add_argument("--symbols",type=Path)
    p.add_argument("--selftest",action="store_true")
    a=p.parse_args()
    source_check()
    if a.selftest:
        assert symbols_map("00000003 T f\n00000004 T g")=={"f":(3,"T"),"g":(4,"T")}
        try:native_check("","")
        except ValueError:pass
        else:raise AssertionError("MISSING_LINK_ACCEPTED")
        print("EXISTING_P7G6_SYS_F0_SOURCE_GATE_PASS")
    if a.disassembly or a.symbols:
        require(bool(a.disassembly and a.symbols),"NATIVE_INPUT_PAIR_REQUIRED")
        native_check(a.disassembly.read_text(),a.symbols.read_text())
        print("R2_NATIVE_EXISTING_G6_F0_TO_P7D1_CALL_CHAIN_PASS")

if __name__=="__main__":main()
