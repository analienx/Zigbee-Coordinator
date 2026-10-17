"""Read-only source-qualified F0/F1/F2 ownership proof across B4 and B1.

B1 management owns F1. B4 v3 owns F0. B4 v4 nonce diagnostics use F2.
This never combines or flashes two draft firmware branches.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess

B1_SHA = "a514c194ea0d94b5d38b28c7b07ca5caba9aeffd"
B1_HEADER = "firmware/slzb-06p7u/r4/b1/b1_management.h"
B1_SOURCE = "firmware/slzb-06p7u/r4/b1/b1_management.c"
B4_V3 = 0xF0
B1_STATUS = 0xF1
B4_V4 = 0xF2

def inspect(b1_header, b1_source, b4_mt):
    match = re.search(r"^\s*#define\s+B1_STATUS_COMMAND\s+0x([0-9a-fA-F]+)u?\b",b1_header,re.M)
    if not match:
        raise ValueError("B1 status command declaration unavailable")
    b1_opcode = int(match.group(1),16)
    if b1_opcode != B1_STATUS:
        raise ValueError("B1 management opcode changed; independent ABI review required")
    if len({B4_V3,b1_opcode,B4_V4}) != 3:
        raise ValueError("B4/B1 existing-owner MT opcode collision")
    if ("frame[2] == B1_STATUS_COMMAND" not in b1_source or
            "return B1_MT_STATUS;" not in b1_source):
        raise ValueError("B1 HOLD status admission path no longer source-backed")
    for opcode in (B4_V3,B4_V4):
        if b4_mt.count("case 0x%02X:" % opcode) != 1:
            raise ValueError("B4 F0/F2 source-dispatch identity missing")
    if "case 0xF1:" in b4_mt:
        raise ValueError("B4 attempted to take B1 F1")
    # Current B1 HOLD filter admits only SYS PING/VERSION and B1 F1.
    # Therefore B4 SYS F2 must remain unavailable while HOLD is asserted,
    # until a separately reviewed B1/B4 combined dispatch explicitly permits.
    return {
        "schema":"r4-b4-v4-cross-phase-command-ownership-v1",
        "b4_v3_sys":"F0","b1_hold_status_sys":"F1","b4_v4_sys":"F2",
        "command_collision":False,
        "b1_hold_allows_b4_v4_f2":False,
        "b1_b4_combined_source_ready":False,
        "source_review":"PINNED_B1_MANAGEMENT_ONLY_NOT_INTEGRATION_APPROVAL",
    }

def verify(b1, b4_sys):
    b1 = Path(b1)
    if not b1.is_dir() or not str(b1.resolve()).startswith("/tmp/"):
        raise ValueError("B1 must be a disposable source checkout")
    try:
        sha=subprocess.check_output(["git","-C",str(b1),"rev-parse","HEAD"],text=True).strip()
    except (subprocess.CalledProcessError,OSError) as error:
        raise ValueError("cannot verify B1 SHA") from error
    if sha != B1_SHA:
        raise ValueError("B1 upstream source SHA drift; do not claim integration")
    for path in (B1_HEADER,B1_SOURCE):
        actual=(b1/path).read_bytes()
        pristine=subprocess.check_output(["git","-C",str(b1),"show",B1_SHA+":"+path])
        if actual!=pristine:
            raise ValueError("B1 source content mutated")
    return inspect((b1/B1_HEADER).read_text(),
                   (b1/B1_SOURCE).read_text(),Path(b4_sys).read_text())

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--b1",type=Path,required=True)
    parser.add_argument("--b4-mt",type=Path,required=True)
    a=parser.parse_args()
    print(json.dumps(verify(a.b1,a.b4_mt),sort_keys=True))

if __name__=="__main__":
    main()
