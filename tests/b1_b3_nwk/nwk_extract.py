#!/usr/bin/env python3
"""Compile actual TI B1+B3 function, refuse synthetic substitute bodies."""
import argparse
from pathlib import Path
import sys

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--source",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    args=p.parse_args()
    root=Path(__file__).resolve().parents[2]
    sys.path.insert(0,str(root/"firmware/slzb-06p7u/r4/b1/tools"))
    from patch_zdapp import extract_function
    from b1_b3_nwk_checkpoint import SIG, REPLACEMENT
    body=extract_function(args.source.read_text(),SIG)
    if body != REPLACEMENT:
        raise SystemExit("B1_B3_ACTUAL_TI_SAVE_BODY_NOT_REVIEWED")
    args.out.write_text('#include "nwk_stub.h"\n'+body+"\n")
    print("B1_B3_GENUINE_REWRITTEN_TI_NWK_SAVE_EXTRACTED")

if __name__=="__main__": main()
