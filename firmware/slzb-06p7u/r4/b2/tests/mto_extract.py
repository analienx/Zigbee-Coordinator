#!/usr/bin/env python3
"""Extract compiled TI 8.33 ZDApp_ForceConcentratorChange body, not a mock."""
import argparse
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from b2_mto_nv_guard import source_function, BEFORE, AFTER

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--donor-negative", action="store_true")
    a = parser.parse_args()
    body = source_function(a.source.read_text(encoding="utf-8"))
    if body != (BEFORE if a.donor_negative else AFTER):
        raise SystemExit("unexpected real TI MTO function preimage")
    a.out.write_text('#include "mto_stub.h"\n' + body + '\n')
    print("B2_ACTUAL_PINNED_TI_MTO_FUNCTION_EXTRACTED")

if __name__ == "__main__":
    main()
