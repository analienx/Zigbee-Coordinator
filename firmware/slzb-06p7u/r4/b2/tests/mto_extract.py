#!/usr/bin/env python3
"""Extract compiled TI 8.33 ZDApp_ForceConcentratorChange body, not a mock."""
import argparse
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from b2_mto_nv_guard import (
    source_function, BEFORE, AFTER, FAILURE_SIGNATURE,
    FAILURE_BEFORE, FAILURE_AFTER,
)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--donor-negative", action="store_true")
    parser.add_argument("--failure-unmodified", action="store_true")
    a = parser.parse_args()
    source = a.source.read_text(encoding="utf-8")
    body = source_function(source)
    if body != (BEFORE if a.donor_negative else AFTER):
        raise SystemExit("unexpected real TI MTO function preimage")
    failure = source_function(source, FAILURE_SIGNATURE)
    if failure != (FAILURE_BEFORE if a.donor_negative else FAILURE_AFTER):
        raise SystemExit("unexpected real TI MTO failure callback preimage")
    if a.failure_unmodified:
        if a.donor_negative:
            raise SystemExit("select one negative mutant")
        failure = FAILURE_BEFORE
    a.out.write_text('#include "mto_stub.h"\n' + body + '\n' + failure + '\n')
    print("B2_ACTUAL_PINNED_TI_MTO_FUNCTION_EXTRACTED")

if __name__ == "__main__":
    main()
