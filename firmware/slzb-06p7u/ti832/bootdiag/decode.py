#!/usr/bin/env python3
"""Decode an existing private raw UART capture; never opens a device."""
import argparse
import json
from pathlib import Path

STAGES = ("unused", "board_ready", "before_nv", "nv_result", "nv_first_failure",
          "before_bios", "stack_enter", "crypto", "mac", "nv_globals",
          "services", "stack_ready", "uart_handoff", "npi_uart_open", "assert")


def decode(data):
    result, offset, discarded = [], 0, 0
    while offset + 8 <= len(data):
        frame = data[offset:offset + 8]
        checksum = 0
        for value in frame:
            checksum ^= value
        if frame[:2] != b"\xa5\x5a" or checksum or not 0 < frame[2] < len(STAGES):
            discarded += 1
            offset += 1
            continue
        stage = frame[2]
        result.append({"stage": stage, "name": STAGES[stage],
                       "arg": int.from_bytes(frame[3:5], "little"),
                       "value": int.from_bytes(frame[5:7], "little")})
        offset += 8
    return {"schema": "p7u-temporary-bootdiag-v1", "records": result,
            "non_record_bytes": discarded + len(data) - offset,
            "root_cause_automatically_inferred": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    args = parser.parse_args()
    print(json.dumps(decode(args.capture.read_bytes()), indent=2))
