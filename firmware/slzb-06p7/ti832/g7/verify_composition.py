#!/usr/bin/env python3
"""HOSTED ONLY: exact surviving G5/G6 hooks and mandatory G7 task integration."""
import argparse
import json
import re
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "g6"))
import g6_overlay as g6
import diag_overlay as diag


def verify(sdk):
    return verify_texts({rel: (sdk / rel).read_text() for rel in {p[0] for p in diag.PATCHES}})


def verify_texts(texts):
    # These six old hooks are intentionally replaced by the classified G7
    # enqueue/submission path. Every other original named hook must survive.
    removed = {"npi_q_accept_sync", "npi_q_accept_async", "npi_q_reject_type",
               "npi_q_reject_alloc", "uart_write_rejected", "uart_write_accepted"}
    expected = set()
    for _, _, replacement, _ in diag.PATCHES:
        expected.update(re.findall(r"P7DIAG:([a-z_]+)", replacement))
    expected -= removed
    found = []
    for rel in sorted({p[0] for p in diag.PATCHES}):
        found.extend(re.findall(r"P7DIAG:([a-z_]+)", texts[rel]))
    if set(found) != expected or len(found) != len(expected):
        raise ValueError("G7_SURVIVING_HOOKS_CHANGED:" + str((expected - set(found), set(found) - expected)))
    task = texts[g6.TASK]
    anchors = ['#include "p7_g7_task.inc"', 'p7_g7_init();',
               'p7_g7_service(); /* RX handled before bounded TX pass */',
               'p7_g7_enqueue(NPIFrame_frameMsg(pMsg));', 'p7_g7_enqueue(pNPIMsg);',
               'p7_g7_isr_event = 0;', '| p7_g7_isr_event;']
    for anchor in anchors:
        if task.count(anchor) != 1: raise ValueError("G7_TASK_ANCHOR_CHANGED:" + anchor)
    if "NPITask_ProcessTXQ" in task or "npiTxQueue" in task:
        raise ValueError("G7_OLD_ASYNC_OWNER_PATH_REMAINS")
    return {"qualification": "G7_COMPOSED_SOURCE_ONLY_NOT_FLASHABLE",
            "surviving_g5_g6_hooks": sorted(expected), "replaced_hooks": sorted(removed),
            "g7_task_anchors": anchors, "hardware_qualified": False, "flash_authorized": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdk", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.sdk), indent=2))
