#!/usr/bin/env python3
"""HOSTED ONLY: G7 real linked call path, in addition to unchanged G6 audits."""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "g5"))
from diag_build_compare import symbols


def body(dis, name):
    match = re.search(r"<" + re.escape(name) + r">:(.*?)(?=^\s*[0-9a-fA-F]+\s+<|\Z)", dis, re.S | re.M)
    if not match: raise ValueError("LINKED_BODY_MISSING_" + name)
    return match.group(1)


def calls(dis, caller, target):
    return bool(re.search(r"\b(?:b(?:\.[wn])?|bl(?:\.w)?|blx)\s+[^\n]*<" +
                          re.escape(target) + r">", body(dis, caller)))


def verify(candidate):
    dis = (candidate / "DIAG-disassembly.txt").read_text()
    map_text = (candidate / "DIAG-NOT-FLASHABLE.map").read_text()
    syms = symbols((candidate / "DIAG-symbols.txt").read_text())
    required = {"p7_g7_service", "p7_g7_enqueue", "p7_g7_counters", "p7_g7_tl_outcome",
                "p7_g7_uart_outcome", "p7_g7_uart_completion_error", "p7_tx_budget_ready", "p7_tx_choose", "UART2_write",
                "UART2_writeTimeout", "UART2_writeTimeoutBlocking", "NPITL_writeTL",
                "NPITLUART_writeTransport"}
    if not required <= syms: raise ValueError("G7_LINKED_SYMBOLS_MISSING:" + str(required - syms))
    task_callers = [name for name in ("NPITask_process", "NPITask_Fxn", "NPITask_task")
                    if name in syms and calls(dis, name, "p7_g7_service")]
    if not task_callers: raise ValueError("TASK_TO_G7_SERVICE_NOT_LINKED")
    edges = [("p7_g7_service", "p7_g7_uart_completion_error"),
             ("p7_g7_service", "NPITL_writeTL"), ("NPITL_writeTL", "NPITLUART_writeTransport"),
             ("NPITLUART_writeTransport", "UART2_write"), ("UART2_write", "UART2_writeTimeout"),
             ("UART2_writeTimeout", "UART2_writeTimeoutBlocking")]
    for caller, target in edges:
        if not calls(dis, caller, target): raise ValueError("G7_CALL_NOT_PROVEN_" + caller + "_" + target)
    # Weak UART APIs must resolve to the exact source unit exercised by host
    # vectors, not a same-named board-specific override or unused mock symbol.
    for name in ("UART2_write", "UART2_writeTimeout", "UART2_writeTimeoutBlocking"):
        rows = [line for line in map_text.splitlines() if "(.text." + name + ")" in line]
        if len(rows) != 1 or "UART2.c.obj" not in rows[0]:
            raise ValueError("UART_WEAK_API_SOURCE_NOT_PROVEN_" + name)
    return {"qualification": "G7_LINKED_SOURCE_ONLY_NOT_FLASHABLE",
            "runtime_qualified": False, "hardware_qualified": False, "flash_authorized": False,
            "symbols": sorted(required), "task_callers": task_callers,
            "linked_call_edges": edges, "uart_api_source_unit": "UART2.c.obj",
            "disassembly_sha256": hashlib.sha256(dis.encode()).hexdigest(),
            "map_sha256": hashlib.sha256(map_text.encode()).hexdigest(),
            "runtime_queue_stress_and_original_P7U_transport": "UNPROVEN"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.candidate)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
