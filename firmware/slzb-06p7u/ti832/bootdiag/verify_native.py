#!/usr/bin/env python3
"""Bind temporary boot diagnostics to its exact native image; no device access."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "qualification"))
import p7u_rom_bsl_image_gate as gate
sys.path.insert(0, str(HERE.parents[2] / "slzb-06p7/ti832/f07"))
from verify_composed_native import function_body


def need(condition, code):
    if not condition: raise ValueError(code)


def verify(baseline, candidate, sdk):
    full = (candidate / "DIAG-NOT-FLASHABLE.hex").read_bytes()
    data = gate.parse_hex(full)
    geometry = gate.candidate_audit(data, "p7u-cap192-f07")
    app_hex = gate.application_only_hex(data, "p7u-cap192-f07")
    app_data = gate.parse_hex(app_hex)
    end = max(app_data) + 1
    count = (end + gate.SECTOR - 1) // gate.SECTOR
    need(count in (23, 24) and end <= 0x30000, "BOOTDIAG_OUTSIDE_EXACT_24_SECTOR_MAXIMUM")
    symbols = (candidate / "DIAG-symbols.txt").read_text()
    def symbol(name):
        matches = re.findall(r"(?m)^([0-9a-fA-F]+)\s+\w\s+" + re.escape(name) + r"$", symbols)
        need(len(matches) == 1, "BOOTDIAG_MISSING_SYMBOL_" + name)
        return int(matches[0], 16)
    need(symbol("__STACK_SIZE") == 4096 and symbol("__STACK_END") == 0x20024000,
         "BOOTDIAG_STACK_NOT_EXACT_RESERVED_P7_REGION")
    dis = (candidate / "DIAG-disassembly.txt").read_text()
    for caller, callees in {
        "main": ("p7_bootdiag_begin", "p7_bootdiag_arm_stack", "p7_bootdiag_nv_result"),
        "NPITLUART_initializeTransport": ("p7_bootdiag_handoff", "p7_bootdiag_npi_opened"),
    }.items():
        body = function_body(dis, caller)
        for callee in callees:
            need(re.search(r"\b(?:bl|blx|b)(?:\.[wn])?\s+[^\n]*<" + re.escape(callee) + r">", body),
                 "BOOTDIAG_LINKED_CALL_MISSING_" + caller + "_" + callee)
    emitter = function_body(dis, "p7_bootdiag_stage")
    need(not re.search(r"<(?:UART2_write\w*|[vs]?printf|malloc|calloc)(?:\+[^>]*)?>", emitter),
         "BOOTDIAG_UNBOUNDED_OR_ALLOCATING_EMITTER")
    source_report = json.loads((candidate / "BOOTDIAG-SOURCE.json").read_text())
    nv_hash = hashlib.sha256((sdk / "source/ti/common/nv/nvocmp.c").read_bytes()).hexdigest()
    need(source_report["nv_driver_before_and_after_sha256"] == nv_hash,
         "BOOTDIAG_NV_DRIVER_NOT_PRESERVED")
    main = (sdk / "source/ti/zstack/startup/main.c").read_text()
    need("if (p7_bd_nv_status != NVINTF_SUCCESS)" in main and
         "Main_assertReason = 0xE1;" in main and
         "for (;;) {} /* no stack, radio start or automatic reset */" in main,
         "BOOTDIAG_NV_FAILURE_HALT_MISSING")
    (candidate / "BOOTDIAG.APP-ONLY-NOT-FLASHABLE.hex").write_bytes(app_hex)
    return {"schema": "p7u-temporary-bootdiag-linked-v1", "stack_bytes": 4096,
            "old_stack_boundary_bytes": 1024, "app_end_exclusive": hex(end),
            "required_application_sectors": count, "application_envelope_end": hex(count * gate.SECTOR),
            "stock_cleanup_must_cover_same_sector_count": True,
            "normal_r2_full_hex_sha256": hashlib.sha256((baseline / "DIAG-NOT-FLASHABLE.hex").read_bytes()).hexdigest(),
            "bootdiag_full_hex_sha256": hashlib.sha256(full).hexdigest(),
            "bootdiag_app_hex_sha256": hashlib.sha256(app_hex).hexdigest(),
            "nv_driver_sha256": nv_hash, "geometry": geometry,
            "temporary_instrumentation": True, "release_candidate": False,
            "flash_authorized": False, "hardware_tested": False,
            "watermark_is_lower_bound_including_instrumentation": True}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("baseline", "candidate", "sdk", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.baseline, args.candidate, args.sdk)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, sort_keys=True))
