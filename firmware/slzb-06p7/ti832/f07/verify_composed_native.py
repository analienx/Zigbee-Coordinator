#!/usr/bin/env python3
"""Independent G7+F07 native call-edge and source-order evidence, no flashing.

This does not prove NVOCMP power-cut atomicity, entire security table durability,
or the fitted P7U hardware. All required anchors are fail-closed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

GUARDS = {
    "ZDApp_NetworkStartEvt": "p7_f07_commit_nib_before_ready",
    "ZDOInitDeviceEx": "p7_f07_nv_restore_preflight",
}
SRC_RESTORED = "networkStateNV = ZDApp_RestoreNetworkState();"
SRC_CHECK = "if (networkStateNV != ZDO_INITDEV_RESTORED_NETWORK_STATE)"
SRC_CLEAR = "ZDSecMgrClearNVKeyValues();"


def function_body(disassembly: str, symbol: str) -> str:
    m = re.search(
        r"<" + re.escape(symbol) + r">:(.*?)(?=^\s*[0-9a-fA-F]+\s+<|\Z)",
        disassembly, re.S | re.M)
    if not m:
        raise ValueError("F07_NATIVE_BODY_MISSING_" + symbol)
    return m.group(1)


def verify_source(text: str) -> dict:
    required = (
        "p7_f07_commit_nib_before_ready",
        "p7_f07_nv_restore_preflight",
        "pZStackCfg->nvFps.updateItem(id, sizeof(nwkIB_t), &_NIB) == NVINTF_SUCCESS",
        "pZStackCfg->nvFps.readItem(id, 0, sizeof(nwkIB_t), readback) == NVINTF_SUCCESS",
        "pZStackCfg->nvFps.readItem(id, 0, sizeof(nwkIB_t), copy) == NVINTF_SUCCESS",
        "pZStackCfg->nvFps.getItemLen(id) != sizeof(nwkIB_t)",
        "ZDO_INITDEV_LEAVE_NOT_STARTED",
        "DEV_HOLD",
    )
    for anchor in required:
        if anchor not in text:
            raise ValueError("F07_REQUIRED_SOURCE_ANCHOR_MISSING:" + anchor)
    if text.count("p7_f07_commit_nib_before_ready(") != 2:
        raise ValueError("F07_NIB_GUARD_CALLSITE_AMBIGUOUS")
    if text.count("p7_f07_nv_restore_preflight(") != 2:
        raise ValueError("F07_RESTORE_GUARD_CALLSITE_AMBIGUOUS")
    start = text.index("uint8_t ZDOInitDeviceEx( uint16_t startDelay, uint8_t mode)\\n{")
    ready = text.index("void ZDApp_NetworkStartEvt( void )\\n{")
    start_text = text[start:ready]
    if not (
        start_text.index("if (!p7_f07_nv_restore_preflight())")
        < start_text.index(SRC_RESTORED)
        < start_text.index(SRC_CHECK)
        < start_text.index("#if (BDB_TOUCHLINK_CAPABILITY_ENABLED == TRUE)")
        < start_text.index(SRC_CLEAR)
    ):
        raise ValueError("F07_RESTORE_FAIL_CLOSED_ORDER_BROKEN")
    if "devState = DEV_HOLD;" not in start_text or start_text.count("return ZDO_INITDEV_LEAVE_NOT_STARTED;") < 2:
        raise ValueError("F07_RESTORE_NO_FAIL_CLOSED_STATE")
    ready_text = text[ready:]
    if not (ready_text.index("if (!p7_f07_commit_nib_before_ready())")
            < ready_text.index("ZDApp_NwkWriteNVRequest();")
            < ready_text.index("ZDApp_ChangeState( DEV_ZB_COORD );")):
        raise ValueError("F07_READY_BEFORE_NIB_GUARD")
    return {"restoration_guard_precedes_restore_and_touchlink": True,
            "no_implicit_network_clear_on_failed_restore": True,
            "coordinator_ready_preceded_by_nib_commit": True,
            "raw_nv_success_only": True,
            "pinned_source_sha256": hashlib.sha256(text.encode()).hexdigest()}


def verify(candidate: Path, source: Path, profile: str) -> dict:
    if profile not in ("p7u-f07-stock", "cap192-f07"):
        raise ValueError("F07_INTEGRATION_PROFILE_NOT_SUPPORTED")
    source_evidence = verify_source(source.read_text())
    symbols_text = (candidate / "DIAG-symbols.txt").read_text()
    disassembly = (candidate / "DIAG-disassembly.txt").read_text()
    linked = {}
    for caller, guard in GUARDS.items():
        if len(re.findall(r"(?m)^\S.*\b" + re.escape(guard) + r"$", symbols_text)) != 1:
            raise ValueError("F07_LINKED_GUARD_SYMBOL_MISSING_" + guard)
        body = function_body(disassembly, caller)
        function_body(disassembly, guard)
        if not re.search(r"\b(?:b(?:\.[wn])?|bl(?:\.w)?|blx)\s+[^\n]*<" + re.escape(guard) + r">", body):
            raise ValueError("F07_NATIVE_CALL_EDGE_MISSING_" + caller + "_" + guard)
        linked[caller] = guard
    # Existing G6/G7 strict audit separately owns CCFG, NV, cap, ELF/HEX map
    return {
        "qualification": "F07_COMBINED_G7_LINKED_SOURCE_ONLY_NOT_FLASHABLE",
        "profile": profile,
        "verified_call_edges": linked,
        "source": source_evidence,
        "disassembly_sha256": hashlib.sha256(disassembly.encode()).hexdigest(),
        "symbols_sha256": hashlib.sha256(symbols_text.encode()).hexdigest(),
        "frame_counters_and_security_keys_qualified": False,
        "nv_power_loss_qualified": False,
        "board_io_qualified": False,
        "flash_authorized": False,
    }


def main() -> None:
    a = argparse.ArgumentParser(description=__doc__)
    a.add_argument("--candidate", type=Path, required=True)
    a.add_argument("--source", type=Path, required=True)
    a.add_argument("--profile", required=True)
    a.add_argument("--out", type=Path, required=True)
    args = a.parse_args()
    result = verify(args.candidate, args.source, args.profile)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
