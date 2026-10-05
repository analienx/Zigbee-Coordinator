#!/usr/bin/env python3
"""Fail-closed policy validation for T832-DIAG-R0."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    args = ap.parse_args()
    root = args.root.resolve()

    manifest = json.loads((root / "diag_manifest.json").read_text(encoding="utf-8"))
    require(manifest["variant"] == "T832-DIAG-R0", "wrong diagnostic variant")
    require(manifest["base_variant"] == "T832-KCTRL-R0", "wrong control base")
    ram = manifest["static_ram"]
    require(ram["maximum_diagnostic_bytes"] == 4096, "diagnostic RAM cap must be 4 KiB")
    require(ram["minimum_linker_free_sram_bytes"] == 8192, "free SRAM gate must remain 8 KiB")
    require(ram["critical_records"] == 64, "critical recorder must be 64 records")
    require(ram["routine_records"] == 64, "routine recorder must be 64 records")

    transport = manifest["transport"]
    require(transport["envelope"] == "AREQ DEBUG.msg", "transport must remain DEBUG.msg AREQ")
    require(transport["schema"] == 2, "diagnostic schema must be 2 (length-prefixed batch)")
    require(transport["length_prefixed"] is True, "DEBUG payload must carry the string length prefix")
    require(transport["maximum_payload_bytes"] <= 240, "diagnostic payload exceeds 240 bytes")
    require(transport["maximum_records_per_frame"] <= 4, "batch exceeds frame budget")
    require(transport["minimum_export_interval_ms"] >= 5000, "telemetry faster than one frame/5 s")
    require(transport["health_snapshot_interval_ms"] == 10000, "health snapshot must be 10 s")
    require(transport["resource_snapshot_interval_ms"] == 60000, "resource snapshot must be 60 s")
    require(transport["maximum_pending_diagnostic_messages"] == 1, "more than one diagnostic message pending")
    require(transport["normal_znp_has_priority"] is True, "normal ZNP must have priority")
    require(transport["bypass_sync_suppression"] is False, "must not bypass SREQ/SRSP suppression")

    capabilities = manifest["capabilities"]
    for name in manifest["release_gate_required_capabilities"]:
        require(capabilities.get(name) is True, f"required capability unavailable: {name}")

    runtime = (root / "t832_diag_impl.inc").read_text(encoding="utf-8")
    header = (root / "t832_diag.h").read_text(encoding="utf-8")
    patcher = (root / "apply_diag.py").read_text(encoding="utf-8")
    host = (root / "t832_incident.py").read_text(encoding="utf-8")

    require("T832_DIAG_CRITICAL_RECORDS 64u" in runtime, "critical ring source drift")
    require("T832_DIAG_ROUTINE_RECORDS 64u" in runtime, "routine ring source drift")
    require("sizeof(T832DiagState) <= 4096u" in runtime, "static RAM assertion missing")
    require("T832_DIAG_EXPORT_MIN_MS 5000u" in runtime, "export limiter missing")
    require("T832_DIAG_HEALTH_MS 10000u" in runtime, "health interval drift")
    require("T832_DIAG_RESOURCE_MS 60000u" in runtime, "resource interval drift")
    require("t832Diag.sync_outstanding || t832Diag.transport_active" in runtime, "backpressure/sync gate missing")
    require("t832Diag.diag_pending || t832Diag.normal_pending" in runtime, "pending-message gate missing")
    require("T832_DIAG_EV_NPI_RX_OVERFLOW" in runtime, "RX overflow instrumentation missing")
    require("T832_DIAG_EV_NPI_WRITE_REJECT" in runtime, "write rejection instrumentation missing")
    require("T832_DIAG_EV_NPI_TX_FINISHED" in runtime, "physical TX-completion instrumentation missing")
    require("T832_DIAG_EV_STARTUP_BDB_REQUEST" in runtime, "startup BDB request instrumentation missing")
    require("T832_DIAG_SCHEMA_VERSION 2u" in header, "schema version must be 2")
    require("T832_DIAG_BATCH_MAX 4u" in header, "batch bound missing")
    require("T832_DIAG_BOOT_MAGIC" in header, "boot validity marker missing")
    require("T832_DIAG_CAP_RESET_CAUSE" in header, "early reset-cause capability missing")
    require("T832Diag_captureResetCauseEarly" in patcher, "early reset-cause hook missing")
    require("source/ti/zstack/startup/main.c" in patcher, "main() capture patch missing")
    require("SysCtrlResetSourceGet" in patcher, "reset-source read missing from patch")
    require("Boot_getBootReason" not in patcher, "dead Boot_getBootReason writer must stay removed")
    require("T832_BUILD_ID" in patcher, "immutable build identity missing from patch")
    require("npi_task.c" in patcher, "NPI task patch missing")
    require("T832Diag_npiTrap" in patcher, "NPI trap hook missing")
    require("NPITL_writeTL" in patcher, "TX dequeue hook missing")
    require("NPITask_sendToHost" in patcher, "app-originated TX hook missing")
    require("T832Diag_npiTxRefused" in patcher, "TX-path refusal hooks missing")
    require("T832Diag_npiTxRefused" in runtime, "TX-path refusal instrumentation missing")
    require("T832Diag_npiTxRefusedOwned" in patcher, "R4-F01 owned stage-3 refusal hook missing")
    require("T832Diag_npiTxRefusedOwned" in runtime, "R4-F01 owned refusal instrumentation missing")
    require(patcher.index("T832Diag_npiTxQueuedOther") < patcher.index("T832Diag_npiTxRefusedOwned"),
            "R4-F01 push-before-refusal order broken: QueuedOther must precede RefusedOwned")
    require("T832Diag_popPeeked(uint8_t sel, uint16_t seq, uint32_t first_ms," in runtime,
            "R4-F10 staged retirement must carry first/last_ms identity")
    require("T832Diag_afOldestLocked" in runtime, "R4-F09 oldest-survivor rescan missing")
    require("T832Diag_afDispatch" in patcher, "AF dispatch hook missing")
    require("ZStackTaskProcessEvent" in patcher, "ZStack progress hook missing")
    require("T832Diag_networkState" in patcher, "existing-network resume-state hook missing")
    require("T832Diag_uartRxOverflow" in patcher, "UART overflow hook missing")
    require("T832Diag_uartTxFinished" in patcher, "UART completion hook missing")
    require("T832_DIAG_CAP_MT_EVENTS" in header, "MT event-mask capability missing")
    require("T832_DIAG_CAP_TASK_MODES" not in header, "TASK_MODES label must stay renamed: it observes event masks, not task states")
    require("T832_DIAG_CAP_TX_OWNERSHIP" in header, "TX ownership capability missing")
    require("T832_DIAG_CAP_AF_ACCEPT" in header, "AF accept-table capability missing")
    require("T832_DIAG_CAP_BATCHED_V2" in header, "batched schema capability missing")
    require("T832_DIAG_CAP_NV_COMPACT" in header, "NV compaction capability missing")
    require("T832_DIAG_CAP_AF_AGE" in header, "AF outstanding-age capability missing")
    require("T832_DIAG_EV_TASK_EVENTS" in header, "task-events kind missing")
    require("T832_DIAG_EV_NV_EVENT" in header, "NV event kind missing")
    require("T832_DIAG_EV_AF_STATE" in header, "AF state kind missing")
    require("T832_DIAG_EV_NV_FAULT" in header, "NV fault kind missing")
    require("T832Diag_nvEvent" in runtime, "NV compaction instrumentation missing")
    require("T832Diag_nvInit" in runtime, "NV init-action instrumentation missing")
    require("mt_sticky_events" in runtime, "MT event-bit tracking missing")
    require("af_outstanding" in runtime, "AF outstanding tracking missing")
    require("MT_AF_DATA_CONFIRM" in runtime, "AF confirm correlation missing")
    require("nvocmp.c" in patcher, "NV source patch missing")
    require("NVOCMP_compact(pNvHandle)" in patcher, "NV compaction hook missing")
    require("gAction = action;" in patcher, "NV init-action hook missing")
    require("T832Diag_nvInit((uint8_t)action)" in patcher, "NV init hook call missing")

    require("T832D2:" in runtime, "schema-2 text prefix missing")
    require("out[0] = strLen" in runtime, "length-prefix store missing from exporter")

    # Hot hook bodies must remain observational only. Export is intentionally excluded.
    hook_names = [
        "T832Diag_captureResetCauseEarly",
        "T832Diag_taskScheduled", "T832Diag_taskWork", "T832Diag_npiTaskWake",
        "T832Diag_commandRx",
        "T832Diag_commandDispatch", "T832Diag_afDispatch", "T832Diag_commandComplete",
        "T832Diag_responseQueued", "T832Diag_responseAllocFailed",
        "T832Diag_npiTxQueuedOther", "T832Diag_npiTxDequeue",
        "T832Diag_npiTrap", "T832Diag_npiAllocFailed", "T832Diag_npiTxRefused",
        "T832Diag_npiTxRefusedOwned",
        "T832Diag_uartConfigured", "T832Diag_uartRx", "T832Diag_uartRxOverflow",
        "T832Diag_uartTxStart", "T832Diag_uartWriteRejected",
        "T832Diag_uartTxFinished", "T832Diag_startup",
        "T832Diag_networkState", "T832Diag_bdb", "T832Diag_rxBufferFull",
        "T832Diag_nvEvent", "T832Diag_nvInit",
    ]
    banned = re.compile(r"\b(malloc|calloc|realloc|free|printf|fprintf|UART2_write|flash|sleep|Task_sleep)\b")
    for name in hook_names:
        match = re.search(rf"void\s+{name}\([^)]*\)\s*\{{(?P<body>.*?)\n\}}", runtime, re.S)
        require(match is not None, f"hook missing: {name}")
        require(banned.search(match.group("body")) is None, f"hot hook has forbidden operation: {name}")

    require("import serial" not in host and "from serial" not in host, "host collector must not use pyserial")
    require("/dev/serial" not in host, "host collector must not open coordinator serial path")
    require("default=7" in host, "seven-day retention default missing")
    require("default=1 << 30" in host, "1 GiB recording cap default missing")
    require("default=15 * 60" in host, "15-minute incident window missing")
    require("default=30" in host, "30-second capture deadline missing")
    require("automatic-reset-already-consumed" in host, "one-reset latch guard missing")
    require("stability-window-not-complete" in host, "10-minute stability close guard missing")

    harness = (root / "host_harness" / "t832_diag_host_test.c").read_text(encoding="utf-8")
    harness_sdk = (root / "host_harness" / "t832_host_sdk.h").read_text(encoding="utf-8")
    require("T832-DIAG-R0 host harness marker" in harness, "host harness marker missing")
    require('#include "t832_diag_impl.inc"' in harness, "harness must exercise the real recorder")
    require("MT_BuildAndSendZToolResponse" in harness_sdk, "harness export stub missing")

    print("T832-DIAG-R0 policy contract: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
