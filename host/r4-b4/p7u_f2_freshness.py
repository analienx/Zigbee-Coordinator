"""Read-only, hash-chain-verified F2 freshness and passive host-progress report.

This never opens ZNP/serial, sends MQTT, or changes the active owner.
F2 staleness is NOT proof of a hang and must NEVER actuate recovery.
"""
from __future__ import annotations

import argparse
import collections
import dataclasses
import json
import time
from pathlib import Path

from p7u_f2_acceptance import EvidenceHold, read_verified_history
from f2_progress_contract import valid_progress

SUBSYSTEMS = ("AF", "ZDO", "SYS", "UTIL")
MT_LIFECYCLE_FIELDS = (
    "allProduced", "allEnqueued", "allAllocFailed", "allSendFailed",
    "allNpiReceived", "allFramedQueued", "allFramingFailed",
    "allTlSubmitted", "allTlRejected", "afDataProduced",
    "afDataEnqueued", "afDataAllocFailed", "afDataSendFailed",
    "afDataNpiReceived", "afDataFramedQueued", "afDataFramingFailed",
    "afDataTlSubmitted", "afDataTlRejected",
)

def _mt_lifecycle(record: dict) -> dict | None:
    data = record.get("mtLifecycle")
    if data is None:
        return None
    if (record.get("minor") not in (2, 3) or type(data) is not dict
            or set(data) != set(MT_LIFECYCLE_FIELDS)
            or not all(type(data[k]) is int and 0 <= data[k] <= 0xFFFFFFFF
                       for k in MT_LIFECYCLE_FIELDS)):
        raise EvidenceHold("P7U_F2_V42_MT_LIFECYCLE_INVALID")
    return data
ALLOWED_REASONS = frozenset((
    "ADAPTER_QUEUE_PENDING", "ZNP_WAITRESS_PENDING", "OUTER_ADMISSION_GATED",
    "HOST_OR_OTA_ADMISSION_SKIPPED", "COOLDOWN_OR_ALREADY_IN_FLIGHT",
    "F2_REPLY_TIMEOUT", "PASSIVE_HOST_SREQ_TIMEOUT",
    "DIAGNOSTIC_QUARANTINED", "HOST_NOT_OPERATIONAL",
    "HERDSMAN_UNAVAILABLE", "HERDSMAN_STOPPING", "ADAPTER_DISCONNECTED",
    "AF_SREQ_TIMEOUT", "ZDO_SREQ_TIMEOUT", "SYS_SREQ_TIMEOUT", "UTIL_SREQ_TIMEOUT",
))


def _nonneg(value: object) -> bool:
    return type(value) is int and value >= 0


def _age(now_ms: int, event_ms: object) -> int | None:
    if not _nonneg(event_ms) or event_ms > now_ms:
        return None
    return now_ms - event_ms


def _safe_reason(value: object) -> str:
    return value if isinstance(value, str) and value in ALLOWED_REASONS else "OTHER_OR_UNKNOWN"


def _host_counts(record: dict) -> dict | None:
    evidence = record.get("hostEvidence")
    if type(evidence) is not dict:
        return None
    srsp = evidence.get("srsp")
    if type(srsp) is not dict:
        return None
    result = {}
    for subsystem in SUBSYSTEMS:
        counters = srsp.get(subsystem)
        if type(counters) is not dict:
            return None
        ok, timeout = counters.get("ok"), counters.get("timeout")
        if not (_nonneg(ok) and _nonneg(timeout)):
            return None
        result[subsystem] = {"ok": ok, "timeout": timeout}
    return result


def _host_wire(record: dict) -> dict | None:
    evidence = record.get("hostEvidence")
    if type(evidence) is not dict or "wire" not in evidence:
        return None
    wire = evidence["wire"]
    keys = ("rxRawBytes", "rxChunks", "unpiParsedFrames",
            "unpiParseErrors", "unpiBufferedBytes", "txQueuedBytes",
            "txQueuedFrames", "txQueuedRawBuffers")
    if (type(wire) is not dict or set(wire) != set(keys) | {"measurement"}
            or wire.get("measurement") != "EXISTING_OWNER_STREAM_ONLY"
            or not all(_nonneg(wire.get(k)) for k in keys)):
        raise EvidenceHold("P7U_F2_EVIDENCE_HOLD_WIRE_SCHEMA")
    return {k: wire[k] for k in keys}


def analyze(rows: list[dict], *, now_ms: int, fresh_after_ms: int = 1_800_000,
            progress_window_ms: int = 3_600_000,
            collector_fresh_after_ms: int = 180_000) -> dict:
    if not (_nonneg(now_ms) and _nonneg(fresh_after_ms) and fresh_after_ms > 0
            and _nonneg(progress_window_ms) and progress_window_ms > 0
            and _nonneg(collector_fresh_after_ms) and collector_fresh_after_ms > 0):
        raise EvidenceHold("P7U_F2_EVIDENCE_HOLD_REPORT_ARGUMENTS")
    report = {
        "schema": "p7u-f2-passive-freshness-v1",
        "evaluated_at_utc_ms": now_ms, "retained_network_serving": "NOT_ASSESSED",
        "automatic_recovery_permitted": False,
        "evidence_trust": "VERIFIED_CHAIN_REQUIRED_BY_READER",
        "collector_feed": "NO_RECORDS", "collector_last_record_age_s": None,
        "f2_freshness": "NO_CURRENT_OWNER_VALID", "last_valid_f2_age_s": None,
        "native_f2_30m_objective": "NOT_ASSESSED",
        "native_f2_in_last_30m": 0, "native_f2_deadline_seconds": 1800,
        "last_valid_f2_utc_ms": None, "valid_f2_current_owner_count": 0,
        "current_owner_records": 0, "last_native": None,
        "recent_sampling_outcomes": {"VALID": 0, "SKIPPED": 0, "FAILED": 0, "QUARANTINED": 0},
        "recent_skip_reasons": {}, "latest_failed_event": None,
        "passive_srsp_progress": "UNKNOWN", "passive_srsp_delta": None,
        "wire_boundary_status": "NOT_INSTALLED_OR_INSUFFICIENT",
        "wire_boundary_deltas": None,
        "waitress_live_vs_expired": None,
        "native_mt_lifecycle": None,
        "native_mt_lifecycle_delta": None,
        "native_mt_delta_status": "NOT_QUALIFIED",
        "native_uart_progress": None,
    }
    if not rows:
        return report
    last = rows[-1]
    latest_age = _age(now_ms, last.get("utc"))
    report["collector_last_record_age_s"] = (latest_age / 1000 if latest_age is not None else None)
    if latest_age is None:
        report["collector_feed"] = "CLOCK_UNCERTAIN"
    else:
        report["collector_feed"] = (
            "FRESH" if latest_age <= collector_fresh_after_ms else "STALE"
        )
    # Never attribute another restarted owner's good F2 to the current process.
    owner = (last.get("hostRunId"), last.get("ownerGeneration"))
    current = []
    for r in reversed(rows):
        if (r.get("hostRunId"), r.get("ownerGeneration")) != owner:
            break
        current.append(r)
    current.reverse()
    report["current_owner_records"] = len(current)
    accounting = ((current[-1].get("hostEvidence") or {}).get("waitressAccounting")
                  if current else None)
    if accounting is not None:
        required = {"active", "timedOut", "resolved", "rawMapEntries"}
        if (type(accounting) is not dict or set(accounting) != required or
                not all(_nonneg(accounting.get(k)) for k in required) or
                accounting["active"] + accounting["timedOut"] +
                accounting["resolved"] != accounting["rawMapEntries"]):
            raise EvidenceHold("P7U_F2_EVIDENCE_HOLD_WAITRESS_ACCOUNTING")
        report["waitress_live_vs_expired"] = accounting
    valid = [r for r in current if r.get("kind") == "VALID"]
    report["valid_f2_current_owner_count"] = len(valid)
    latest_valid = valid[-1] if valid else None
    thirty_minutes = 1_800_000
    current_native = [r for r in valid if
                      (t := _age(now_ms, r.get("utc"))) is not None and
                      t <= thirty_minutes]
    report["native_f2_in_last_30m"] = len(current_native)
    if current_native:
        report["native_f2_30m_objective"] = "MET"
    else:
        # No previous owner's native records are eligible, even after restart.
        # If no native sample exists since this owner started, use its earliest
        # monotonic uptime as a lower bound on duration (never infer 0).
        latest_uptime = last.get("processUptimeMs")
        uptime_expired = _nonneg(latest_uptime) and latest_uptime >= thirty_minutes
        first_seen_age = _age(now_ms, current[0].get("utc")) if current else None
        report["native_f2_30m_objective"] = (
            "BREACHED" if uptime_expired or
            (first_seen_age is not None and first_seen_age >= thirty_minutes)
            else "NOT_YET_OBSERVED_FOR_30M"
        )
    if latest_valid:
        age = _age(now_ms, latest_valid.get("utc"))
        report["last_valid_f2_age_s"] = age / 1000 if age is not None else None
        report["last_valid_f2_utc_ms"] = latest_valid.get("utc")
        report["f2_freshness"] = (
            "CLOCK_UNCERTAIN" if age is None else
            "FRESH" if age <= fresh_after_ms else "STALE"
        )
        mask = latest_valid.get("validityMask")
        if type(mask) is not int or mask not in (0x2c, 0x3f, 0x00ffffec, 0x00ffffff):
            raise EvidenceHold("P7U_F2_EVIDENCE_HOLD_VALIDITY_MASK")
        native = {
            "sequence": latest_valid.get("sequence"),
            "validity_mask": mask,
            "async_depth": latest_valid.get("asyncDepth"),
            "async_high_water": latest_valid.get("asyncHighWater"),
            "uart_tx_finished_events": latest_valid.get("uartTxFinishedEvents"),
            "srsp_depth": latest_valid.get("srspDepth") if mask & 0x01 else None,
            "srsp_high_water": latest_valid.get("srspHighWater") if mask & 0x02 else None,
        }
        for v in native.values():
            if v is not None and not _nonneg(v):
                raise EvidenceHold("P7U_F2_EVIDENCE_HOLD_INVALID_NATIVE_COUNTER")
        report["last_native"] = native
        report["native_mt_lifecycle"] = _mt_lifecycle(latest_valid)
        if latest_valid.get("minor") in (2, 3) and report["native_mt_lifecycle"] is None:
            raise EvidenceHold("P7U_F2_V42_MISSING_RADIO_CAUSAL_COUNTERS")
        if latest_valid.get("minor") in (2, 3) and mask not in (0x00ffffec, 0x00ffffff):
            raise EvidenceHold("P7U_F2_V42_INVALID_COUNTER_MASK")
        if latest_valid.get("minor") == 1 and mask not in (0x2c, 0x3f):
            raise EvidenceHold("P7U_F2_V41_INVALID_COUNTER_MASK")
        qualified = [v for v in valid if
                     v.get("minor") in (2, 3) and
                     _mt_lifecycle(v) is not None and
                     v.get("radioEpochTag") is not None and
                     v.get("radioEpochTag") == latest_valid.get("radioEpochTag")]
        if len(qualified) >= 2:
            first, last_mt = qualified[0], qualified[-1]
            if (type(first.get("sequence")) is int and
                    type(last_mt.get("sequence")) is int and
                    last_mt["sequence"] > first["sequence"]):
                old, new = _mt_lifecycle(first), _mt_lifecycle(last_mt)
                deltas = {k: new[k] - old[k] for k in MT_LIFECYCLE_FIELDS}
                if any(x < 0 for x in deltas.values()):
                    report["native_mt_delta_status"] = "COUNTER_DISCONTINUITY"
                else:
                    report["native_mt_delta_status"] = (
                        "SAME_OWNER_TOKEN_OBSERVATION_NOT_HARDWARE_ATTESTED")
                    report["native_mt_lifecycle_delta"] = deltas
        report["native_uart_progress"] = latest_valid.get("uartProgress")
        if latest_valid.get("minor") == 3 and not valid_progress(report["native_uart_progress"]):
            raise EvidenceHold("P7U_F2_V43_PROGRESS_INVALID")
    # Count only events in a recent bounded window, same owner, no negative ages.
    recent = [r for r in current if
              (t := _age(now_ms, r.get("utc"))) is not None and
              t <= progress_window_ms]
    for r in recent:
        kind = r.get("kind")
        if kind in report["recent_sampling_outcomes"]:
            report["recent_sampling_outcomes"][kind] += 1
    report["recent_skip_reasons"] = dict(sorted(collections.Counter(
        _safe_reason(r.get("reason")) for r in recent
        if r.get("kind") == "SKIPPED"
    ).items()))
    for r in reversed(recent):
        if r.get("kind") == "FAILED":
            report["latest_failed_event"] = {
                "utc_ms": r["utc"], "reason": _safe_reason(r.get("reason")),
                "class": _safe_reason(r.get("failureClass")),
            }
            break
    evidence_rows = [(r, _host_counts(r)) for r in recent]
    evidence_rows = [(r, c) for r, c in evidence_rows if c is not None]
    if len(evidence_rows) >= 2:
        a, b = evidence_rows[0][1], evidence_rows[-1][1]
        deltas = {}
        for name in SUBSYSTEMS:
            ok = b[name]["ok"] - a[name]["ok"]
            timeout = b[name]["timeout"] - a[name]["timeout"]
            if ok < 0 or timeout < 0:
                report["passive_srsp_progress"] = "COUNTER_DISCONTINUITY"
                return report
            deltas[name] = {"ok": ok, "timeout": timeout}
        report["passive_srsp_progress"] = "OBSERVED_HOST_COUNTERS"
        report["passive_srsp_delta"] = deltas
    wire_rows = [(r, _host_wire(r)) for r in recent]
    wire_rows = [(r, w) for r, w in wire_rows if w is not None]
    if len(wire_rows) >= 2:
        before, after = wire_rows[0][1], wire_rows[-1][1]
        cumulative = ("rxRawBytes", "rxChunks", "unpiParsedFrames",
                      "unpiParseErrors", "txQueuedBytes",
                      "txQueuedFrames", "txQueuedRawBuffers")
        diff = {k: after[k] - before[k] for k in cumulative}
        if any(v < 0 for v in diff.values()):
            report["wire_boundary_status"] = "COUNTER_DISCONTINUITY"
        else:
            report["wire_boundary_deltas"] = {
                **diff, "unpiBufferedBytesLatest": after["unpiBufferedBytes"]}
            af = (report.get("passive_srsp_delta") or {}).get("AF") or {}
            if diff["txQueuedBytes"] > 0 and diff["rxRawBytes"] == 0:
                verdict = "NO_RAW_RX_WHILE_HOST_QUEUES_TX"
            elif diff["rxRawBytes"] > 0 and diff["unpiParsedFrames"] == 0:
                verdict = "RAW_RX_WITHOUT_VALID_UNPI_FRAMES"
            elif (diff["unpiParsedFrames"] > 0 and af.get("ok") == 0
                  and (af.get("timeout") or 0) > 0):
                verdict = "VALID_UNPI_BUT_AF_SRSP_NOT_PROGRESSING"
            elif diff["rxRawBytes"] > 0 and diff["unpiParsedFrames"] > 0:
                verdict = "RAW_RX_AND_UNPI_PROGRESS"
            else:
                verdict = "NO_DETERMINING_CHANGE"
            report["wire_boundary_status"] = verdict
    return report


def main() -> None:
    p = argparse.ArgumentParser(description="Read-only verified F2 freshness; never reset")
    p.add_argument("--history-dir", type=Path, required=True)
    p.add_argument("--fresh-seconds", type=int, default=1800,
                   help="native F2 age objective (default 1800 seconds / 30 min)")
    p.add_argument("--collector-fresh-seconds", type=int, default=180,
                   help="passive collector feed age budget (default 180 seconds)")
    p.add_argument("--window-seconds", type=int, default=3600)
    p.add_argument("--now-ms", type=int, default=None, help="offline replay only")
    args = p.parse_args()
    try:
        rows = read_verified_history(args.history_dir)
        report = analyze(
            rows, now_ms=args.now_ms if args.now_ms is not None else int(time.time() * 1000),
            fresh_after_ms=args.fresh_seconds * 1000,
            progress_window_ms=args.window_seconds * 1000,
            collector_fresh_after_ms=args.collector_fresh_seconds * 1000,
        )
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    except EvidenceHold as exc:
        print(json.dumps({"schema": "p7u-f2-passive-freshness-v1",
                          "evidence_trust": "HOLD", "automatic_recovery_permitted": False,
                          "reason": str(exc)}, sort_keys=True))
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
