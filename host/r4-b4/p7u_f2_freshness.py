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

SUBSYSTEMS = ("AF", "ZDO", "SYS", "UTIL")
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


def analyze(rows: list[dict], *, now_ms: int, fresh_after_ms: int = 300_000,
            progress_window_ms: int = 3_600_000) -> dict:
    if not (_nonneg(now_ms) and _nonneg(fresh_after_ms) and fresh_after_ms > 0
            and _nonneg(progress_window_ms) and progress_window_ms > 0):
        raise EvidenceHold("P7U_F2_EVIDENCE_HOLD_REPORT_ARGUMENTS")
    report = {
        "schema": "p7u-f2-passive-freshness-v1",
        "evaluated_at_utc_ms": now_ms, "retained_network_serving": "NOT_ASSESSED",
        "automatic_recovery_permitted": False,
        "evidence_trust": "VERIFIED_CHAIN_REQUIRED_BY_READER",
        "collector_feed": "NO_RECORDS", "collector_last_record_age_s": None,
        "f2_freshness": "NO_CURRENT_OWNER_VALID", "last_valid_f2_age_s": None,
        "last_valid_f2_utc_ms": None, "valid_f2_current_owner_count": 0,
        "current_owner_records": 0, "last_native": None,
        "recent_sampling_outcomes": {"VALID": 0, "SKIPPED": 0, "FAILED": 0, "QUARANTINED": 0},
        "recent_skip_reasons": {}, "latest_failed_event": None,
        "passive_srsp_progress": "UNKNOWN", "passive_srsp_delta": None,
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
            "FRESH" if latest_age <= fresh_after_ms else "STALE"
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
    valid = [r for r in current if r.get("kind") == "VALID"]
    report["valid_f2_current_owner_count"] = len(valid)
    latest_valid = valid[-1] if valid else None
    if latest_valid:
        age = _age(now_ms, latest_valid.get("utc"))
        report["last_valid_f2_age_s"] = age / 1000 if age is not None else None
        report["last_valid_f2_utc_ms"] = latest_valid.get("utc")
        report["f2_freshness"] = (
            "CLOCK_UNCERTAIN" if age is None else
            "FRESH" if age <= fresh_after_ms else "STALE"
        )
        mask = latest_valid.get("validityMask")
        if type(mask) not in (int,) or mask not in (0x2c, 0x3f):
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
    return report


def main() -> None:
    p = argparse.ArgumentParser(description="Read-only verified F2 freshness; never reset")
    p.add_argument("--history-dir", type=Path, required=True)
    p.add_argument("--fresh-seconds", type=int, default=300)
    p.add_argument("--window-seconds", type=int, default=3600)
    p.add_argument("--now-ms", type=int, default=None, help="offline replay only")
    args = p.parse_args()
    try:
        rows = read_verified_history(args.history_dir)
        report = analyze(
            rows, now_ms=args.now_ms if args.now_ms is not None else int(time.time() * 1000),
            fresh_after_ms=args.fresh_seconds * 1000,
            progress_window_ms=args.window_seconds * 1000,
        )
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    except EvidenceHold as exc:
        print(json.dumps({"schema": "p7u-f2-passive-freshness-v1",
                          "evidence_trust": "HOLD", "automatic_recovery_permitted": False,
                          "reason": str(exc)}, sort_keys=True))
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
