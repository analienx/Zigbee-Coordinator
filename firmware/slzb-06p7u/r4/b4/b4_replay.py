"""B4 synthetic incident replay adapter over the existing #87 passive recorder.

This is not an active host collector. Public fixture timestamps are expressly
illustrative; only named historical counts/categories from issue #98 are facts.
No radio epoch, previous counter state or firmware root cause is reconstructed.
"""
from collections import Counter
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from r4_passive_recorder import PassiveR4Recorder, normalize

KNOWN_CASES = frozenset(("p7u_oct16", "p10_oct02", "p10_oct13", "usb_detach"))
EVIDENCE = frozenset(("DIRECT_OBSERVED", "HOSTED_SYNTHETIC", "NOT_MEASURED", "UNKNOWN"))

def item(kind, at, waiter=None):
    event = {"kind": kind, "at_ms": at}
    if waiter is not None:
        event["waiter_id"] = waiter
    normalize(event)  # enforcement even for generated fixtures
    return event

def fixture(case):
    if case not in KNOWN_CASES:
        raise ValueError("unknown historical replay")
    if case == "p7u_oct16":
        # Relative times preserve broad ordering; NOT original private timestamps.
        events = [item("OTA_START", 0), item("OTA_STOP", 35 * 60_000)]
        events += [item("AF_SREQ_TIMEOUT", 35 * 60_000 + i * 41_000, i) for i in range(64)]
        events += [item("ZDO_SREQ_TIMEOUT", 52 * 60_000 + i * 7_000, 1000 + i) for i in range(6)]
        events += [item("ZCL_TIMEOUT", 36 * 60_000 + i * 36_000) for i in range(69)]
        events += [item("HOST_SIGTERM", 79 * 60_000)]
    elif case == "p10_oct02":
        # Count eight is a synthetic replay stimulus, NOT a measured incident count.
        events = [item("AF_SREQ_TIMEOUT", i * 3_000, i) for i in range(8)]
        events += [item("ZDO_SREQ_TIMEOUT", 25_000, 100),
                   item("SYS_SREQ_TIMEOUT", 30_000, 101)]
    elif case == "p10_oct13":
        # Diagnostic responsive AFTER host/radio restart, not before the prior event.
        events = [item("ZDO_SREQ_TIMEOUT", 100, 1),
                  item("DIAG_F0_RESPONSIVE", 30_000)]
    else:
        events = [item("USB_DISCONNECTED", 100)]
    return sorted(events, key=lambda x: x["at_ms"])

def replay(case, *, events=None):
    """Emit a bounded, privacy-safe evidence receipt and alternative explanations.

    Never return raw events, waiter IDs, packet buffers or host paths.
    """
    if case not in KNOWN_CASES:
        raise ValueError("unknown incident")
    rows = fixture(case) if events is None else events
    if type(rows) not in (list, tuple) or len(rows) > 2048:
        raise ValueError("unbounded replay")
    recorder = PassiveR4Recorder(process_generation=1, max_history=256)
    total = Counter()
    prev = None
    for row in rows:
        at, kind, _ = normalize(row)
        if prev is not None and at < prev:
            raise ValueError("nonmonotonic fixture")
        prev = at
        if not recorder.offer(row) or recorder.drain() != 1 or recorder.dropped:
            raise ValueError("replay lost or duplicated evidence")
        total[kind] += 1
    snap = recorder.snapshot()
    alternatives = {
        "p7u_oct16": ("NPI or radio processing latency", "host bridge/parser latency",
                       "device/network request latency", "independent OTA overlap"),
        "p10_oct02": ("coordinator NPI/queue starvation", "bridge/host request loss",
                       "RF-side concurrency"),
        "p10_oct13": ("subsystem-local path delay", "host/bridge parser delay",
                       "radio epoch change before snapshot"),
        "usb_detach": ("host USB bridge hardware/software", "upstream USB re-enumeration",
                       "power/connector path"),
    }
    # "no match" is a description of the replay, NOT proof of zero live failures.
    evidence_level = "DIRECT_OBSERVED" if case == "p7u_oct16" else "HOSTED_SYNTHETIC"
    counts = {key: total.get(key, 0) for key in (
        "AF_SREQ_TIMEOUT", "ZDO_SREQ_TIMEOUT", "SYS_SREQ_TIMEOUT",
        "ZCL_TIMEOUT", "HOST_SIGTERM", "USB_DISCONNECTED",
        "DIAG_F0_RESPONSIVE", "OTA_START", "OTA_STOP",
    )}
    return {
        "schema": "r4-b4-replay-receipt-v1",
        "case": case,
        "evidence": evidence_level,
        "timings": "HOSTED_SYNTHETIC_NOT_EXACT_HISTORICAL_TIMESTAMPS",
        "event_counts_in_fixture": counts,
        "window_ms": snap["window_ms"],
        "window_signals": snap["signals"],
        "root_cause": "UNKNOWN",
        "alternatives": list(alternatives[case]),
        "ota_causal": False,
        "has_ota_chronology": counts["OTA_START"] > 0,
        "radio_epoch_before_failure": "NOT_MEASURED",
        "radio_epoch_after_failure": "UNKNOWN",
        "usb_available": False if counts["USB_DISCONNECTED"] else "NOT_MEASURED",
        "source": "OFFLINE_REFERENCE_ONLY",
    }
