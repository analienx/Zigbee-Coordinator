#!/usr/bin/env python3
"""File-only independent bridge/reset/startup evidence contract.

The existing serial owner / observer writes input events. This tool performs
no USB, serial, SLZB, HA, HTTP, reset or process operations. Missing firmware
telemetry never qualifies startup recovery. Output remains private evidence.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path

import t832_incident as incident

SCHEMA = "t832-sideband/v1"
KINDS = {"usb_identity", "non_p10_liveness", "cdc", "control_line", "slzb",
         "bridge_uart", "addon_health", "znp_health", "reset_request", "p10_boot"}
TI_RESET_CLASSES = {0: "PWR_ON", 1: "PIN_RESET", 2: "VDDS_LOSS", 4: "VDDR_LOSS",
                    5: "CLK_LOSS", 6: "SYSRESET", 7: "WARMRESET",
                    8: "WAKEUP_FROM_SHUTDOWN", 9: "WAKEUP_FROM_TCK_NOISE"}
ALLOWED_FIELDS = {"schema", "utc", "kind", "observer", "radio_index", "attempt_id",
    "action", "result", "error_code", "device_id", "vid", "pid", "interface",
    "identity_hash", "alive", "rx", "tx", "reinit", "state", "startup_id",
    "startup_utc", "owner", "command", "success", "timed_out", "deadline_ms",
    "tier", "reset_source", "boot_epoch", "firmware_build_id", "uptime_ms"}


def timestamp(value):
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("UTC timestamp required")
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timezone required")
    return parsed.astimezone(dt.timezone.utc)


def validate(event):
    if not isinstance(event, dict) or set(event) - ALLOWED_FIELDS:
        raise ValueError("unknown sideband fields (do not include URLs, credentials or raw responses)")
    if event.get("schema") != SCHEMA or event.get("kind") not in KINDS:
        raise ValueError("unsupported sideband schema/kind")
    timestamp(event.get("utc"))
    observer = event.get("observer")
    if not isinstance(observer, str) or not observer or len(observer) > 80:
        raise ValueError("observer identity required")
    for key, value in event.items():
        if isinstance(value, (dict, list)) or isinstance(value, str) and len(value) > 200:
            raise ValueError(f"unbounded field: {key}")
    for key in ("alive", "success", "timed_out"):
        if key in event and type(event[key]) is not bool:
            raise ValueError(f"boolean required: {key}")
    for key in ("radio_index", "rx", "tx", "reinit", "reset_source", "boot_epoch", "deadline_ms", "uptime_ms"):
        if key in event and (type(event[key]) is not int or not 0 <= event[key] <= 0xFFFFFFFF):
            raise ValueError(f"bounded unsigned integer required: {key}")
    if "radio_index" in event and event["radio_index"] > 31:
        raise ValueError("radio index must be 0..31")
    for key in ("startup_id", "attempt_id", "owner"):
        if key in event and (not isinstance(event[key], str) or not event[key]):
            raise ValueError(f"nonempty string required: {key}")
    if event["kind"] in {"addon_health", "znp_health", "p10_boot"}:
        if type(event.get("radio_index")) is not int:
            raise ValueError("radio binding required")
    if event["kind"] == "addon_health":
        if event.get("state") not in {"started", "stopped", "unknown"} or not event.get("startup_id"):
            raise ValueError("bounded addon state/startup identity required")
        timestamp(event.get("startup_utc"))
    if event["kind"] in {"reset_request", "control_line", "slzb"}:
        if not event.get("attempt_id") or type(event.get("radio_index")) is not int:
            raise ValueError("control evidence needs attempt_id and radio_index")
    if event["kind"] == "reset_request" and event.get("tier") not in {"pin", "software", "power", "bsl", "esp"}:
        raise ValueError("unsupported reset tier")
    if event["kind"] == "znp_health":
        if not event.get("owner") or event.get("command") not in {"SYS_PING", "SYS_VERSION", "ZDO"}:
            raise ValueError("health must originate from the existing ZNP owner")
        if type(event.get("deadline_ms")) is not int or not 1 <= event["deadline_ms"] <= 30000:
            raise ValueError("health probe must be bounded to 30 seconds")
        if type(event.get("success")) is not bool or type(event.get("timed_out")) is not bool:
            raise ValueError("explicit health outcome required")
        if not event.get("startup_id"):
            raise ValueError("health must be startup-correlated")
    return dict(event)


def ingest(store, path, max_bytes=1 << 20):
    # Validate the complete bounded input before any append. Streaming a
    # partial batch into the journal would make malformed evidence look valid.
    with path.open("rb") as stream:
        raw = stream.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError("sideband input exceeds byte limit")
    lines = raw.decode("utf-8").splitlines()
    if len(lines) > 1000:
        raise ValueError("sideband input exceeds event limit")
    rows = [validate(json.loads(line)) for line in lines if line.strip()]
    with store.locked():
        # Persist boot epochs independently of collector restarts, without
        # claiming every source discontinuity proves a hardware reboot.
        state_path = store.state / "sideband.json"
        state = store.load_strict(state_path) if state_path.exists() else {"boot_epoch": 0, "boots": {}}
        if (not isinstance(state, dict) or type(state.get("boot_epoch")) is not int or
                state["boot_epoch"] < 0 or not isinstance(state.get("boots"), dict)):
            raise RuntimeError("sideband-state-corrupt")
        for event in rows:
            if event["kind"] == "p10_boot":
                radio = str(event["radio_index"])
                previous = state["boots"].get(radio)
                if previous is not None and (not isinstance(previous, dict) or "utc" not in previous):
                    raise RuntimeError("sideband-boot-frontier-corrupt")
                if previous is None or timestamp(event["utc"]) > timestamp(previous["utc"]):
                    state["boot_epoch"] += 1
                    state["boots"][radio] = {"utc": event["utc"], "observer": event["observer"]}
        for event in rows:
            store.append_host_event("t832_sideband", domain="bridge", sideband=event)
        store.atomic_json(state_path, state)
    return {"ok": True, "events": len(rows), "boot_epoch": state["boot_epoch"]}


def extract(host_rows):
    events = []
    for row in host_rows:
        try:
            value = json.loads(str(row.get("raw_line", "")))
            if value.get("kind") == "t832_sideband":
                events.append(validate(value["sideband"]))
        except (ValueError, TypeError, KeyError, AttributeError):
            continue
    return sorted(events, key=lambda event: timestamp(event["utc"]))


def correlate(events):
    """Absence or class mismatch stays evidence, never recovery success."""
    requests = [e for e in events if e["kind"] == "reset_request"]
    result = []
    expected = {"pin": "PIN_RESET", "software": "SYSRESET", "power": "PWR_ON"}
    for request in requests[-32:]:
        later = [e for e in events if e["kind"] == "p10_boot"
                 and timestamp(e["utc"]) > timestamp(request["utc"])
                 and e.get("radio_index") == request.get("radio_index")]
        # A subsequent reset supersedes the attempt; its BOOT cannot be
        # attributed to this earlier request simply because it is later.
        next_request = next((e for e in requests if timestamp(e["utc"]) > timestamp(request["utc"])
                             and e.get("radio_index") == request.get("radio_index")), None)
        if next_request:
            later = [e for e in later if timestamp(e["utc"]) < timestamp(next_request["utc"])]
        boot = later[0] if later else None
        reset_class = TI_RESET_CLASSES.get(boot.get("reset_source"), "UNKNOWN") if boot else None
        result.append({"attempt_id": request["attempt_id"], "radio_index": request["radio_index"],
                       "requested_tier": request["tier"], "observed_reset_class": reset_class,
                       "outcome": "no-subsequent-boot-reset-path-unproven" if boot is None else
                       "expected-reset-class" if expected.get(request["tier"]) == reset_class else
                       "unexpected-or-unclassified-reset-class", "boot": boot})
    return {"schema": SCHEMA, "observed_kinds": sorted({e["kind"] for e in events}),
            "reset_attempts": result, "note": "UART silence is loss of observability; no CPU-death inference."}


def startup_verdict(events, startup_id, now):
    matching = [e for e in events if e.get("startup_id") == startup_id]
    addon = [e for e in matching if e["kind"] == "addon_health"]
    probes = [e for e in matching if e["kind"] == "znp_health"]
    if not addon or not probes:
        return {"qualifies": False, "reason": "missing-addon-or-owner-znp-evidence"}
    addon, probe = addon[-1], probes[-1]
    if addon.get("radio_index") != probe.get("radio_index"):
        return {"qualifies": False, "reason": "addon-probe-radio-mismatch"}
    for event in (addon, probe):
        age = (now - timestamp(event["utc"])).total_seconds()
        if not 0 <= age <= 60:
            return {"qualifies": False, "reason": "stale-or-future-health-evidence"}
    if addon.get("state") != "started" or probe.get("success") is not False or probe.get("timed_out") is not True:
        return {"qualifies": False, "reason": "no-confirmed-running-addon-znp-timeout"}
    if timestamp(probe["utc"]) < timestamp(addon["utc"]):
        return {"qualifies": False, "reason": "probe-precedes-addon-observation"}
    # Require a bounded grace period after startup, independent of MQTT state.
    if not addon.get("startup_utc") or not 60 <= (now - timestamp(addon["startup_utc"])).total_seconds() <= 600:
        return {"qualifies": False, "reason": "outside-startup-grace-window"}
    return {"qualifies": True, "reason": "startup-owner-znp-timeout", "startup_id": startup_id,
            "radio_index": probe.get("radio_index"), "owner": probe["owner"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-root", required=True, type=Path)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--startup-id", help="Evaluate persisted startup evidence without MQTT or any live I/O")
    args = parser.parse_args()
    if bool(args.input) == bool(args.startup_id):
        parser.error("choose exactly one of --input or --startup-id")
    store = incident.Store(args.state_root)
    if args.input:
        result = ingest(store, args.input)
    else:
        # Bounded tail; absence or truncation fails closed. The capture barrier
        # validates again from its private incident, not this caller verdict.
        rows = []
        if store.host_events.exists():
            with store.host_events.open("rb") as stream:
                size = stream.seek(0, 2)
                stream.seek(max(0, size - (1 << 20)))
                raw = stream.read(1 << 20)
            if size > (1 << 20):
                raw = raw.split(b"\n", 1)[-1]
            for line in raw.decode("utf-8", errors="replace").splitlines():
                rows.append({"raw_line": line})
        result = startup_verdict(extract(rows), args.startup_id, incident.utcnow())
        result["event_type"] = "t832_startup_health"
        result["event_data"] = {"startup_id": args.startup_id}
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
