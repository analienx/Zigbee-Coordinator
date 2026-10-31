"""Read-only Zigbee2MQTT USB recovery diagnosis from existing one-shot attempt.

Reads Supervisor state and bounded log tail. Classifies only post-start
timestamps; counts natural device MQTT messages and distinct route failures.
No resets, firmware actions, Z2M starts/stops or Zigbee network modifications.
"""
from __future__ import annotations

import argparse
import collections
import datetime as dt
import json
from pathlib import Path
import re
import subprocess

ADDON = "45df7312_zigbee2mqtt"
LOG_TIME = re.compile(r"^\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\]")
TOPIC = re.compile(r"MQTT publish: topic 'zigbee2mqtt/([^']+)'")
NO_ROUTE = re.compile(r"Failed to ping '([^']+)'|Data request failed.*?NWK_NO_ROUTE")
ERR = ("error while starting", "failed to start zigbee-herdsman",
       "areq - sys - resetind", "network key mismatch",
       "failed to connect to mqtt")


def ha(command: str, timeout: int = 40) -> str:
    result = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o",
                             "ConnectTimeout=6", "ha", command],
                            capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError("HA_QUERY_FAILED: " + command.split()[0] +
                           ": " + result.stderr[-220:])
    return result.stdout


def start_local_time(start_iso_utc: str, offset: str) -> dt.datetime:
    utc = dt.datetime.fromisoformat(start_iso_utc)
    if utc.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    if not re.fullmatch(r"[+-]\d{4}", offset):
        raise ValueError("HA numeric UTC offset missing")
    hours = int(offset[1:3])
    minutes = int(offset[3:5])
    sign = 1 if offset[0] == "+" else -1
    return utc.astimezone(dt.timezone(sign * dt.timedelta(hours=hours,
                                                        minutes=minutes)))


def since_start(lines: list[str], started: dt.datetime) -> list[str]:
    filtered = []
    for line in lines:
        m = LOG_TIME.match(line)
        if m:
            local = dt.datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
            local = local.replace(tzinfo=started.tzinfo)
            if local >= started - dt.timedelta(seconds=2):
                filtered.append(line)
    return filtered


def diagnostic(messages: list[str], state: str) -> dict:
    text = "\n".join(messages).lower()
    topics = []
    route = collections.Counter()
    for line in messages:
        m = TOPIC.search(line)
        if m:
            topic = m.group(1)
            if not topic.startswith("bridge/") and not topic.endswith("/availability"):
                topics.append(topic)
        n = NO_ROUTE.search(line) if "NWK_NO_ROUTE" in line else None
        if n:
            route[n.group(1) or "unknown"] += 1
    bad = [x for x in ERR if x in text]
    positive = {
        "zigbee_herdsman_started": "zigbee-herdsman started" in text,
        "zigbee2mqtt_started": "zigbee2mqtt started" in text,
        "mqtt_server_connected": "connected to mqtt server" in text,
        "live_device_mqtt": len(set(topics)) >= 3,
    }
    if state != "started":
        status = "NOT_RUNNING"
    elif bad:
        status = "STARTUP_ERRORS_OBSERVED"
    elif positive["live_device_mqtt"]:
        status = "RUNNING_WITH_LIVE_DEVICE_MQTT"
    elif any(positive.values()):
        status = "RUNNING_WITH_STARTUP_EVIDENCE"
    else:
        status = "STARTED_WITHOUT_ENOUGH_LOG_EVIDENCE"
    return {"status": status, "addon_state": state,
            "total_recent_log_lines": len(messages),
            "mqtt_device_messages": len(topics),
            "distinct_mqtt_device_topics": len(set(topics)),
            "sample_mqtt_devices": sorted(set(topics))[:12],
            "nwk_no_route_counts": dict(route.most_common(20)),
            "startup_error_signatures": bad, "positive": positive}


def check(private: Path, n: int) -> dict:
    attempt = json.loads((private / "z2m-usb-once/start-attempt.json").read_text())
    offset = ha("date +%z").strip()
    started = start_local_time(attempt["started_at_utc"], offset)
    information = json.loads(ha("ha apps info " + ADDON + " --raw-json"))["data"]
    output = ha(f"ha apps logs {ADDON} -n {n}", timeout=80)
    matched = since_start(output.splitlines(), started)
    details = diagnostic(matched, information.get("state", "unknown"))
    # Distinguish short-term route discovery during startup from ongoing
    # problems without issuing any Zigbee pings or sending user commands.
    late = since_start(matched, started + dt.timedelta(seconds=90))
    late_report = diagnostic(late, information.get("state", "unknown"))
    details["routing_after_90s"] = late_report["nwk_no_route_counts"]
    details["mqtt_device_topics_after_90s"] = late_report["distinct_mqtt_device_topics"]
    persistent = len(late_report["nwk_no_route_counts"])
    details["routing_health"] = ("DEGRADED_PERSISTENT_NO_ROUTE"
                                  if persistent >= 3 else
                                  "WARN_TRANSIENT_NO_ROUTE" if persistent else
                                  "NO_ROUTE_WARNINGS_NOT_OBSERVED")
    details["overall_acceptance"] = (
        "PARTIAL_ROUTING_DEGRADED" if details["status"] ==
        "RUNNING_WITH_LIVE_DEVICE_MQTT" and persistent >= 3 else
        "USB_MQTT_PASS" if details["status"] ==
        "RUNNING_WITH_LIVE_DEVICE_MQTT" else
        "HOLD_STARTUP_OR_TRAFFIC_UNPROVEN")
    details.update({"source": attempt["source"],
                    "usb_port_correct": (
                        information.get("options", {}).get("serial", {}).get("port")
                        == "/dev/serial/by-id/usb-SMLIGHT_SMLIGHT_SLZB-06p7U_SLZB-06p7U115236-if00"),
                    "started_at": started.isoformat(),
                    "observed_last_log_at": LOG_TIME.match(matched[-1]).group(1)
                                            if matched else None})
    return details


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private", type=Path, required=True)
    parser.add_argument("--lines", type=int, default=1600)
    parser.add_argument("--save", action="store_true")
    args = parser.parse_args()
    if not 100 <= args.lines <= 8000:
        parser.error("--lines must be 100..8000")
    report = check(args.private, args.lines)
    print("USB_Z2M_HEALTH", json.dumps(report, sort_keys=True, indent=2))
    if args.save:
        target = args.private / "z2m-usb-once/poststart-health.json"
        target.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n",
                          encoding="utf-8")
        print("USB_Z2M_HEALTH_EVIDENCE", target)
    return 0 if report["status"] == "RUNNING_WITH_LIVE_DEVICE_MQTT" else 2


if __name__ == "__main__":
    raise SystemExit(main())
