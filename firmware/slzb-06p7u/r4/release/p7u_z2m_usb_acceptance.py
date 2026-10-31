"""One-shot HA USB/Zigbee2MQTT acceptance with bounded logs and private evidence.

Never flashes, resets, re-pairs, restores NV or retries the service automatically.
Requires a verified source-bound R4 operator startup receipt. Python stdlib only.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from p7u_z2m_usb_health import since_start, start_local_time
import time

ADDON = "45df7312_zigbee2mqtt"
USB = "/dev/serial/by-id/usb-SMLIGHT_SMLIGHT_SLZB-06p7U_SLZB-06p7U115236-if00"
OK_LOG = ("zigbee2mqtt started", "zigbee-herdsman started",
          "connected to mqtt server", "connected to mqtt broker",
          "mqtt publish: topic 'zigbee2mqtt/")
ERR_LOG = ("failed to start zigbee-herdsman", "error while starting",
           "areq - sys - resetind", "error: srsp", "failed to start")
SOURCE = "323949a95c9a07901c4ffc3d026fca414982c148"


def ssh(remote: str, timeout: int = 18) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=6", "ha", remote],
        text=True, capture_output=True, timeout=timeout, check=False)


def require(ok: bool, message: str) -> None:
    if not ok:
        raise RuntimeError("USB_Z2M_HOLD_" + message)


def redacted(text: str) -> str:
    text = re.sub(r"(?i)(network_key|password|auth_token|secret|apikey)\s*[:=]\s*[^\s,]+",
                  r"\1=<redacted>", text)
    text = re.sub(r"(?i)(Bearer\s+)\S+", r"\1<redacted>", text)
    return re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", text)


def addon_info() -> dict:
    result = ssh(f"ha apps info {ADDON} --raw-json")
    require(result.returncode == 0, "ADDON_INFO_FAILED")
    return json.loads(result.stdout)["data"]


def logs() -> list[str]:
    result = ssh(f"ha apps logs {ADDON} -n 400")
    require(result.returncode == 0, "ADDON_LOGS_UNAVAILABLE")
    return redacted(result.stdout).splitlines()


def after_baseline(lines: list[str], baseline: list[str],
                   started_local: dt.datetime | None = None) -> list[str]:
    if not baseline:
        return lines
    # The log tail can shift as new messages appear. Anchor on a suffix of
    # pre-start lines; never classify historical errors as new ones.
    for n in (3, 2, 1):
        if len(baseline) < n:
            continue
        needle = baseline[-n:]
        for i in range(len(lines) - n, -1, -1):
            if lines[i:i+n] == needle:
                return lines[i+n:]
    # High-volume Zigbee activity may evict ALL pre-start lines from the
    # bounded tail. Filter by the preserved, HA-timezone-aware start timestamp.
    return since_start(lines, started_local) if started_local else []


def stage_receipts(private: Path) -> dict:
    flash = json.loads((private / "flash-result.json").read_text())
    start = json.loads((private / "startup-result.json").read_text())
    require(flash.get("status") == "APP_AND_AC000_VERIFIED_STILL_IN_BSL"
            and flash.get("nv_touched") is False and flash.get("ccfg_touched") is False,
            "FLASH_RECEIPT_NOT_VERIFIED")
    require(start.get("status") == "COORDINATOR_STATE9_MARKER_PASS"
            and start.get("post_state") == 9 and start.get("source") == SOURCE
            and start.get("attempts") == 1, "STATE9_SOURCE_NOT_VERIFIED")
    return {"flash": "PASS", "source": SOURCE, "coordinator_state": 9,
            "written_sectors": len(flash["written_sectors"])}


def preflight(private: Path) -> dict:
    receipt = stage_receipts(private)
    found = ssh("test -e " + USB + " && readlink -f " + USB)
    require(found.returncode == 0 and "/dev/ttyACM" in found.stdout,
            "USB_BY_ID_NOT_CONNECTED")
    info = addon_info()
    opts = info.get("options") or {}
    serial = opts.get("serial") or {}
    require(serial.get("port") == USB and serial.get("adapter") == "zstack"
            and serial.get("baudrate") == 115200
            and serial.get("rtscts") is False, "SERIAL_OPTIONS_MISMATCH")
    require(info.get("watchdog") is False, "WATCHDOG_MUST_BE_OFF_FOR_ONCE")
    return {**receipt, "usb_device": found.stdout.strip(), "addon_before": info["state"],
            "addon_version": info.get("version"), "watchdog": False}


def classify(state: str, messages: list[str]) -> dict:
    text = "\n".join(messages).lower()
    ok = [phrase for phrase in OK_LOG if phrase in text]
    err = [phrase for phrase in ERR_LOG if phrase in text]
    return {"status": "FAILED" if (state == "error" or err) else
            "RUNNING_LOGS_CONFIRMED" if (state == "started" and ok) else
            "RUNNING_NO_STARTUP_LOG_PROOF" if state == "started" else
            "PENDING", "positive": ok, "negative": err}


def write_exclusive(path: Path, payload: dict) -> None:
    with path.open("x", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private", type=Path, required=True)
    parser.add_argument("--start-once", action="store_true")
    parser.add_argument("--watch-seconds", type=int, default=180)
    args = parser.parse_args()
    require(10 <= args.watch_seconds <= 600, "BOUNDED_WATCH_REQUIRED")
    before = preflight(args.private)
    print("USB_PREFLIGHT_PASS", json.dumps(before, sort_keys=True), flush=True)
    if not args.start_once:
        return 0
    require(before["addon_before"] != "started", "ALREADY_STARTED_NO_NEW_ACTION")
    evidence = args.private / "z2m-usb-once"
    evidence.mkdir(exist_ok=True)
    stamp = {"schema": "p7u-r4-z2m-usb-once-v1",
             "source": SOURCE, "started_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
             "preflight": before}
    # Durable before the first non-read-only operation, never replay.
    write_exclusive(evidence / "start-attempt.json", stamp)
    baseline = logs()
    ha_offset = ssh("date +%z").stdout.strip()
    started_local = start_local_time(stamp["started_at_utc"], ha_offset)
    command = ssh(f"ha apps start {ADDON} --raw-json", timeout=75)
    print("HA_START_CMD", command.returncode, redacted(command.stdout)[-500:],
          redacted(command.stderr)[-350:], flush=True)
    observations = []
    start = time.monotonic()
    final = None
    while time.monotonic() - start < args.watch_seconds:
        info = addon_info()
        state = info.get("state", "unknown")
        new = after_baseline(logs(), baseline, started_local)
        outcome = classify(state, new)
        observations.append({"elapsed_s": round(time.monotonic() - start, 1),
                             "addon_state": state, "diagnosis": outcome,
                             "new_log_lines": len(new)})
        print("USB_Z2M_OBSERVE", json.dumps(observations[-1]), flush=True)
        if outcome["status"] == "FAILED":
            final = "START_FAILED"; break
        if outcome["status"] == "RUNNING_LOGS_CONFIRMED":
            # Continue a short bounded stability watch for delayed crashes.
            if time.monotonic() - start >= min(60, args.watch_seconds - 5):
                final = "STARTED_LOGS_CONFIRMED"; break
        time.sleep(6)
    if final is None:
        final = "WATCH_TIMEOUT_NO_PASS" if observations[-1]["diagnosis"]["status"] not in (
            "RUNNING_LOGS_CONFIRMED",) else "STARTED_LOGS_CONFIRMED"
    # Store only bounded, redacted diagnostic messages, never credentials,
    # Zigbee network keys, coordinator backup or full device state.
    tail = after_baseline(logs(), baseline, started_local)
    report = {"schema": "p7u-r4-usb-z2m-acceptance-v1", "result": final,
              "source": SOURCE, "preflight": before,
              "ha_start_command_exit_code": command.returncode,
              "observations": observations,
              "startup_log_tail": [x.split(", payload ")[0] for x in tail[-70:]],
              "ended_at_utc": dt.datetime.now(dt.timezone.utc).isoformat()}
    write_exclusive(evidence / "diagnosis.json", report)
    print("USB_Z2M_RESULT", json.dumps(
        {k: report[k] for k in ("result", "source", "ha_start_command_exit_code")},
        sort_keys=True), flush=True)
    print("USB_Z2M_REPORT", evidence / "diagnosis.json", flush=True)
    return 0 if final == "STARTED_LOGS_CONFIRMED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
