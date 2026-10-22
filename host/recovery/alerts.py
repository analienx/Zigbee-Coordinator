"""One visible Home Assistant WARNING per confirmed coordinator incident.

Two independent sinks:
  1. system_log.write with level=warning (Home Assistant System Log)
  2. persistent_notification.create with a stable notification_id (HA bell UI).
Does not publish MQTT, open Zigbee serial or reset hardware.

Each sink's intent is fsynced to private disk *before* any service request so
ambiguous responses cannot spam repeated alerts. The notification is overwritten
by the same ID on resolution/failure, never dismissed behind the user's back.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

NOTIFICATION_ID = "p7u_coordinator_hang_warning"
_TYPES = frozenset(("DETECTED", "RECOVERED", "RECOVERY_FAILED"))


def _time(t: int) -> str:
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _content(kind: str, incident: int, reason: str) -> tuple[str, str, str]:
    if kind not in _TYPES or incident <= 0:
        raise ValueError("BAD_INCIDENT_OR_STATUS")
    # Reason is strictly from a finite internal enum; never include raw
    # Z2M log lines, MQTT packet bodies, credentials, NWK keys, or IEEE.
    if reason not in (
        "ADAPTER_SPECIFIC_START_FAILURE", "MULTI_DEVICE_AF_ZNP_STARVATION",
        "ESP_STAGE_FAILED_RADIO_FALLBACK_ONCE", "RADIO_FALLBACK_FAILED_NO_MORE_RESTARTS",
        "ESP_VERIFY_TIMEOUT_AMBIGUOUS", "RADIO_VERIFY_TIMEOUT_AMBIGUOUS",
        "REAL_TRAFFIC_VERIFIED_AFTER_ESP", "REAL_TRAFFIC_VERIFIED_AFTER_RADIO",
        "AMBIGUOUS_ACTION", "RECOVERY_BUDGET_OR_COOLDOWN_EXHAUSTED",
    ):
        reason = "COORDINATOR_HEALTH_DEGRADED"
    timestamp = _time(incident)
    if kind == "DETECTED":
        title = "⚠️ WARNING — Zigbee coordinator hang detected"
        body = (
            f"**Incident:** {timestamp}\n\n"
            "**Coordinator:** SMLIGHT SLZB-06P7U (USB)\n\n"
            f"**Observed fault:** `{reason}`\n\n"
            "**State:** Confirmed. Evidence capture and bounded ESP-first recovery "
            "are the next steps. Do not factory-reset or repeatedly restart "
            "Zigbee2MQTT.\n\n"
            "The warning will be updated when recovery is verified or blocked."
        )
    elif kind == "RECOVERED":
        title = "✅ Zigbee coordinator recovered"
        body = (
            f"**Incident:** {timestamp}\n\n"
            "**State:** Zigbee2MQTT restarted and fresh device messages were "
            "verified. This is not proof all Zigbee routes are healthy."
        )
    else:
        title = "⚠️ WARNING — Zigbee recovery needs attention"
        body = (
            f"**Incident:** {timestamp}\n\n"
            "**State:** Automatic recovery is blocked or exhausted. "
            "No further reset attempts will be issued. "
            f"**Reason:** `{reason}`."
        )
    log_level = "warning" if kind != "RECOVERED" else "info"
    return title, body, log_level


def _journal_once(directory: Path, incident: int, kind: str, channel: str):
    """Durably record the one-shot intent, with no duplicate service calls."""
    if channel not in ("system_log", "notification"):
        raise ValueError("BAD_CHANNEL")
    path = directory / f"incident-{incident}-{kind}-{channel}.attempt.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"schema": "p7u-ha-visible-incident-v1", "incident": incident,
                   "event": kind, "channel": channel,
                   "sent_at": datetime.now(timezone.utc).isoformat()}, f)
        f.flush()
        os.fsync(f.fileno())
    if os.name == "posix":
        dfd = os.open(str(directory), os.O_RDONLY)
        try: os.fsync(dfd)
        finally: os.close(dfd)
    return path


class HAIncidentReporter:
    def __init__(self, supervisor, directory: Path):
        self.supervisor = supervisor
        self.directory = Path(directory)

    def report(self, kind: str, incident: int, reason: str) -> dict:
        title, message, level = _content(kind, incident, reason)
        # Only existing, private local filesystem is allowed.
        if not self.directory.is_dir() or self.directory.is_symlink():
            raise ValueError("PRIVATE_JOURNAL_MISSING")
        outcome = {}
        for channel in ("system_log", "notification"):
            try:
                marker = _journal_once(self.directory, incident, kind, channel)
            except FileExistsError:
                outcome[channel] = "ALREADY_ATTEMPTED_NO_REPEAT"
                continue
            try:
                if channel == "system_log":
                    self.supervisor.call(
                        "/core/api/services/system_log/write",
                        method="POST",
                        payload={"level": level, "message":
                                 f"P7U coordinator {kind.lower()} "
                                 f"incident={incident} reason={reason}"})
                else:
                    self.supervisor.call(
                        "/core/api/services/persistent_notification/create",
                        method="POST",
                        payload={"title": title, "message": message,
                                 "notification_id": NOTIFICATION_ID})
            except Exception as exc:
                # Do not repeat an ambiguous API call and create many warnings.
                outcome[channel] = "NOT_CONFIRMED_NO_REPEAT_" + type(exc).__name__
            else:
                outcome[channel] = "ACCEPTED"
        return outcome
