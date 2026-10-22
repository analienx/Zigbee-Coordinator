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
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError

NOTIFICATION_ID = "p7u_coordinator_hang_warning"
TEST_NOTIFICATION_ID = "p7u_coordinator_recovery_acceptance_test"
_TYPES = frozenset(("DETECTED", "RECOVERED", "RECOVERY_FAILED"))
_REASONS = frozenset((
    "ADAPTER_SPECIFIC_START_FAILURE", "MULTI_DEVICE_AF_ZNP_STARVATION",
    "ESP_STAGE_FAILED_RADIO_FALLBACK_ONCE", "RADIO_FALLBACK_FAILED_NO_MORE_RESTARTS",
    "ESP_VERIFY_TIMEOUT_AMBIGUOUS", "RADIO_VERIFY_TIMEOUT_AMBIGUOUS",
    "REAL_TRAFFIC_VERIFIED_AFTER_ESP", "REAL_TRAFFIC_VERIFIED_AFTER_RADIO",
    "AMBIGUOUS_ACTION", "RECOVERY_BUDGET_OR_COOLDOWN_EXHAUSTED",
))
MAX_NOTIFICATION_ATTEMPTS = 3
NOTIFICATION_RETRY_SECONDS = 60


def _reason(reason: str) -> str:
    return reason if reason in _REASONS else "COORDINATOR_HEALTH_DEGRADED"


def _time(t: int) -> str:
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _content(kind: str, incident: int, reason: str) -> tuple[str, str, str]:
    if kind not in _TYPES or incident <= 0:
        raise ValueError("BAD_INCIDENT_OR_STATUS")
    # Reason is strictly from a finite internal enum; never include raw
    # Z2M log lines, MQTT packet bodies, credentials, NWK keys, or IEEE.
    reason = _reason(reason)
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


def _sync_directory(directory: Path):
    if os.name == "posix":
        dfd = os.open(str(directory), os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)


def _save(path: Path, data: dict):
    fd, temporary = tempfile.mkstemp(prefix=".alert-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, path)
        _sync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _journal_once(directory: Path, incident: int, kind: str, channel: str,
                  attempt: int = 1):
    """Durably reserve this attempt before its service call."""
    if channel not in ("system_log", "notification"):
        raise ValueError("BAD_CHANNEL")
    suffix = "" if attempt == 1 else f"-{attempt}"
    path = directory / f"incident-{incident}-{kind}-{channel}.attempt{suffix}.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"schema": "p7u-ha-visible-incident-v1", "incident": incident,
                   "event": kind, "channel": channel,
                   "attempt": attempt, "intent_utc": int(time.time())}, f)
        f.flush()
        os.fsync(f.fileno())
    _sync_directory(directory)
    return path


class HAIncidentReporter:
    def __init__(self, supervisor, directory: Path):
        self.supervisor = supervisor
        self.directory = Path(directory)

    def _check_directory(self):
        if not self.directory.is_dir() or self.directory.is_symlink():
            raise ValueError("PRIVATE_JOURNAL_MISSING")

    def _send(self, incident, kind, channel, payload, *, attempt=1):
        try:
            marker = _journal_once(self.directory, incident, kind, channel, attempt)
        except FileExistsError:
            return "ALREADY_ATTEMPTED_NO_REPEAT"
        endpoint = "system_log/write" if channel == "system_log" else "persistent_notification/create"
        retryable = channel == "notification"
        try:
            response = self.supervisor.call("/core/api/services/" + endpoint,
                                            method="POST", payload=payload)
            if not isinstance(response, list):
                raise ValueError("INVALID_HA_SERVICE_RESPONSE")
        except HTTPError as exc:
            status = f"REJECTED_HTTP_{exc.code}"
            retryable = retryable and (exc.code in (408, 429) or exc.code >= 500)
        except Exception as exc:
            status = ("NOT_CONFIRMED_RETRY_PENDING_" if channel == "notification"
                      else "NOT_CONFIRMED_NO_REPEAT_") + type(exc).__name__
        else:
            status = "ACCEPTED"
            retryable = False
        # The intent survives a crash during either the request or this write.
        _save(marker.with_name(marker.name.replace(".attempt", ".outcome")), {
            "status": status, "attempt": attempt,
            "recorded_utc": int(time.time()), "retryable": retryable,
        })
        return status

    def _latest_path(self, test=False):
        return self.directory / ("notification-test-latest.json" if test else "notification-latest.json")

    @staticmethod
    def _order(document):
        return (document["incident"], {"DETECTED": 0, "RECOVERY_FAILED": 1,
                                      "RECOVERED": 2, "TEST": 0}[document["kind"]])

    def _notification(self, document):
        incident, kind = document["incident"], document["kind"]
        existing = []
        for attempt in range(1, MAX_NOTIFICATION_ATTEMPTS + 1):
            suffix = "" if attempt == 1 else f"-{attempt}"
            path = self.directory / f"incident-{incident}-{kind}-notification.attempt{suffix}.json"
            if not path.exists():
                break
            existing.append(path)
        if existing:
            path = existing[-1]
            outcome_path = path.with_name(path.name.replace(".attempt", ".outcome"))
            outcome = json.loads(outcome_path.read_text()) if outcome_path.exists() else {}
            if outcome.get("status") == "ACCEPTED":
                return "ALREADY_ATTEMPTED_NO_REPEAT_ACCEPTED"
            if outcome and not outcome.get("retryable"):
                return "DELIVERY_REJECTED_NO_RETRY"
            if len(existing) >= MAX_NOTIFICATION_ATTEMPTS:
                return "DELIVERY_RETRY_BUDGET_EXHAUSTED"
            intent = json.loads(path.read_text())
            if time.time() - intent.get("intent_utc", path.stat().st_mtime) < NOTIFICATION_RETRY_SECONDS:
                return "DELIVERY_PENDING_RETRY"
        return self._send(incident, kind, "notification", document["payload"],
                          attempt=len(existing) + 1)

    def _report(self, kind, incident, reason, *, test=False):
        self._check_directory()
        reason = _reason(reason)
        if test:
            if incident <= 0:
                raise ValueError("BAD_INCIDENT_OR_STATUS")
            title = "TEST — P7U recovery warning acceptance"
            message = ("Synthetic notification test. No coordinator hang was detected; "
                       "no recovery, reset, serial, or flash action was requested.")
            level = "warning"
            kind = "TEST"
        else:
            title, message, level = _content(kind, incident, reason)
        log_payload = {"level": level, "message":
                       f"P7U coordinator {kind.lower()} incident={incident} reason={reason}"}
        if test:
            log_payload["message"] = f"TEST P7U synthetic warning acceptance incident={incident}; no reset or recovery requested"
        document = {"incident": incident, "kind": kind,
                    "payload": {"title": title, "message": message,
                                "notification_id": TEST_NOTIFICATION_ID if test else NOTIFICATION_ID}}
        latest_path = self._latest_path(test)
        latest = json.loads(latest_path.read_text()) if latest_path.exists() else None
        if latest is None or self._order(document) >= self._order(latest):
            _save(latest_path, document)
        result = {"system_log": self._send(incident, kind, "system_log", log_payload)}
        if latest is not None and self._order(document) < self._order(latest):
            result["notification"] = "SUPERSEDED_NO_SEND"
        else:
            result["notification"] = self._notification(document)
        return result

    def report(self, kind: str, incident: int, reason: str) -> dict:
        return self._report(kind, incident, reason)

    def report_test(self, incident: int) -> dict:
        return self._report("TEST", incident, "SYNTHETIC_TEST", test=True)

    def retry_pending(self) -> dict:
        """Only retry the latest idempotent notification, at most three sends."""
        self._check_directory()
        path = self._latest_path()
        if not path.exists():
            return {"notification": "NONE_PENDING"}
        return {"notification": self._notification(json.loads(path.read_text()))}
