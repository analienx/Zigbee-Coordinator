"""Durably one-shot EXECUTOR SHELL for the shared P7U recovery policy.

This is NOT a Home Assistant integration and has NO DEVICE ACTUATORS.
Caller must supply independently reviewed HA adapter methods. No HTTP,
serial, ZNP, shell, Zigbee, MQTT or ESP commands implemented here.
Default is dry run; all active calls require 'enabled=True' explicitly.
"""
from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import json
import os
from pathlib import Path
from typing import Protocol

from policy import Decision, Observation, _prohibited

_ACTION_PHASE = {
    "CAPTURE_EVIDENCE": "CAPTURE_PENDING",
    "STOP_Z2M": "STOP_PENDING",
    "RESET_RADIO": "RADIO_RESET_PENDING",
    "START_Z2M": ("RADIO_START_PENDING", "ESP_START_PENDING"),
    "RESTART_ESP": "ESP_RESET_PENDING",
}


class HAActuator(Protocol):
    """A separate, source-audited owner of HA/SMLIGHT REST or native buttons.

    Any implementation must use HA's native SMLIGHT Zigbee restart button
    and HA add-on controls, never a raw ZNP tty or ambiguous hard reset.
    """
    def perform_once(self, action: str) -> bool:
        """Return only service-level acknowledgement, NOT recovery success."""
        ...


@dataclass(frozen=True)
class Receipt:
    status: str
    attempt_file: str = ""
    detail: str = ""


def _atomic_unique(path: Path, document: dict) -> None:
    """Single-writer durable create: never retry an ambiguous command.

    An exclusive attempt receipt is written and fsynced BEFORE side effects.
    An existing attempt file blocks issuing a second command across crashes.
    """
    payload = (json.dumps(document, sort_keys=True, indent=2) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        raise
    # Best effort directory flush for POSIX; Windows file fsync still applies.
    if os.name == "posix":
        directory = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def dispatch(
    decision: Decision,
    observation: Observation,
    actuator: HAActuator,
    evidence_dir: Path,
    *,
    enabled: bool = False,
) -> Receipt:
    """Execute a policy-proposed action exactly once OR report dry-run.

    After a crash or timeout the attempt exists and the action is never
    repeated. Successful HTTP/HA service acceptance still needs *separate*
    actual radio, Zigbee2MQTT and live MQTT verification by policy.evaluate.
    """
    action = decision.action
    if action not in _ACTION_PHASE:
        return Receipt("NO_PHYSICAL_ACTION", detail=action)
    phase = _ACTION_PHASE[action]
    if isinstance(phase, tuple):
        allowed = decision.state.phase in phase
    else:
        allowed = decision.state.phase == phase
    if not allowed or observation.utc != decision.state.last_sample_utc:
        raise ValueError("ACTION_NOT_FROM_CURRENT_POLICY_EPOCH")
    if _prohibited(observation):
        raise ValueError("CURRENT_HARDWARE_OR_MAINTENANCE_GATE_FAILURE")
    if decision.state.incident_since <= 0:
        raise ValueError("MISSING_DURABLE_INCIDENT_EPOCH")
    if not enabled:
        return Receipt("DRY_RUN", detail=action)

    evidence_dir = Path(evidence_dir)
    if not evidence_dir.is_dir() or evidence_dir.is_symlink():
        raise ValueError("EXISTING_PRIVATE_EVIDENCE_DIRECTORY_REQUIRED")

    # Action-specific phase prevents collisions between radio and ESP starts.
    marker = evidence_dir / (
        f"p7u-recovery-{decision.state.incident_since}-"
        f"{decision.state.phase}-{action}.attempt.json"
    )
    _atomic_unique(marker, {
        "schema": "p7u-shared-recovery-attempt-v1",
        "action": action,
        "state": decision.state.phase,
        "incident_since_utc": decision.state.incident_since,
        "observation_utc": observation.utc,
        "sent_after_receipt": True,
        "recorded_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
    })
    # Do not persist arbitrary API response bodies, which may reveal secrets.
    try:
        acknowledged = actuator.perform_once(action)
    except Exception as exc:
        # Ambiguous side effect; no immediate replay or automatic escalation.
        return Receipt("AMBIGUOUS_NO_RETRY", str(marker), type(exc).__name__)
    if acknowledged is not True:
        return Receipt("NOT_ACKNOWLEDGED_NO_RETRY", str(marker), action)
    return Receipt("COMMAND_ACCEPTED_NOT_YET_VERIFIED", str(marker), action)
