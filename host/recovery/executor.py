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
import re
from typing import Protocol

from policy import Decision, Observation, State, _prohibited

_ACTION_PHASE = {
    "CAPTURE_EVIDENCE": "CAPTURE_PENDING",
    "STOP_Z2M": "STOP_PENDING",
    "RESET_RADIO": "RADIO_RESET_PENDING",
    "START_Z2M": ("RADIO_START_PENDING", "ESP_START_PENDING"),
    "RESTART_ESP": "ESP_RESET_PENDING",
}
ACCEPTED = "COMMAND_ACCEPTED_NOT_YET_VERIFIED"
_OUTCOMES = frozenset((ACCEPTED, "AMBIGUOUS_NO_RETRY", "NOT_ACKNOWLEDGED_NO_RETRY"))


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
    action_key: str = ""
    outcome: dict | None = None


def action_key(state: State, action: str, phase: str | None = None) -> str:
    """Identify one operation in one immutable, UUID-bound incident."""
    phase = phase or state.phase
    allowed = _ACTION_PHASE.get(action, ())
    allowed = (allowed,) if isinstance(allowed, str) else allowed
    if (not re.fullmatch(r"[0-9a-f]{32}", state.incident_id)
            or phase not in allowed):
        raise ValueError("INVALID_INCIDENT_OR_ACTION_PHASE")
    return f"{state.incident_id}:{phase}:{action}"


def _receipt_matches(document: dict, state: State, action: str,
                     phase: str | None = None) -> bool:
    phase = phase or state.phase
    try:
        expected = action_key(state, action, phase)
    except ValueError:
        return False
    return bool(
        isinstance(document, dict)
        and document.get("schema") == "p7u-shared-recovery-result-v2"
        and document.get("action_key") == expected
        and document.get("incident_id") == state.incident_id
        and document.get("phase") == phase
        and document.get("action") == action
        and isinstance(document.get("status"), str)
        and document.get("status") in _OUTCOMES
    )


def accepted_receipt(receipts: dict, state: State, action: str,
                     phase: str | None = None) -> bool:
    try:
        key = action_key(state, action, phase)
    except ValueError:
        return False
    doc = receipts.get(key)
    return bool(_receipt_matches(doc, state, action, phase)
                and doc["status"] == ACCEPTED)


def _action_path(evidence_dir: Path, state: State, action: str, suffix: str) -> Path:
    action_key(state, action)  # Validate every path component before joining.
    return evidence_dir / (
        f"p7u-recovery-{state.incident_id}-{state.phase}-{action}.{suffix}.json")


def load_action_result(evidence_dir: Path, state: State, action: str) -> dict | None:
    path = _action_path(Path(evidence_dir), state, action, "result")
    if path.is_symlink():
        raise ValueError("SYMLINK_ACTION_RESULT_FORBIDDEN")
    if not path.exists():
        return None
    doc = json.loads(path.read_text(encoding="utf-8"))
    if not _receipt_matches(doc, state, action):
        raise ValueError("ACTION_RESULT_IDENTITY_MISMATCH")
    return doc


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
    """Execute a policy-proposed action at most once OR report dry-run.

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
    # After our acknowledged stop, current Zigbee application logs are
    # intentionally unavailable. Later stages rely on this incident's receipts
    # and independently refreshed control-plane/quiescence gates instead.
    if action in ("CAPTURE_EVIDENCE", "STOP_Z2M") and not observation.observation_valid:
        raise ValueError("CURRENT_OBSERVATION_UNAVAILABLE")
    if action == "STOP_Z2M" and not observation.saved_evidence:
        raise ValueError("CURRENT_INCIDENT_EVIDENCE_RECEIPT_REQUIRED")
    if action in ("RESTART_ESP", "RESET_RADIO") and (
        not observation.stopped_receipt or observation.addon not in ("error", "stopped")
    ):
        raise ValueError("CURRENT_INCIDENT_STOP_AND_QUIESCENCE_PROOF_REQUIRED")
    if action == "START_Z2M" and not (
        observation.radio_reset_ack if decision.state.phase == "RADIO_START_PENDING"
        else observation.esp_restart_ack
    ):
        raise ValueError("CURRENT_INCIDENT_REBOOT_RECEIPT_REQUIRED")
    if decision.state.incident_since <= 0:
        raise ValueError("MISSING_DURABLE_INCIDENT_EPOCH")
    if not enabled:
        return Receipt("DRY_RUN", detail=action)

    key = action_key(decision.state, action)

    evidence_dir = Path(evidence_dir)
    if not evidence_dir.is_dir() or evidence_dir.is_symlink():
        raise ValueError("EXISTING_PRIVATE_EVIDENCE_DIRECTORY_REQUIRED")

    # Action-specific phase prevents collisions between radio and ESP starts.
    marker = _action_path(evidence_dir, decision.state, action, "attempt")
    _atomic_unique(marker, {
        "schema": "p7u-shared-recovery-attempt-v2",
        "action_key": key,
        "incident_id": decision.state.incident_id,
        "action": action,
        "phase": decision.state.phase,
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
        status, detail = "AMBIGUOUS_NO_RETRY", type(exc).__name__
    else:
        status = ACCEPTED if acknowledged is True else "NOT_ACKNOWLEDGED_NO_RETRY"
        detail = action
    outcome = {
        "schema": "p7u-shared-recovery-result-v2", "action_key": key,
        "incident_id": decision.state.incident_id, "phase": decision.state.phase,
        "action": action, "status": status, "detail": detail,
        "recorded_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    # The durable result is authoritative if the process dies before updating
    # the ledger projection. Missing/partial results are never treated as ACKs.
    _atomic_unique(_action_path(evidence_dir, decision.state, action, "result"), outcome)
    return Receipt(status, str(marker), detail, key, outcome)
