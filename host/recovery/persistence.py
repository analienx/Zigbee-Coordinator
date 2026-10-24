"""Crash-safe private recovery ledger and conservative startup reconciliation.

The write-ahead action files are authoritative. This module never calls HA,
MQTT, serial or an actuator. An unresolved prior action always holds, never
replays. File replacement uses a unique temporary name, so an abandoned old
temporary file cannot prevent the next state save.
"""
from __future__ import annotations

from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import re
import tempfile
import time
import uuid

from policy import PHASES, State
from executor import ACCEPTED, action_key, load_action_result

SCHEMA = "p7u-recovery-state-v2"
_PENDING = {
    "CAPTURE_PENDING": "CAPTURE_EVIDENCE", "STOP_PENDING": "STOP_Z2M",
    "ESP_RESET_PENDING": "RESTART_ESP", "RADIO_RESET_PENDING": "RESET_RADIO",
    "ESP_START_PENDING": "START_Z2M", "RADIO_START_PENDING": "START_Z2M",
}
_PRECEDING = {
    "ESP_BOOT": ("ESP_RESET_PENDING", "RESTART_ESP"),
    "RADIO_BOOT": ("RADIO_RESET_PENDING", "RESET_RADIO"),
    "ESP_VERIFY": ("ESP_START_PENDING", "START_Z2M"),
    "RADIO_VERIFY": ("RADIO_START_PENDING", "START_Z2M"),
}


def atomic_json(path: Path, obj: dict) -> None:
    path = Path(path)
    if path.is_symlink():
        raise ValueError("SYMLINK_LEDGER_FORBIDDEN")
    # Serialize before creating a temporary file; malformed state cannot leave
    # a competing incomplete file. mkstemp is exclusive and private by default.
    payload = (json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd, name = tempfile.mkstemp(prefix=path.name + ".", suffix=".new", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name == "posix":
            directory = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        # Never remove anyone else's abandoned temporary or any action marker.
        if temporary.exists():
            temporary.unlink()


def _decode_state(raw: dict, *, legacy: bool = False) -> State:
    if not isinstance(raw, dict) or set(raw) - set(State.__dataclass_fields__):
        raise ValueError("INVALID_LEDGER_STATE_FIELDS")
    required = set(State.__dataclass_fields__) - ({"incident_id", "stable_since"} if legacy else set())
    if not required <= set(raw):
        raise ValueError("MISSING_LEDGER_STATE_FIELDS")
    values = dict(raw)
    for name in ("phase", "incident_id", "reason"):
        if name in values and not isinstance(values[name], str):
            raise ValueError("INVALID_LEDGER_STRING")
    for name in set(State.__dataclass_fields__) - {
        "phase", "incident_id", "reason", "recovery_attempts_24h"
    }:
        value = values.get(name, 0)
        if type(value) is not int or value < 0:
            raise ValueError("INVALID_LEDGER_INTEGER")
    history = values.get("recovery_attempts_24h", ())
    if (not isinstance(history, (list, tuple)) or len(history) > 1000
            or any(type(t) is not int or t <= 0 for t in history)):
        raise ValueError("INVALID_RECOVERY_BUDGET_HISTORY")
    values["recovery_attempts_24h"] = tuple(history)
    state = State(**values)
    if state.phase not in PHASES:
        raise ValueError("INVALID_LEDGER_PHASE")
    if state.incident_id and not re.fullmatch(r"[0-9a-f]{32}", state.incident_id):
        raise ValueError("INVALID_LEDGER_INCIDENT_UUID")
    if state.phase in _PENDING or state.phase in _PRECEDING:
        if legacy:
            return replace(state, phase="HOLD", stable_since=0,
                           reason="LEGACY_PENDING_ACTION_NO_REPLAY")
        if not state.incident_id or not state.incident_since or not state.stage_since:
            raise ValueError("MISSING_LEDGER_TRANSACTION_IDENTITY")
    return state


def load_ledger(path: Path) -> tuple[State, dict]:
    path = Path(path)
    if path.is_symlink():
        raise ValueError("SYMLINK_LEDGER_FORBIDDEN")
    if not path.exists():
        return State(), {}
    original = path.read_bytes()
    try:
        doc = json.loads(original)
        if not isinstance(doc, dict) or doc.get("schema") not in (
            SCHEMA, "p7u-recovery-state-v1"
        ):
            raise ValueError("INCOMPATIBLE_WATCHDOG_STATE")
        legacy = doc["schema"] != SCHEMA
        state = _decode_state(doc.get("state"), legacy=legacy)
        receipts = doc.get("receipts", {})
        if not isinstance(receipts, dict):
            raise ValueError("INVALID_LEDGER_RECEIPTS")
        if legacy:
            # Unscoped booleans can never acknowledge a v2 transaction.
            receipts = {}
        elif any(not isinstance(k, str) or not isinstance(v, dict)
                 for k, v in receipts.items()):
            raise ValueError("INVALID_LEDGER_RECEIPT_TYPES")
        return state, receipts
    except (ValueError, TypeError):
        # Preserve rejected bytes privately before the caller can save HOLD.
        # Never rename the sole original away: failure before writing HOLD
        # must not turn a later startup into the "missing ledger" case.
        incident_id = uuid.uuid4().hex
        rejected = path.with_name(path.name + ".rejected-" + incident_id + ".json")
        fd = os.open(rejected, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(original)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "posix":
            directory = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        return State(phase="HOLD", incident_id=incident_id,
                     incident_since=int(time.time()), reason="INVALID_LEDGER"), {}


def save_ledger(path: Path, state: State, receipts: dict) -> None:
    _decode_state(asdict(state))
    if not isinstance(receipts, dict) or any(
        not isinstance(k, str) or not isinstance(v, dict) for k, v in receipts.items()
    ):
        raise ValueError("INVALID_LEDGER_RECEIPT_TYPES")
    atomic_json(path, {"schema": SCHEMA, "state": asdict(state), "receipts": receipts})


def reconcile_pending(state: State, receipts: dict, evidence_dir: Path) -> State:
    """Import a proven prior ACK or HOLD; never execute or reissue an action.

    Reset stability after any process restart. A matching, complete result file
    permits policy progression even if the ledger update was interrupted. The
    intent alone, a missing result, and malformed data all require human review.
    """
    state = replace(state, stable_since=0)
    if state.phase in _PENDING:
        phase, action = state.phase, _PENDING[state.phase]
    elif state.phase in _PRECEDING:
        phase, action = _PRECEDING[state.phase]
    else:
        return state
    action_state = replace(state, phase=phase)
    try:
        outcome = load_action_result(evidence_dir, action_state, action)
        if outcome is not None and outcome["status"] == ACCEPTED:
            receipts[action_key(action_state, action)] = outcome
            return state
    except (OSError, ValueError, TypeError):
        pass
    return replace(state, phase="HOLD", reason="UNRESOLVED_ACTION_AFTER_RESTART_NO_REPLAY")
