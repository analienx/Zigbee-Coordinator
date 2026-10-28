"""Fail-closed shared coordinator recovery policy: stock or custom P7U.

Pure state machine: never opens serial, MQTT, HTTP, HA, or sends any command.
Its 'action' is a PROPOSAL to a separately reviewed, at-most-once HA executor.
All times are UTC Unix seconds from the host. No secrets, IEEE, PAN or keys.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Literal

Action = Literal[
    "NONE", "CAPTURE_EVIDENCE", "STOP_Z2M", "RESET_RADIO",
    "START_Z2M", "RESTART_ESP", "RECOVERY_SUCCEEDED", "ALERT_HUMAN"
]
PHASES = frozenset((
    "MONITOR", "SUSPECT", "CAPTURE_PENDING", "STOP_PENDING",
    "RADIO_RESET_PENDING", "RADIO_BOOT", "RADIO_START_PENDING",
    "RADIO_VERIFY", "ESP_RESET_PENDING", "ESP_BOOT",
    "ESP_START_PENDING", "ESP_VERIFY", "COMPLETE", "HOLD",
))
FAULTS = frozenset(("SRSP_SYS_PING", "SRSP_AF_REGISTER", "SRSP_SYS_RESETIND"))
MAX_SAMPLE_GAP_S = 60
PENDING_DEADLINE_S = 120
BOOT_DEADLINE_S = 180
VERIFY_DEADLINE_S = 240
STABILITY_S = 120


@dataclass(frozen=True)
class Observation:
    utc: int
    addon: str
    adapter_error: str = ""
    mode: str = "USB"
    expected_identity: bool = False
    expected_usb: bool = False
    esp_reachable: bool = False
    ha_reachable: bool = False
    mqtt_reachable: bool = False
    maintenance: bool = False
    ota_active: bool = False
    firmware_flash_active: bool = False
    serial_owner_exclusive: bool = True
    app_uptime_s: int = 0
    srsp_120s: int = 0
    affected_devices_120s: int = 0
    fresh_device_topics_120s: int = 0
    health_fresh: bool = False
    # Actual runner supplies calibrated, current-epoch validity. Defaults retain
    # compatibility with deterministic callers which already validate inputs.
    observation_valid: bool = True
    rx_valid: bool = True
    bridge_online_fresh: bool = False
    herdsman_started_fresh: bool = False
    saved_evidence: bool = False
    # These are receipts from the real executor, not predictions.
    stopped_receipt: bool = False
    radio_reset_ack: bool = False
    esp_restart_ack: bool = False
    z2m_start_ack: bool = False


@dataclass(frozen=True)
class State:
    phase: str = "MONITOR"
    suspect_since: int = 0
    fault_samples: int = 0
    last_sample_utc: int = 0
    incident_since: int = 0
    # Assigned by the runner before the CAPTURE_EVIDENCE decision is persisted.
    # The pure policy never generates randomness or performs I/O.
    incident_id: str = ""
    stage_since: int = 0
    stable_since: int = 0
    recovery_attempts_24h: tuple[int, ...] = ()
    last_recovery_utc: int = 0
    reason: str = ""


@dataclass(frozen=True)
class Decision:
    state: State
    action: Action
    reason: str


def _prohibited(o: Observation) -> str:
    # Never act during any maintenance or when controller identity is uncertain.
    if o.maintenance or o.ota_active or o.firmware_flash_active:
        return "MAINTENANCE_OR_OTA"
    if o.mode != "USB" or not (o.expected_usb and o.expected_identity):
        return "UNKNOWN_MODE_IDENTITY_OR_USB"
    if not o.serial_owner_exclusive:
        return "MULTIPLE_ZNP_OWNERS"
    if not (o.esp_reachable and o.ha_reachable and o.mqtt_reachable):
        return "INDEPENDENT_CONTROL_PLANE_UNAVAILABLE"
    return ""


def _fault(o: Observation) -> str:
    if not o.observation_valid:
        return ""
    # A plain stopped add-on may be an intentional operator stop.
    if o.addon == "error" and o.adapter_error in FAULTS:
        return "ADAPTER_SPECIFIC_START_FAILURE"
    if o.addon == "started" and o.app_uptime_s >= 180 and (
        o.rx_valid and o.mqtt_reachable and o.health_fresh and o.srsp_120s >= 5
        and o.affected_devices_120s >= 3 and o.fresh_device_topics_120s == 0
    ):
        return "MULTI_DEVICE_AF_ZNP_STARVATION"
    return ""


def _running_proven(o: Observation) -> bool:
    # Retained bridge MQTT state or an HA 'started' process is NOT proof.
    return bool(
        o.observation_valid and o.rx_valid and o.health_fresh
        and o.addon == "started" and o.bridge_online_fresh
        and o.herdsman_started_fresh and o.fresh_device_topics_120s >= 3
        and o.srsp_120s == 0
    )


def _hold(s: State, reason: str) -> Decision:
    return Decision(replace(s, phase="HOLD", stable_since=0, reason=reason),
                    "ALERT_HUMAN", reason)


def _verify(o: Observation, s: State) -> Decision:
    tier = "ESP" if s.phase == "ESP_VERIFY" else "RADIO"
    if o.utc - s.stage_since > VERIFY_DEADLINE_S:
        return _hold(s, tier + "_VERIFY_TIMEOUT_AMBIGUOUS")
    if _running_proven(o):
        stable = s.stable_since or o.utc
        s = replace(s, stable_since=stable)
        if o.utc - stable < STABILITY_S:
            return Decision(s, "NONE", "STABILITY_GRACE")
        return Decision(replace(s, phase="COMPLETE"), "RECOVERY_SUCCEEDED",
                        "REAL_TRAFFIC_VERIFIED_AFTER_" + tier)
    s = replace(s, stable_since=0)
    if (tier == "ESP" and o.observation_valid and o.addon == "error"
            and o.adapter_error in FAULTS and o.utc - s.stage_since >= 20):
        return Decision(replace(s, phase="RADIO_RESET_PENDING", stage_since=o.utc),
                        "RESET_RADIO", "ESP_STAGE_FAILED_RADIO_FALLBACK_ONCE")
    if tier == "RADIO" and o.addon == "error":
        return _hold(s, "RADIO_FALLBACK_FAILED_NO_MORE_RESTARTS")
    return Decision(s, "NONE", tier + "_VERIFY_PENDING")


def evaluate(o: Observation, s: State = State()) -> Decision:
    """Compute one deterministic proposal; repeated calls NEVER repeat a sent action.

    Executor must persist the returned state before performing any action and
    update receipts explicitly after verified completion. It must never replay
    a pending action on restart, even if an HTTP timeout hides whether it ran.
    """
    if o.utc <= 0 or s.phase not in PHASES:
        return _hold(s, "BAD_TIME_OR_STATE")
    if s.last_sample_utc and o.utc < s.last_sample_utc:
        return _hold(s, "CLOCK_REWIND")
    if s.last_sample_utc and o.utc == s.last_sample_utc:
        return Decision(s, "NONE", "DUPLICATE_SAMPLE")
    sample_gap = o.utc - s.last_sample_utc if s.last_sample_utc else 0
    s = replace(s, last_sample_utc=o.utc)
    if sample_gap > MAX_SAMPLE_GAP_S:
        s = replace(s, stable_since=0)
        if s.phase == "SUSPECT":
            s = replace(s, phase="MONITOR", suspect_since=0, fault_samples=0)
    if s.phase == "COMPLETE":
        # Re-arm for future incidents while retaining cooldown and daily budget.
        return Decision(replace(s, phase="MONITOR", suspect_since=0,
                                fault_samples=0, incident_id="", incident_since=0,
                                stage_since=0, stable_since=0, reason=""),
                        "NONE", "RECOVERY_CLOSED")
    if s.phase == "HOLD":
        return Decision(s, "NONE", "HOLD")
    gate = _prohibited(o)
    if gate:
        if s.phase in ("MONITOR", "SUSPECT") and gate in (
            "INDEPENDENT_CONTROL_PLANE_UNAVAILABLE", "MAINTENANCE_OR_OTA"
        ):
            return Decision(replace(s, phase="MONITOR", suspect_since=0,
                                    fault_samples=0), "NONE", gate)
        # ESP/USB disappear briefly while ESP is deliberately restarting.
        if s.phase in ("ESP_RESET_PENDING", "ESP_BOOT",
                       "RADIO_RESET_PENDING", "RADIO_BOOT") and gate in (
            "INDEPENDENT_CONTROL_PLANE_UNAVAILABLE",
            "UNKNOWN_MODE_IDENTITY_OR_USB"
        ):
            if o.utc - s.stage_since <= BOOT_DEADLINE_S:
                return Decision(s, "NONE", "AWAIT_RADIO_OR_ESP_REENUMERATION")
        return _hold(s, gate)
    if s.phase.endswith("_PENDING") and (
        o.utc - s.stage_since > PENDING_DEADLINE_S
    ):
        return _hold(s, "PENDING_ACTION_OR_PROOF_TIMEOUT_NO_RETRY")
    if s.phase in ("ESP_BOOT", "RADIO_BOOT") and (
        o.utc - s.stage_since > BOOT_DEADLINE_S
    ):
        return _hold(s, "BOOT_REENUMERATION_TIMEOUT_NO_RETRY")
    if s.phase in ("MONITOR", "SUSPECT"):
        cause = _fault(o)
        if not cause:
            return Decision(replace(s, phase="MONITOR", suspect_since=0,
                                    fault_samples=0), "NONE", "NO_CONFIRMED_HANG")
        if s.phase == "MONITOR" or s.suspect_since == 0:
            return Decision(replace(s, phase="SUSPECT", suspect_since=o.utc,
                                    fault_samples=1, reason=cause),
                            "NONE", "FIRST_FAULT_SAMPLE")
        # Avoid double-counting one poll; do not wait unbounded across outages.
        if o.utc - s.suspect_since > 600:
            return Decision(replace(s, suspect_since=o.utc, fault_samples=1,
                                    reason=cause), "NONE", "REARM_SUSPICION")
        if o.utc - s.suspect_since < 30 or cause != s.reason:
            return Decision(s, "NONE", "WAIT_FOR_INDEPENDENT_CONFIRMATION")
        history = tuple(t for t in s.recovery_attempts_24h if o.utc - t < 86400)
        if len(history) >= 2 or (s.last_recovery_utc and
                                 o.utc - s.last_recovery_utc < 21600):
            return _hold(s, "RECOVERY_BUDGET_OR_COOLDOWN_EXHAUSTED")
        return Decision(replace(s, phase="CAPTURE_PENDING",
                                incident_since=o.utc, incident_id="",
                                stage_since=o.utc, stable_since=0,
                                recovery_attempts_24h=history),
                        "CAPTURE_EVIDENCE", cause)
    if s.phase == "CAPTURE_PENDING":
        if not o.saved_evidence:
            return Decision(s, "NONE", "AWAIT_DURABLE_EVIDENCE")
        return Decision(replace(s, phase="STOP_PENDING", stage_since=o.utc),
                        "STOP_Z2M", "QUIESCE_BEFORE_HARDWARE_ACTION")
    if s.phase == "STOP_PENDING":
        if not o.stopped_receipt or o.addon not in ("error", "stopped"):
            return Decision(s, "NONE", "AWAIT_Z2M_STOP_PROOF")
        # First-line, physically demonstrated successful recovery: ESP restart.
        new = replace(s, phase="ESP_RESET_PENDING", stage_since=o.utc,
                      recovery_attempts_24h=tuple(s.recovery_attempts_24h) + (o.utc,),
                      last_recovery_utc=o.utc)
        return Decision(new, "RESTART_ESP", "FIRST_LINE_ESP_RESTART")
    if s.phase == "ESP_RESET_PENDING":
        if not o.esp_restart_ack:
            return Decision(s, "NONE", "ESP_RESTART_PENDING_NO_RETRY")
        return Decision(replace(s, phase="ESP_BOOT", stage_since=o.utc),
                        "NONE", "WAIT_ESP_BOOT")
    if s.phase == "ESP_BOOT":
        if o.utc - s.stage_since < 20:
            return Decision(s, "NONE", "BOUNDED_ESP_BOOT_GRACE")
        return Decision(replace(s, phase="ESP_START_PENDING", stage_since=o.utc),
                        "START_Z2M", "ONE_HOST_RECONNECT_AFTER_ESP_RESTART")
    if s.phase == "ESP_START_PENDING":
        if not o.z2m_start_ack:
            return Decision(s, "NONE", "ESP_HOST_START_PENDING_NO_RETRY")
        return Decision(replace(s, phase="ESP_VERIFY", stage_since=o.utc,
                                stable_since=0),
                        "NONE", "VERIFY_REAL_ZIGBEE_TRAFFIC")
    if s.phase == "ESP_VERIFY":
        return _verify(o, s)
    if s.phase == "RADIO_RESET_PENDING":
        if not o.radio_reset_ack:
            return Decision(s, "NONE", "RADIO_RESET_PENDING_NO_RETRY")
        return Decision(replace(s, phase="RADIO_BOOT", stage_since=o.utc),
                        "NONE", "WAIT_RADIO_BOOT")
    if s.phase == "RADIO_BOOT":
        if o.utc - s.stage_since < 20:
            return Decision(s, "NONE", "BOUNDED_BOOT_GRACE")
        return Decision(replace(s, phase="RADIO_START_PENDING", stage_since=o.utc),
                        "START_Z2M", "ONE_HOST_RECONNECT_AFTER_RADIO_RESET")
    if s.phase == "RADIO_START_PENDING":
        if not o.z2m_start_ack:
            return Decision(s, "NONE", "HOST_START_PENDING_NO_RETRY")
        return Decision(replace(s, phase="RADIO_VERIFY", stage_since=o.utc,
                                stable_since=0),
                        "NONE", "VERIFY_REAL_ZIGBEE_TRAFFIC")
    if s.phase == "RADIO_VERIFY":
        return _verify(o, s)
    raise AssertionError("unreachable state")
