"""Fail-closed shared coordinator recovery policy: stock or custom P7U.

Pure state machine: never opens serial, MQTT, HTTP, HA, or sends any command.
Its 'action' is a PROPOSAL to a separately reviewed, exactly-once HA executor.
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
    stage_since: int = 0
    radio_resets_24h: tuple[int, ...] = ()
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
    if o.addon in ("error", "stopped") and o.adapter_error in FAULTS:
        return "ADAPTER_SPECIFIC_START_FAILURE"
    if o.addon == "started" and o.app_uptime_s >= 180 and (
        o.mqtt_reachable and o.health_fresh and o.srsp_120s >= 5
        and o.affected_devices_120s >= 3 and o.fresh_device_topics_120s == 0
    ):
        return "MULTI_DEVICE_AF_ZNP_STARVATION"
    return ""


def _running_proven(o: Observation) -> bool:
    # Retained bridge MQTT state or an HA 'started' process is NOT proof.
    return bool(
        o.addon == "started" and o.bridge_online_fresh
        and o.herdsman_started_fresh and o.fresh_device_topics_120s >= 3
        and o.srsp_120s == 0
    )


def evaluate(o: Observation, s: State = State()) -> Decision:
    """Compute one deterministic proposal; repeated calls NEVER repeat a sent action.

    Executor must persist the returned state before performing any action and
    update receipts explicitly after verified completion. It must never replay
    a pending action on restart, even if an HTTP timeout hides whether it ran.
    """
    if o.utc <= 0 or s.phase not in PHASES:
        return Decision(replace(s, phase="HOLD"), "ALERT_HUMAN", "BAD_TIME_OR_STATE")
    if s.last_sample_utc and o.utc < s.last_sample_utc:
        return Decision(replace(s, phase="HOLD"), "ALERT_HUMAN", "CLOCK_REWIND")
    s = replace(s, last_sample_utc=o.utc)
    gate = _prohibited(o)
    if gate:
        return Decision(replace(s, phase="HOLD", reason=gate),
                        "ALERT_HUMAN", gate)
    if s.phase in ("HOLD", "COMPLETE"):
        return Decision(s, "NONE", s.phase)
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
        history = tuple(t for t in s.radio_resets_24h if o.utc - t < 86400)
        if len(history) >= 2 or (s.last_recovery_utc and
                                 o.utc - s.last_recovery_utc < 21600):
            return Decision(replace(s, phase="HOLD"), "ALERT_HUMAN",
                            "RESET_BUDGET_OR_COOLDOWN_EXHAUSTED")
        return Decision(replace(s, phase="CAPTURE_PENDING",
                                incident_since=o.utc, stage_since=o.utc,
                                radio_resets_24h=history),
                        "CAPTURE_EVIDENCE", cause)
    if s.phase == "CAPTURE_PENDING":
        if not o.saved_evidence:
            return Decision(s, "NONE", "AWAIT_DURABLE_EVIDENCE")
        return Decision(replace(s, phase="STOP_PENDING", stage_since=o.utc),
                        "STOP_Z2M", "QUIESCE_BEFORE_HARDWARE_ACTION")
    if s.phase == "STOP_PENDING":
        if not o.stopped_receipt or o.addon not in ("error", "stopped"):
            return Decision(s, "NONE", "AWAIT_Z2M_STOP_PROOF")
        new = replace(s, phase="RADIO_RESET_PENDING", stage_since=o.utc,
                      radio_resets_24h=s.radio_resets_24h + (o.utc,))
        return Decision(new, "RESET_RADIO", "ONE_RADIO_RESET_QUEUED")
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
        return Decision(replace(s, phase="RADIO_VERIFY", stage_since=o.utc),
                        "NONE", "VERIFY_REAL_ZIGBEE_TRAFFIC")
    if s.phase == "RADIO_VERIFY":
        if _running_proven(o):
            if o.utc - s.stage_since < 120:
                return Decision(s, "NONE", "STABILITY_GRACE")
            return Decision(replace(s, phase="COMPLETE", last_recovery_utc=o.utc),
                            "RECOVERY_SUCCEEDED", "REAL_TRAFFIC_VERIFIED")
        if o.addon == "error" and o.adapter_error in FAULTS and (
            o.utc - s.stage_since >= 20
        ):
            return Decision(replace(s, phase="ESP_RESET_PENDING",
                                    stage_since=o.utc),
                            "RESTART_ESP", "RADIO_STAGE_FAILED_ESCALATE_ONCE")
        if o.utc - s.stage_since > 240:
            return Decision(replace(s, phase="HOLD"), "ALERT_HUMAN",
                            "RADIO_VERIFY_TIMEOUT_AMBIGUOUS")
        return Decision(s, "NONE", "RADIO_VERIFY_PENDING")
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
        return Decision(replace(s, phase="ESP_VERIFY", stage_since=o.utc),
                        "NONE", "VERIFY_REAL_ZIGBEE_TRAFFIC")
    if s.phase == "ESP_VERIFY":
        if _running_proven(o):
            if o.utc - s.stage_since < 120:
                return Decision(s, "NONE", "STABILITY_GRACE")
            return Decision(replace(s, phase="COMPLETE", last_recovery_utc=o.utc),
                            "RECOVERY_SUCCEEDED", "REAL_TRAFFIC_VERIFIED_AFTER_ESP")
        if o.utc - s.stage_since > 240 or o.addon == "error":
            return Decision(replace(s, phase="HOLD"), "ALERT_HUMAN",
                            "ESP_STAGE_FAILED_NO_FURTHER_AUTOMATIC_RESETS")
        return Decision(s, "NONE", "ESP_VERIFY_PENDING")
    raise AssertionError("unreachable state")
