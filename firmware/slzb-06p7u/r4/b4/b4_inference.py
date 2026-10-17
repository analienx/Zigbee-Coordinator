"""B4 offline conservative incident inference from nonidentifying, qualified facts.

Never opens serial, USB, Zigbee, MQTT, filesystem or issues firmware requests.
No raw frames or network identifiers accepted. A single observation cannot
prove root cause. Unsupported producer => NOT_MEASURED, not event_count=0.
"""
import math

ALLOWED = frozenset((
    "usb_disconnected", "usb_reenumerated", "serial_present",
    "host_sigterm", "host_unexpected_exit", "sys_sreq_timeout",
    "zdo_sreq_timeout", "af_sreq_timeout", "af_local_srsp_ok",
    "af_confirm_observed", "zcl_response_observed", "nwk_no_route",
    "source_route_error", "f0_responsive", "ota_overlap",
    "b1_hold_nv", "b1_hold_security", "b2_routes_measured",
    "b3_nv_status_measured",
))
# Each field only boolean or unknown. Never accept actual USB serial, IEEE,
# PAN, key, raw packet or unbounded event vectors.
UNKNOWN = "UNKNOWN"
NOT_MEASURED = "NOT_MEASURED"
CONFIDENCE = "OBSERVATIONAL_NOT_CAUSAL"
ALTERNATIVES = {
    "USB_DETACHED": ("host USB bridge or driver", "cable/power connection", "device reenumeration"),
    "MT_NONRESPONSE_WITH_SERIAL_PRESENT": ("NPI queue starvation", "UART bridge/parser delay", "radio task delay"),
    "SYS_RESPONSIVE_OTHER_SRSP_TIMEOUT": ("AF/ZDO task or queue backlog", "host waiter lifecycle", "transient transport"),
    "AF_CONFIRM_AFTER_SRSP_TIMEOUT": ("late device/stack completion", "missed or late SRSP", "host waiter expiration"),
    "RF_ROUTE_FAILURE_INDEPENDENT_OF_SRSP": ("NWK route discovery", "source routing state", "RF mesh topology"),
    "UART_DELIVERY_UNKNOWN": ("UART driver callback", "USB bridge/parser", "host queue"),
    "HOST_SIGTERM_OBSERVED": ("normal supervisor stop", "administrative restart", "maintenance shutdown"),
    "HOST_UNEXPECTED_EXIT_OBSERVED": ("process exception", "supervisor termination", "host resource condition"),
    "OTA_CORRELATED_ONLY": ("independent host traffic", "concurrent routing load", "OTA pacing overlap"),
}

def _check(event):
    if not isinstance(event, dict) or set(event) - ALLOWED:
        raise ValueError("only exact B4 boolean event fields may enter inference")
    for key, value in event.items():
        if value is not None and type(value) is not bool:
            raise ValueError("B4 evidence values must be boolean or unavailable")
    if event.get("usb_disconnected") is True and event.get("serial_present") is True:
        # A single snapshot cannot establish both detached and connected at
        # the same time; the caller must use distinct chronological samples.
        raise ValueError("contradictory USB/serial state in one snapshot")
    return event

def classify(observation):
    """Categorize only directly observed symptoms; root cause always UNKNOWN."""
    o = _check(observation)
    signals = []
    if o.get("usb_disconnected") is True:
        signals.append("USB_DETACHED")
    elif o.get("serial_present") is True and (o.get("sys_sreq_timeout") is True or o.get("zdo_sreq_timeout") is True):
        if o.get("f0_responsive") is True:
            signals.append("SYS_RESPONSIVE_OTHER_SRSP_TIMEOUT")
        else:
            signals.append("MT_NONRESPONSE_WITH_SERIAL_PRESENT")
    elif o.get("f0_responsive") is True and (o.get("af_sreq_timeout") is True or o.get("zdo_sreq_timeout") is True):
        signals.append("SYS_RESPONSIVE_OTHER_SRSP_TIMEOUT")

    if o.get("host_sigterm") is True:
        signals.append("HOST_SIGTERM_OBSERVED")
    if o.get("host_unexpected_exit") is True:
        signals.append("HOST_UNEXPECTED_EXIT_OBSERVED")
    if o.get("af_sreq_timeout") is True and o.get("af_confirm_observed") is True:
        signals.append("AF_CONFIRM_AFTER_SRSP_TIMEOUT")
    if o.get("af_local_srsp_ok") is True and (o.get("nwk_no_route") is True or o.get("source_route_error") is True):
        signals.append("RF_ROUTE_FAILURE_INDEPENDENT_OF_SRSP")
    if o.get("ota_overlap") is True:
        signals.append("OTA_CORRELATED_ONLY")
    if o.get("usb_reenumerated") is True:
        signals.append("USB_REENUMERATION_OBSERVED")
    if o.get("zcl_response_observed") is True:
        signals.append("ZCL_RESPONSE_OBSERVED")
    if not signals:
        signals.append("NO_SUPPORTED_FAILURE_SYMPTOM")

    return {
        "schema": "r4-b4-conservative-inference-v1",
        "source": "OFFLINE_EVIDENCE_ONLY",
        "signals": signals,
        "confidence": CONFIDENCE,
        "root_cause": UNKNOWN,
        "alternatives": {kind: list(ALTERNATIVES[kind])
                         for kind in signals if kind in ALTERNATIVES},
        "f0_available": False if o.get("usb_disconnected") is True else (
            True if o.get("f0_responsive") is True else UNKNOWN),
        "af_srsp_result": ("TIMEOUT_OBSERVED" if o.get("af_sreq_timeout") is True else
                           "LOCAL_OK_OBSERVED" if o.get("af_local_srsp_ok") is True else
                           UNKNOWN),
        "af_confirm_result": "OBSERVED" if o.get("af_confirm_observed") is True else UNKNOWN,
        "zcl_result": "OBSERVED" if o.get("zcl_response_observed") is True else UNKNOWN,
        "nwk_route_result": ("FAILURE_OBSERVED" if o.get("nwk_no_route") is True or o.get("source_route_error") is True else
                             UNKNOWN),
        "b1_hold_state": (
            "HOLD_SECURITY" if o.get("b1_hold_security") is True else
            "HOLD_NV" if o.get("b1_hold_nv") is True else
            UNKNOWN
        ),
        "b1_rf_permission": "NOT_GRANTED_BY_DIAGNOSTICS",
        "b2_route_counters": UNKNOWN if o.get("b2_routes_measured") is not True else "SOURCE_REPORT_REQUIRED",
        "b3_nonsecret_nv_status": UNKNOWN if o.get("b3_nv_status_measured") is not True else "SOURCE_REPORT_REQUIRED",
        "ota_causal": False,
        "hardware_epoch_proven": False,
    }

def uart_interval(*, prev_accepted, curr_accepted, prev_finished, curr_finished,
                  accepted_valid, finished_valid, continuous_radio_epoch):
    """Only discuss UART accepted/finished progress with qualified same-boot data.

    Counts use a known 32-bit modulo width. Even when a delta is warranted,
    this returns an observational candidate, never physical USB delivery proof.
    """
    for field in (accepted_valid, finished_valid, continuous_radio_epoch):
        if type(field) is not bool:
            raise ValueError("provenance/validity flags must be exact booleans")
    result = {
        "accepted_delta": None, "finished_delta": None,
        "classification": "NOT_MEASURED",
        "root_cause": UNKNOWN,
        "host_received_bytes": UNKNOWN,
    }
    if not all((accepted_valid, finished_valid, continuous_radio_epoch)):
        return result
    nums = (prev_accepted, curr_accepted, prev_finished, curr_finished)
    if any(type(x) is not int or not 0 <= x <= 0xFFFFFFFF for x in nums):
        raise ValueError("qualified counters must be u32")
    accepted_delta = (curr_accepted - prev_accepted) & 0xFFFFFFFF
    finished_delta = (curr_finished - prev_finished) & 0xFFFFFFFF
    result["accepted_delta"] = accepted_delta
    result["finished_delta"] = finished_delta
    if accepted_delta > finished_delta:
        result["classification"] = "UART_COMPLETION_LAG_CANDIDATE"
    elif finished_delta > accepted_delta:
        # Count discrepancy could reflect in-flight events at interval
        # boundaries; no cause may be claimed.
        result["classification"] = "UART_COMPLETION_INTERVAL_MISMATCH"
    else:
        result["classification"] = "UART_ACCEPTED_COMPLETION_COUNTS_MATCH"
    return result
