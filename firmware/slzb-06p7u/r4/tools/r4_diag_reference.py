"""Offline R4-01a diagnostic ABI *reference only*.

No hardware/serial/MQTT, radio firmware, disk or network access. The proposed
v3 layout is NOT yet implemented by P7U firmware or herdsman. V2 is the
legacy P10 donor contract and must remain byte-compatible.
"""
import math
import struct

COUNTER_COUNT = 25
V2_VERSION = 2
V2_SIZE = 102
V3_MAGIC = b"R4D3"
V3_VERSION = 3
KNOWN_FLAGS = 0x07
CAP_RADIO_BOOT_ID = 1 << 0
KNOWN_CAPABILITIES = CAP_RADIO_BOOT_ID
VALID_COUNTER_MASK = (1 << COUNTER_COUNT) - 1
COUNTERS = (
    "srsp_depth", "srsp_high_water", "async_depth", "async_high_water",
    "srsp_enqueued", "srsp_uart_accepted", "async_uart_accepted",
    "tx_immediate_rejects", "tx_rejected_drops", "stack_frame_failures",
    "stack_queue_failures", "srsp_allocation_failures",
    "srsp_enqueue_failures", "rx_frame_failures", "srsp_queue_fallbacks",
    "af_direct_accepted", "af_direct_buffer_full", "af_direct_memory_failure",
    "af_direct_other", "af_source_accepted", "af_source_buffer_full",
    "af_confirm_cca_failure", "af_confirm_other_failure",
    "rx_overflow_events", "rx_overflow_discarded_bytes",
)
_V3_HEADER = struct.Struct("<4sBBHIIQII")
V3_SIZE = _V3_HEADER.size + COUNTER_COUNT * 4  # 132 bytes


def _bytes(frame):
    if not isinstance(frame, (bytes, bytearray, memoryview)):
        raise ValueError("diagnostic body must be bytes-like")
    return bytes(frame)


def decode_v2(frame):
    """P10 donor v2: every u32 is a legitimate value (incl. 0xFFFFFFFF).
    There is NO unknown-value sentinel, radio epoch or capability bitmap.
    """
    body = _bytes(frame)
    if len(body) != V2_SIZE:
        raise ValueError("v2 diagnostic length mismatch")
    version, flags = struct.unpack_from("<BB", body)
    if version != V2_VERSION:
        raise ValueError("unsupported v2 version")
    if flags & ~KNOWN_FLAGS:
        raise ValueError("unsupported v2 flags")
    values = struct.unpack_from("<25I", body, 2)
    return {
        "abi": 2, "flags": flags, "counters": dict(zip(COUNTERS, values)),
        "counter_validity": "LEGACY_ASSUMED_ALL",
        "radio_boot_id": None, "radio_boot_id_verified": False,
    }


def decode_v3(frame):
    """Proposed v3 only. Explicit per-counter validity and boot ID capability.
    No firmware implementation exists at R4-01a.
    """
    body = _bytes(frame)
    if len(body) != V3_SIZE:
        raise ValueError("v3 diagnostic length mismatch")
    magic, version, flags, payload_len, caps, valid, radio_boot, uptime_ms, seq = (
        _V3_HEADER.unpack_from(body)
    )
    if magic != V3_MAGIC or version != V3_VERSION:
        raise ValueError("unsupported v3 signature or version")
    if payload_len != V3_SIZE:
        raise ValueError("v3 declared length mismatch")
    if flags & ~KNOWN_FLAGS or caps & ~KNOWN_CAPABILITIES:
        raise ValueError("unsupported v3 flags or capabilities")
    if valid & ~VALID_COUNTER_MASK:
        raise ValueError("v3 validity has reserved bits")
    if caps & CAP_RADIO_BOOT_ID and radio_boot == 0:
        raise ValueError("radio boot identity capability requires a nonzero ID")
    if not caps & CAP_RADIO_BOOT_ID and radio_boot != 0:
        raise ValueError("boot ID field populated without capability")
    vals = struct.unpack_from("<25I", body, _V3_HEADER.size)
    counters = {
        name: vals[i] if valid & (1 << i) else None
        for i, name in enumerate(COUNTERS)
    }
    return {
        "abi": 3, "flags": flags, "counters": counters,
        "counter_validity": "EXPLICIT",
        "radio_boot_id": radio_boot if caps & CAP_RADIO_BOOT_ID else None,
        "radio_boot_id_verified": bool(caps & CAP_RADIO_BOOT_ID),
        "uptime_ms": uptime_ms, "sample_seq": seq,
        "capabilities": caps, "valid_mask": valid,
    }


def trustworthy_radio_epoch(prev, current, *, source_qualified=False):
    """Radio continuity can ONLY be asserted for two v3 samples with
    nonzero, firmware-proven boot identity; host timestamps are insufficient.

    Even equal boot IDs are not proof without an audited source of per-boot
    identity uniqueness. The caller MUST explicitly pass source_qualified=True
    only after a separately reviewed/native-proven boot identity generator.
    An on-wire capability bit alone cannot grant that authority.
    """
    if type(source_qualified) is not bool or not source_qualified:
        return False
    if prev.get("abi") != 3 or current.get("abi") != 3:
        return False
    if not prev.get("radio_boot_id_verified") or not current.get("radio_boot_id_verified"):
        return False
    a, b = prev.get("radio_boot_id"), current.get("radio_boot_id")
    if not isinstance(a, int) or not isinstance(b, int) or a == 0 or a != b:
        return False
    up1, up2 = prev.get("uptime_ms"), current.get("uptime_ms")
    if not isinstance(up1, int) or not isinstance(up2, int):
        return False
    if up2 < up1:  # disallow ambiguous wrap unless independently proven
        return False
    if current.get("sample_seq", 0) <= prev.get("sample_seq", 0):
        return False
    return True


def u32_delta(current, previous, *, continuous_epoch=False):
    """Refuse counter deltas without a PROVEN continuous radio generation."""
    if not continuous_epoch:
        return None
    if (type(current) is not int or type(previous) is not int
            or not 0 <= current <= 0xFFFFFFFF or not 0 <= previous <= 0xFFFFFFFF):
        return None
    return (current - previous) & 0xFFFFFFFF


def classify_host_observation(*, af_sreq_timeouts, zdo_sreq_timeouts=0,
                              sys_sreq_timeouts=0, zcl_timeouts=0, window_seconds=60,
                              sigterm=False, usb_disconnected=False,
                              ota_overlap=False):
    """Host-level symptoms ONLY, never firmware root-cause attribution.

    Host counts must be independently captured and time-windowed by SREQ
    waiter ID. This does not claim a radio hang or prove an OTA trigger.
    """
    for count in (af_sreq_timeouts, zdo_sreq_timeouts, sys_sreq_timeouts, zcl_timeouts):
        if type(count) is not int or count < 0:
            raise ValueError("counts must be nonnegative integers")
    if (type(window_seconds) not in (int, float)
            or not math.isfinite(window_seconds) or window_seconds <= 0):
        raise ValueError("window_seconds must be finite positive")
    if type(sigterm) is not bool or type(usb_disconnected) is not bool or type(ota_overlap) is not bool:
        raise ValueError("event switches must be boolean")
    signals = []
    if sigterm:
        signals.append("HOST_SIGTERM_OBSERVED")
    if usb_disconnected:
        signals.append("USB_DISCONNECTED_OBSERVED")
    if af_sreq_timeouts >= 8 and window_seconds <= 120:
        signals.append("AF_SREQ_TIMEOUT_BURST_OBSERVED")
    if zdo_sreq_timeouts:
        signals.append("ZDO_SREQ_TIMEOUT_OBSERVED")
    if sys_sreq_timeouts:
        signals.append("SYS_SREQ_TIMEOUT_OBSERVED")
    if zcl_timeouts:
        signals.append("ZCL_TIMEOUT_OBSERVED")
    return {
        "signals": signals or ["NO_MATCHING_HOST_SYMPTOM"],
        "root_cause": "UNDETERMINED",
        "ota_causal": False,
        "ota_temporal_overlap": ota_overlap,
        "synthetic_reference_model": True,
    }
