#!/usr/bin/env python3
"""Offline decoder for versioned BSEED P10 MT SYS F0 response payload.

Does not open serial, MQTT, Zigbee2MQTT, HTTP, or the hardware adapter.
"""
import argparse
import json
import re
import struct

FIELDS = (
    "srsp_depth", "srsp_high_water", "async_depth", "async_high_water",
    "srsp_enqueued", "srsp_uart_accepted", "async_uart_accepted",
    "tx_immediate_rejects", "tx_rejected_drops",
    "stack_frame_failures", "stack_queue_failures",
    "srsp_allocation_failures", "srsp_enqueue_failures",
    "rx_frame_failures", "srsp_queue_fallbacks",
    "af_direct_accepted", "af_direct_buffer_full", "af_direct_memory_failure", "af_direct_other",
    "af_source_accepted", "af_source_buffer_full", "af_confirm_cca_failure", "af_confirm_other_failure",
    "rx_overflow_events", "rx_overflow_discarded_bytes"
)
VERSION = 2
SIZE = 2 + len(FIELDS) * 4

def decode(data: bytes) -> dict:
    if len(data) != SIZE:
        raise ValueError(f"NPI_DIAG_SIZE_EXPECTED_{SIZE}_GOT_{len(data)}")
    if data[0] != VERSION:
        raise ValueError(f"NPI_DIAG_VERSION_UNSUPPORTED_{data[0]}")
    flags = data[1]
    if flags & ~0x07:
        raise ValueError("NPI_DIAG_UNKNOWN_FLAGS")
    values = struct.unpack_from("<" + "I" * len(FIELDS), data, 2)
    return {
        "version": VERSION,
        "srsp_priority_queue_enabled": bool(flags & 1),
        "uart_retry_pending": bool(flags & 2),
        "uart_transport_busy": bool(flags & 4),
        "counters": dict(zip(FIELDS, values)),
        "interpretation": "UART accepted is NOT UART on-wire completion or Zigbee delivery",
    }

def parse_hex(value: str) -> bytes:
    clean = re.sub(r"(?:0[xX])|[ \t\n_:\-]", "", value)
    if not re.fullmatch(r"[0-9a-fA-F]*", clean) or len(clean) % 2:
        raise ValueError("HEX_BYTES_REQUIRED")
    return bytes.fromhex(clean)

def selftest() -> None:
    data=bytes([VERSION, 1]) + struct.pack("<" + "I"*len(FIELDS),
        *[0xA1B2C3D4 if i==4 else i*99 for i in range(len(FIELDS))])
    out=decode(data)
    assert out["counters"]["srsp_enqueued"]==0xA1B2C3D4
    assert out["srsp_priority_queue_enabled"] is True
    assert decode(parse_hex(data.hex())) == out
    for bad in [data[:-1], bytes([2])+data[1:], data[:1]+bytes([0x80])+data[2:]]:
        try:
            decode(bad)
            raise AssertionError("invalid payload accepted")
        except ValueError:
            pass
    print("PASS versioned NPI SYS F0 payload decode and reject tests")

def main() -> None:
    p=argparse.ArgumentParser(description=__doc__)
    m=p.add_mutually_exclusive_group(required=True)
    m.add_argument("--payload-hex", help="102 payload bytes ONLY, without UNPI framing")
    m.add_argument("--selftest", action="store_true")
    a=p.parse_args()
    if a.selftest:
        selftest()
    else:
        print(json.dumps(decode(parse_hex(a.payload_hex)), indent=2, sort_keys=True))

if __name__=="__main__":
    main()
