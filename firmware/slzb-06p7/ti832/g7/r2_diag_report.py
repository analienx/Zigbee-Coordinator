#!/usr/bin/env python3
"""Strict offline decoder for the ALREADY IMPLEMENTED P7 G6 SYS/0xF0 endpoint.

The composed R2 native firmware already has the G6 endpoint. It requires a
two-byte request payload [version=1, operation=0], not a zero-byte request.
This utility makes the existing telemetry usable without patching the radio.
It NEVER opens UART, LAN, MQTT or a second Zigbee2MQTT serial owner.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
from pathlib import Path

SPEC=Path(__file__).resolve().parents[1]/"g6"/"p7_g6_decode.py"
spec=importlib.util.spec_from_file_location("p7_existing_g6_decode",SPEC)
assert spec and spec.loader
g6=importlib.util.module_from_spec(spec)
spec.loader.exec_module(g6)

def mt_frame(payload: bytes, command: int) -> bytes:
    if len(payload)>250:raise ValueError("MT_PAYLOAD_OVER_LIMIT")
    body=bytes((len(payload),command,0xf0))+payload
    fcs=0
    for b in body:fcs^=b
    return b"\xfe"+body+bytes((fcs,))

QUERY_FRAME=mt_frame(b"\x01\x00",0x21)
G6_STATUS={0:"OK",1:"LENGTH_ERROR",2:"VERSION_ERROR",
           3:"OPERATION_ERROR",4:"BUSY",5:"WRONG_COMMAND_TYPE"}
ACTIONABLE=frozenset(("NV_AMBIGUOUS","FAULT","UART_REJECTED","NPI_Q_REJECT",
                       "PARSE_ERR","FCS_ERR","OVERFLOW"))

def decode_mt_frame(raw: bytes)->bytes:
    if len(raw)<5 or raw[0]!=0xfe:raise ValueError("MT_FRAME_BAD_HEADER")
    n,cmd0,cmd1=raw[1],raw[2],raw[3]
    if (cmd0,cmd1)!=(0x61,0xf0):raise ValueError("NOT_P7_G6_SYS_F0_SRSP")
    if len(raw)!=n+5:raise ValueError("MT_FRAME_LENGTH_MISMATCH")
    fcs=0
    for b in raw[1:]:fcs^=b
    if fcs:raise ValueError("MT_FRAME_FCS_MISMATCH")
    return raw[4:-1]

def parse(raw: bytes) -> dict:
    if raw.startswith(b"\xfe"):raw=decode_mt_frame(raw)
    envelope=g6.decode(raw)
    status=envelope["status"]
    if status not in G6_STATUS:raise ValueError("UNKNOWN_G6_STATUS")
    result={
      "status":G6_STATUS[status],
      "protocol":"P7G6_V1_READ_ONLY",
      "tick_period_us":envelope["tick_period_us"],
      "reboot_identity":"UNKNOWN",
      "flash_authorized":False,
      "available_metrics":{
        "nv_startup_state":True,
        "reset_cause_if_known":True,
        "recent_uart_npi_errors":True,
        "total_recorder_events_since_boot":True,
        "event_timestamps":True,
        "physical_uart_tx_event_if_observed":True,
        "nwk_source_route_failures":False,
        "af_cca_failures":False,
        "zcl_ack_delivery":False,
        "queue_high_water":False,
        "nv_physical_write_durability":False,
      },
      "interpretation":("The last 8 events are NOT lifetime per-kind counters. "
                        "UART FIFO-loaded is NOT confirmed wire completion. "
                        "No recorded route/AF errors does NOT mean zero failures. "
                        "Device and reboot identity must be established externally."),
    }
    if status:
        result["usable_snapshot"]=False
        return result
    snap=envelope["snapshot"]
    events=snap["events"]
    result.update({
      "usable_snapshot":True,
      "nv_state":g6.g5.NV_NAMES[snap["nv_state"]],
      "boot_generation":snap["boot_generation"],
      "reset_source":snap["reset_source"],
      "total_recorded_events":snap["total"],
      "ring_overwrites":snap["dropped"],
      "recorder_contention_drops":snap["isr_dropped"],
      "recent_events":events,
      "actionable_recent_events":[e for e in events if e["kind"] in ACTIONABLE],
      "cross_boot_duration_ms":None,
      "cross_boot_duration_note":"No reboot-unique identity is available; do not infer intervals across boot boundaries."
    })
    return result

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--response-hex",help="Whole FE... MT SRSP frame or bare P7G6 body")
    ap.add_argument("--response-file",type=Path,help="Read-only file of captured bytes")
    ap.add_argument("--print-request",action="store_true")
    args=ap.parse_args()
    if args.print_request:
        print(json.dumps({
            "command":"MT SREQ SYS/0xF0 G6v1",
            "request_hex":QUERY_FRAME.hex(),
            "body_hex":"0100",
            "must_use_existing_exclusive_znp_owner":True,
            "no_direct_connection_to_running_zigbee2mqtt":True}))
    if args.response_hex is None and args.response_file is None:
        if args.print_request:return
        ap.error("provide captured response")
    if args.response_hex is not None and args.response_file is not None:
        ap.error("one response format only")
    try:
        raw=(bytes.fromhex(args.response_hex) if args.response_hex is not None
             else args.response_file.read_bytes())
        print(json.dumps(parse(raw),sort_keys=True,indent=2))
    except (ValueError,OSError) as exc:
        print(json.dumps({"status":"REJECTED","code":str(exc)}))
        raise SystemExit(2) from None

if __name__=="__main__":main()
