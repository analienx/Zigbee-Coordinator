#!/usr/bin/env python3
"""Explicit BENCH-ONLY ZNP SYS/0xF0 read via exclusive P7U serial owner.

Does not stop/restart Z2M, reset radio, change network, write NV or flash.
Requires independent expected coordinator IEEE, declared isolated P7U and
Zigbee2MQTT stopped. Fails closed on any unsolicited/malformed response.
"""
from __future__ import annotations
import argparse
import json
import re
import time
from pathlib import Path

from r2_diag_report import QUERY_FRAME, decode_mt_frame, mt_frame, parse

IDENTITY_REQUEST=mt_frame(b"",0x21)[:3]+b"\x04\x25"  # FE 00 21 04 25

def check(v,code):
    if not v:raise ValueError(code)

def normalize_ieee(value:str)->str:
    cleaned=re.sub(r"[:\-]","",value.lower())
    check(re.fullmatch(r"[0-9a-f]{16}",cleaned) is not None,"EXPECTED_IEEE_INVALID")
    return cleaned

def port_allowed(device:str)->bool:
    return bool(re.fullmatch(r"COM[1-9][0-9]*",device,re.I)
                or re.fullmatch(r"/dev/serial/by-id/[A-Za-z0-9._:+-]+",device))

def read_response(port, cmd:int, max_seconds:float=4.0)->bytes:
    deadline=time.monotonic()+max_seconds
    def get():
        while time.monotonic()<deadline:
            b=port.read(1)
            if b:return b
        raise ValueError("ZNP_RESPONSE_TIMEOUT")
    # A distinct 0xFE SOP must be observed; no blind buffer flush.
    for _ in range(64):
        if get()==b"\xfe":break
    else:raise ValueError("ZNP_SOP_NOT_FOUND")
    size=get()[0]; command=get()[0]; cid=get()[0]
    check(size<=250,"ZNP_RESPONSE_TOO_LARGE")
    check((command,cid)==(0x61,cmd),"ZNP_UNEXPECTED_SUBSYSTEM_OR_COMMAND")
    payload=bytes(get()[0] for _ in range(size))
    fcs=get()[0]
    raw=b"\xfe"+bytes((size,command,cid))+payload+bytes((fcs,))
    check(decode_mt_frame(raw) == payload if cmd==0xf0 else
          (fcs == __import__("functools").reduce(lambda a,b:a^b,raw[1:-1],0)),
          "ZNP_BAD_RESPONSE_FCS")
    return payload

def capture(port,expected_ieee:str)->dict:
    port.write(IDENTITY_REQUEST)
    port.flush()
    ieee=read_response(port,0x04)
    check(len(ieee)==8,"ZNP_IEEE_LENGTH_INVALID")
    check(ieee[::-1].hex()==normalize_ieee(expected_ieee),
          "WRONG_RADIO_IEEE_NO_DIAGNOSTIC_QUERY")
    port.write(QUERY_FRAME)
    port.flush()
    return parse(read_response(port,0xf0))

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--device",required=True,help="Explicit COMn or /dev/serial/by-id path; never socket://")
    p.add_argument("--expected-ieee",required=True,help="Previously independently recorded P7U coordinator IEEE, MSB-first")
    p.add_argument("--isolated-p7u",action="store_true")
    p.add_argument("--z2m-stopped",action="store_true")
    p.add_argument("--out",required=True,type=Path,help="New, private output JSON; never overwrite existing")
    args=p.parse_args()
    try:
        check(port_allowed(args.device),"USB_SERIAL_BY_ID_OR_COM_REQUIRED")
        check(args.isolated_p7u and args.z2m_stopped,"ISOLATED_EXCLUSIVE_OWNER_REQUIRED")
        normalize_ieee(args.expected_ieee)
        check(not args.out.exists() and not args.out.is_symlink(),"OUTPUT_MUST_BE_NEW")
        import serial  # only load for explicitly approved hardware operation
        with serial.Serial(args.device,baudrate=115200,timeout=0.2,write_timeout=2) as port:
            data=capture(port,args.expected_ieee)
        check(data["status"]=="OK","P7_G6_SNAPSHOT_NOT_READY")
        args.out.parent.mkdir(parents=True,exist_ok=True)
        with args.out.open("x",encoding="utf-8") as dst:
            dst.write(json.dumps(data,indent=2,sort_keys=True)+"\n")
        print(json.dumps({"status":"CAPTURED_READ_ONLY","out":str(args.out),
                          "nv_written":False,"reset_issued":False,"flash_performed":False}))
    except (ValueError,OSError,ImportError) as exc:
        code=str(exc) if isinstance(exc,ValueError) else "SERIAL_OR_OUTPUT_IO_FAILED"
        print(json.dumps({"status":"FAIL_CLOSED","code":code,"flash_performed":False}))
        raise SystemExit(2) from None

if __name__=="__main__":main()
