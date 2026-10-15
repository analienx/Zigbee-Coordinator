#!/usr/bin/env python3
"""Opt-in isolated-bench ZNP diagnostic read using a single serial owner.

Never accesses network/radio configuration or flash. The caller must stop Z2M.
Serial USB control-line behavior cannot be guaranteed without a board test.
"""
from __future__ import annotations

import argparse
import json
import re
import time
from pathlib import Path

from r2_diag_report import QUERY_FRAME, mt_frame, parse

IDENTITY_REQUEST=bytes.fromhex("fe00210425")  # SYS_GET_EXTADDR, zero payload
MAX_UNSOLICITED=16
MAX_BUSY_RETRIES=2
BUSY_RETRY_SECONDS=0.15
COMMAND_TIMEOUT_SECONDS=4.0


def check(condition: bool, code: str) -> None:
    if not condition:
        raise ValueError(code)


def normalize_ieee(value: str) -> str:
    cleaned=re.sub(r"[:-]","",value.lower())
    check(re.fullmatch(r"[0-9a-f]{16}",cleaned) is not None,"EXPECTED_IEEE_INVALID")
    return cleaned


def port_allowed(device: str) -> bool:
    return bool(re.fullmatch(r"COM[1-9][0-9]*",device,re.I) or
                re.fullmatch(r"/dev/serial/by-id/[A-Za-z0-9._:+-]+",device))


def read_response(port, cmd: int, max_seconds: float=COMMAND_TIMEOUT_SECONDS) -> bytes:
    """Consume complete CRC-checked frames until matching SRSP. No blind flush."""
    deadline=time.monotonic()+max_seconds
    skipped=0
    def read_byte():
        while time.monotonic()<deadline:
            byte=port.read(1)
            if byte:
                check(len(byte)==1,"ZNP_SERIAL_READ_SIZE_INVALID")
                return byte[0]
        raise ValueError("ZNP_RESPONSE_TIMEOUT")

    while True:
        check(read_byte()==0xFE,"ZNP_UNEXPECTED_PREFIX")
        size=read_byte()
        command=read_byte()
        command_id=read_byte()
        check(size<=250,"ZNP_RESPONSE_TOO_LARGE")
        payload=bytes(read_byte() for _ in range(size))
        checksum=read_byte()
        actual=size^command^command_id
        for byte in payload:
            actual^=byte
        check(actual==checksum,"ZNP_BAD_RESPONSE_FCS")
        if (command,command_id)==(0x61,cmd):
            return payload
        # Valid asynchronous indication may arrive before an SRSP, but a
        # reset invalidates prior identity/session evidence: fail closed.
        check((command,command_id)!=(0x41,0x80),"ZNP_RESET_INDICATION_ABORT")
        # Never swallow unrelated SRSPs, malformed frames or AREQ floods.
        check((command & 0xE0)==0x40,"ZNP_UNEXPECTED_FRAME_TYPE")
        skipped+=1
        check(skipped<=MAX_UNSOLICITED,"ZNP_UNSOLICITED_LIMIT")


def capture(port, expected_ieee: str, *, sleep=time.sleep) -> dict:
    """Identity must match before SYS F0; BUSY is the ONLY retryable status."""
    expected=normalize_ieee(expected_ieee)
    port.write(IDENTITY_REQUEST)
    port.flush()
    ieee=read_response(port,0x04)
    check(len(ieee)==8,"ZNP_IEEE_LENGTH_INVALID")
    check(ieee[::-1].hex()==expected,"WRONG_RADIO_IEEE_NO_DIAGNOSTIC_QUERY")

    for attempt in range(MAX_BUSY_RETRIES+1):
        port.write(QUERY_FRAME)
        port.flush()
        result=parse(read_response(port,0xF0))
        if result["status"]!="BUSY":
            return result
        if attempt<MAX_BUSY_RETRIES:
            sleep(BUSY_RETRY_SECONDS)
    return result


def open_serial_exclusive(serial, device: str):
    """Set modem lines to disabled BEFORE open; physical glitch still possible."""
    port=serial.Serial(port=None, baudrate=115200, timeout=0.2,
                       write_timeout=2, rtscts=False, dsrdtr=False)
    try:
        port.dtr=False
        port.rts=False
        port.port=device
        port.open()
        return port
    except Exception:
        port.close()
        raise


def main() -> None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--device",required=True,help="Explicit COMn or /dev/serial/by-id, no socket://")
    p.add_argument("--expected-ieee",required=True,help="Independently recorded 16-digit P7U IEEE, MSB-first")
    p.add_argument("--isolated-p7u",action="store_true")
    p.add_argument("--z2m-stopped",action="store_true")
    p.add_argument("--out",type=Path,required=True,help="New private report, refuse overwrite")
    args=p.parse_args()
    try:
        check(port_allowed(args.device),"USB_SERIAL_BY_ID_OR_COM_REQUIRED")
        check(args.isolated_p7u and args.z2m_stopped,"ISOLATED_EXCLUSIVE_OWNER_REQUIRED")
        normalize_ieee(args.expected_ieee)
        check(not args.out.exists() and not args.out.is_symlink(),"OUTPUT_MUST_BE_NEW")
        import serial
        with open_serial_exclusive(serial,args.device) as port:
            data=capture(port,args.expected_ieee)
        check(data["status"]=="OK","P7_G6_SNAPSHOT_NOT_READY_"+data["status"])
        args.out.parent.mkdir(parents=True,exist_ok=True)
        with args.out.open("x",encoding="utf-8") as fd:
            fd.write(json.dumps(data,indent=2,sort_keys=True)+"\n")
        print(json.dumps({"status":"CAPTURED_READ_ONLY","out":str(args.out),
                          "serial_control_lines":"DISABLED_REQUESTED_NOT_HARDWARE_PROVEN",
                          "radio_reset_proven_absent":False,"flash_performed":False}))
    except (ValueError,OSError,ImportError) as exc:
        code=str(exc) if isinstance(exc,ValueError) else "SERIAL_OR_OUTPUT_IO_FAILED"
        print(json.dumps({"status":"FAIL_CLOSED","code":code,"flash_performed":False}))
        raise SystemExit(2) from None


if __name__=="__main__":
    main()
