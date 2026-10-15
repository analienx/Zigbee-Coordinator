#!/usr/bin/env python3
"""New operator-facing diagnostics regression for existing G6 SYS 0xF0 ABI."""
from __future__ import annotations
import argparse,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"firmware/slzb-06p7/ti832/g7"))
from r2_diag_report import QUERY_FRAME,mt_frame,decode_mt_frame,parse,g6
from r2_diag_gate import source_check

def expect_reject(data,tag):
    try:parse(data)
    except ValueError:return
    raise AssertionError("BAD_FRAME_ACCEPTED_"+tag)

def g6_envelope(events=None,status=0,version=1,period=1000):
    x=bytearray(b"P7G6"+bytes([version,status,1,0])+struct.pack("<I",period)+bytes(4))
    if status==0:
        x+=g6.g5.encode(events or [(1,0,1,0),(2,0,16,0xFFFF),
                                  (3,7,22,1),(4,8,13,0)],boot_gen=1)
    x+=struct.pack("<H",g6.g5.crc16(x))
    return bytes(x)

def run():
    source_check()
    assert QUERY_FRAME.hex()=="fe0221f00100d2"
    assert len(QUERY_FRAME)==7
    good=g6_envelope()
    result=parse(mt_frame(good,0x61))
    assert result["status"]=="OK"
    assert result["usable_snapshot"] is True
    assert result["nv_state"]=="unknown"
    assert len(result["recent_events"])==4
    assert len(result["actionable_recent_events"])==2
    assert result["total_recorded_events"]==4
    assert result["cross_boot_duration_ms"] is None
    assert result["boot_generation_reboot_unique"] is False
    assert result["reset_cause_instrumented_in_current_firmware"] is False
    assert result["available_metrics"]["reset_cause_if_known"] is False
    assert result["reset_source"] is None and result["reset_source_raw"] is None
    assert result["available_metrics"]["nwk_source_route_failures"] is False
    assert result["available_metrics"]["af_cca_failures"] is False
    assert result["available_metrics"]["recent_uart_npi_errors"] is True
    assert parse(good)["status"]=="OK"
    for status,name in ((1,"LENGTH_ERROR"),(2,"VERSION_ERROR"),
                        (3,"OPERATION_ERROR"),(4,"BUSY"),(5,"WRONG_COMMAND_TYPE")):
        r=parse(mt_frame(g6_envelope(status=status),0x61))
        assert r["status"]==name and r["usable_snapshot"] is False
    frame=mt_frame(good,0x61)
    for name,bad in [
        ("empty",b""),("truncated",frame[:-1]),("trailing",frame+b"x"),
        ("fcs",frame[:-1]+bytes([frame[-1]^1])),
        ("wrong_cmd",mt_frame(good,0x41)),("bad_version",g6_envelope(version=2)),
        ("bad_period",g6_envelope(period=0)),
        ("inner_crc",good[:-3]+bytes([good[-3]^1])+good[-2:]),
        ("bad_header",b"Z"+good[1:]),
        ("future_status",g6_envelope(status=8)),
        ("bad_inner_length",good[:16]+good[16:-3]+good[-2:]),
    ]:
        expect_reject(bad,name)
    print("R2_EXISTING_G6_DIAG_HOST_PROTOCOL_TEST_PASS 5 status codes, 11 hostile frames")

def capture_tests():
    from r2_diag_capture import capture, port_allowed, IDENTITY_REQUEST
    assert IDENTITY_REQUEST.hex()=="fe00210425"
    assert port_allowed("COM17") and port_allowed("/dev/serial/by-id/usb-SMLIGHT_test")
    assert not port_allowed("socket://192.168.1.2:6638")
    assert not port_allowed("COM0")
    eui=bytes.fromhex("1122334455667788")
    full_ieee="8877665544332211"
    def address_frame(identity=eui):
        buf=bytes((8,0x61,0x04))+identity
        fcs=0
        for v in buf:fcs^=v
        return bytes((0xfe,))+buf+bytes((fcs,))
    good=mt_frame(g6_envelope(),0x61)
    class Fake:
        def __init__(self,rx):
            self.rx=bytearray(rx)
            self.tx=[]
        def read(self,n):
            if not self.rx:return b""
            b=bytes(self.rx[:n]);del self.rx[:n];return b
        def write(self,data):
            self.tx.append(bytes(data));return len(data)
        def flush(self):pass
    f=Fake(address_frame()+good)
    o=capture(f,full_ieee)
    assert o["status"]=="OK" and f.tx==[IDENTITY_REQUEST,QUERY_FRAME]
    wrong=Fake(address_frame()+good)
    try:capture(wrong,"0000000000000000")
    except ValueError as e:assert str(e)=="WRONG_RADIO_IEEE_NO_DIAGNOSTIC_QUERY"
    else:raise AssertionError("WRONG_IDENTITY_ACCEPTED")
    assert wrong.tx==[IDENTITY_REQUEST]
    corrupt=bytearray(address_frame());corrupt[-1]^=1
    try:capture(Fake(bytes(corrupt)+good),full_ieee)
    except ValueError:pass
    else:raise AssertionError("CORRUPT_IEEE_FRAME_ACCEPTED")

    # Valid asynchronous indication can precede BOTH responses, without
    # hijacking the waiter. Unrelated SRSP remains a hard error.
    async_frame=mt_frame(b"\\x01",0x45)  # synthetic AREQ subsystem ZDO
    f=Fake(async_frame+address_frame()+async_frame+good)
    assert capture(f,full_ieee)["status"]=="OK"
    assert f.tx==[IDENTITY_REQUEST,QUERY_FRAME]
    wrong_srsp=bytearray(mt_frame(bytes((0,)),0x61))
    wrong_srsp[3]=0x02  # unrelated SYS VERSION SRSP instead of SYS F0
    wrong_srsp[-1]^=0xF0^0x02
    wrong_srsp=bytes(wrong_srsp)
    for payload in (wrong_srsp+address_frame()+good,
                    address_frame()+wrong_srsp+good):
        try:capture(Fake(payload),full_ieee)
        except ValueError as e:assert str(e)=="ZNP_UNEXPECTED_FRAME_TYPE"
        else:raise AssertionError("UNRELATED_SRSP_ACCEPTED")
    # Bound valid AREQ floods; never loop forever.
    from r2_diag_capture import MAX_UNSOLICITED,MAX_BUSY_RETRIES,read_response,open_serial_exclusive
    try:read_response(Fake(async_frame*(MAX_UNSOLICITED+1)+address_frame()),0x04)
    except ValueError as e:assert str(e)=="ZNP_UNSOLICITED_LIMIT"
    else:raise AssertionError("UNBOUNDED_UNSOLICITED")
    # RESET_IND means the identity check cannot be trusted across reset.
    reset=bytearray(mt_frame(bytes((1,)),0x41));reset[3]=0x80
    reset[-1]^=0xF0^0x80
    try:read_response(Fake(bytes(reset)+address_frame()),0x04)
    except ValueError as e:assert str(e)=="ZNP_RESET_INDICATION_ABORT"
    else:raise AssertionError("RESET_INDICATION_SWALLOWED")
    bad_async=bytearray(async_frame);bad_async[-1]^=1
    try:read_response(Fake(bytes(bad_async)+address_frame()),0x04)
    except ValueError as e:assert str(e)=="ZNP_BAD_RESPONSE_FCS"
    else:raise AssertionError("CORRUPT_ASYNC_ACCEPTED")

    # Recover only transient BUSY, with capped retries; unknown errors fail.
    busy=mt_frame(g6_envelope(status=4),0x61)
    sleeps=[]
    f=Fake(address_frame()+busy+good)
    assert capture(f,full_ieee,sleep=sleeps.append)["status"]=="OK"
    assert f.tx==[IDENTITY_REQUEST,QUERY_FRAME,QUERY_FRAME]
    assert sleeps==[0.15]
    f=Fake(address_frame()+busy*(MAX_BUSY_RETRIES+1))
    assert capture(f,full_ieee,sleep=sleeps.append)["status"]=="BUSY"
    assert len(f.tx)==MAX_BUSY_RETRIES+2  # identity plus max F0 queries
    f=Fake(address_frame()+mt_frame(g6_envelope(status=2),0x61)+good)
    assert capture(f,full_ieee,sleep=sleeps.append)["status"]=="VERSION_ERROR"
    assert len(f.tx)==2

    # The writer does not open with default RTS/DTR asserted. No real port.
    class SerialStub:
        def __init__(self,**kwargs):
            assert kwargs["port"] is None and not kwargs["rtscts"] and not kwargs["dsrdtr"]
            self.dtr=True;self.rts=True;self.port=None;self.events=[]
        def open(self):
            assert self.port=="COM17" and self.dtr is False and self.rts is False
            self.events.append("open_safe_lines_requested")
        def close(self):self.events.append("close")
    class SerialModule:
        Serial=SerialStub
    serial_port=open_serial_exclusive(SerialModule,"COM17")
    assert serial_port.events==["open_safe_lines_requested"]


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--sdk",type=Path)
    p.add_argument("--herdsman",type=Path)
    args=p.parse_args()
    if args.sdk or args.herdsman:
        assert args.sdk and args.herdsman
        sys.path.insert(0,str(ROOT/"firmware/slzb-06p7/ti832/g6"))
        from check_compatibility import check
        assert check(args.sdk,args.herdsman)["sys_f0_collision"] is False
    run()
    capture_tests()
    print("R2_READONLY_CAPTURE_IEEE_FAULT_TEST_PASS")

if __name__=="__main__":main()
