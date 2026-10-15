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
