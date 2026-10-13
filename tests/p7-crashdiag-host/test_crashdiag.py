#!/usr/bin/env python3
"""Durable offline tests for G5 (runnable standalone or under pytest)."""
import subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"firmware/slzb-06p7/ti832/g5"))
import p7_diag_decode as d  # noqa: E402

def test_golden_roundtrip():
    dec=d.decode(bytes.fromhex(d.GOLDEN_HEX))
    assert dec["boot_generation"]==7 and [e["kind"] for e in dec["events"]]==[
        "BOOT_ENTER","RESET_SOURCE","NV_RESTORED","SRSP_QUEUED"]

def test_c_snapshot_cross_decode():
    import os
    exe=os.environ.get("CRASHDIAG_HOST_BIN")
    if not exe: return  # CI sets it; the C bytes are then decoded here
    out=subprocess.run([exe],capture_output=True,text=True,check=True).stdout
    hx=[l.split("=",1)[1] for l in out.splitlines() if l.startswith("SNAPSHOT_HEX=")][0]
    dec=d.decode(bytes.fromhex(hx))
    assert dec["boot_generation"]==7 and dec["nv_state"]==1
    assert [e["kind"] for e in dec["events"]]==["BOOT_ENTER","RESET_SOURCE","NV_READ_BEGIN","NV_RESTORED","SRSP_QUEUED"]
    assert d.classify({"snapshot":dec})=="UNKNOWN_INSUFFICIENT_EVIDENCE"

def test_malformed_rejected():
    raw=bytes.fromhex(d.GOLDEN_HEX)
    for bad in (raw[:-3], raw[:4]+b"\x09"+raw[5:], b"\x00"*40):
        try: d.decode(bad)
        except ValueError: continue
        raise AssertionError("malformed accepted")

def test_negative_classifications():
    assert d.classify({"host_timeout_40s":True})=="UNKNOWN_TIMEOUT_NOT_CRASH"
    assert d.classify({"queue_high_water":158,"queue_current":0})=="NOT_STUCK_HIGHWATER_ONLY"
    assert d.classify({"diag_rtt_ms":1545})=="UNKNOWN_RTT_ONLY"
    assert d.classify({"uart_accepted":True})=="UNKNOWN_HOST_RECEPTION_UNPROVEN"
    assert d.classify({"nv_state":"ambiguous"})=="UNKNOWN_NV_AMBIGUOUS"
    assert d.classify({"nv_state":"restored"})=="UNKNOWN_INSUFFICIENT_EVIDENCE"
    assert d.classify({"nv_state":"new"})=="UNKNOWN_INSUFFICIENT_EVIDENCE"
    assert d.classify({"host_timeout_40s":True,"srsp_queued":True})=="UNKNOWN_TIMEOUT_NOT_CRASH"
    assert d.classify({"queue_high_water":158,"queue_current":3,"uart_tx_finished":False,"diag_rtt_ms":1})=="UNKNOWN_INSUFFICIENT_EVIDENCE"
    assert d.classify({"queue_current_samples":[3,3],"uart_tx_finished":False})=="POSSIBLE_TX_STALL_DEPTH_PERSISTS"
    snap=d.decode(d.encode([(1,0,1,0)],nv_state=3))
    assert d.classify({"snapshot":snap})=="UNKNOWN_NV_AMBIGUOUS"

def test_no_forbidden_tokens_in_c():
    for name in ("p7_crashdiag.h","p7_crashdiag.c"):
        data=(ROOT/"firmware/slzb-06p7/ti832/g5"/name).read_bytes()
        for tok in (b"malloc(",b"nvs_write(",b"printf("):
            assert tok not in data, (name,tok)

if __name__=="__main__":
    test_golden_roundtrip(); test_c_snapshot_cross_decode(); test_malformed_rejected()
    test_negative_classifications(); test_no_forbidden_tokens_in_c()
    d.selftest()
    print("PASS test_crashdiag (standalone)")
