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

def test_no_forbidden_tokens_in_c():
    for name in ("p7_crashdiag.h","p7_crashdiag.c"):
        data=(ROOT/"firmware/slzb-06p7/ti832/g5"/name).read_bytes()
        for tok in (b"malloc(",b"nvs_write(",b"printf("):
            assert tok not in data, (name,tok)

if __name__=="__main__":
    test_golden_roundtrip(); test_malformed_rejected()
    test_negative_classifications(); test_no_forbidden_tokens_in_c()
    d.selftest()
    print("PASS test_crashdiag (standalone)")
