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
    assert dec["reset_source"] is None and dec["reset_known"] is False
    assert [e["kind"] for e in dec["events"]]==["BOOT_ENTER","RESET_SOURCE","NV_READ_BEGIN","NV_RESTORED","SRSP_QUEUED"]
    assert [e["tick"] for e in dec["events"]]==[0,0,5,9,12]
    assert [e["seq"] for e in dec["events"]]==[1,2,3,4,5]
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

def test_decoder_strictness():
    import struct
    for evs in ([(0xFFFFFFFF,0,1,0),(0xFFFFFFFF,1,1,0)],[(1,0,1,0),(100,1,1,0)],[(1,0,1,0),(1,1,1,0)]):
        try: d.decode(d.encode(evs))
        except ValueError: continue
        raise AssertionError(f"non-contiguous accepted {evs}")
    raw=bytearray(d.encode([(1,0,1,0)])); raw[18]=0xFF
    raw[-2:]=struct.pack("<H",d.crc16(bytes(raw[:-2])))
    try: d.decode(bytes(raw))
    except ValueError: pass
    else: raise AssertionError("reserved nonzero accepted")
    assert d.classify({"queue_current_samples":[True,True],"uart_tx_finished":False})=="UNKNOWN_INSUFFICIENT_EVIDENCE"
    for kw in (dict(total=5,dropped=999),dict(total=1,dropped=999)):
        try: d.decode(d.encode([(10,0,1,0),(11,1,1,0)],**kw))
        except ValueError: continue
        raise AssertionError(f"total/dropped bypass {kw}")
    ok=d.decode(d.encode([(69,0,1,0),(70,1,1,0)],total=70,dropped=6,isr_dropped=5))
    assert ok["isr_dropped"]==5 and ok["dropped"]==6
    boot=d.decode(d.encode([(5,500,3,0),(6,0,1,0),(7,0,16,0xFFFF)],total=7))
    assert boot["events"][1]["kind"]=="BOOT_ENTER"
    # preserved history: prior boot RESET_SOURCE(0xFFFF) + new boot source=1 decodes
    pres=d.decode(d.encode([(1,0,1,0),(2,0,16,0xFFFF),(3,9,3,0),(4,0,1,0),(5,0,16,1)],boot_gen=51,reset_known=1,reset_source=1,total=5))
    assert pres["reset_source"]==1 and len(pres["events"])==5

def test_extended_kinds_and_seal_api():
    dec=d.decode(d.encode([(1,0,17,0),(2,1,18,0),(3,2,19,0),(4,3,20,0),(5,4,21,0),(6,5,22,0)]))
    assert [e["kind"] for e in dec["events"]]==["ZDO_DISPATCH","NPI_Q_ACCEPT","NPI_Q_REJECT","PARSE_ERR","FCS_ERR","OVERFLOW"]
    hdr=(ROOT/"firmware/slzb-06p7/ti832/g5/p7_crashdiag.h").read_text()
    src=(ROOT/"firmware/slzb-06p7/ti832/g5/p7_crashdiag.c").read_text()
    assert "p7_diag_seal_retained" in hdr and "p7_diag_preempt_hook" in hdr
    import re as _re
    body=_re.search(r"static void record_common\(.*?\n\}\n", src, _re.S).group(0)
    assert "retained_compute" not in body and "fold_event(e);" in body, "record path not O(1) fold"
    assert src.count("retained_compute()")>=2  # seal + boot verify definition/call sites only

def test_no_forbidden_tokens_in_c():
    for name in ("p7_crashdiag.h","p7_crashdiag.c"):
        data=(ROOT/"firmware/slzb-06p7/ti832/g5"/name).read_bytes()
        for tok in (b"malloc(",b"nvs_write(",b"printf("):
            assert tok not in data, (name,tok)

if __name__=="__main__":
    test_golden_roundtrip(); test_c_snapshot_cross_decode(); test_malformed_rejected()
    test_negative_classifications(); test_decoder_strictness(); test_extended_kinds_and_seal_api(); test_no_forbidden_tokens_in_c()
    d.selftest()
    print("PASS test_crashdiag (standalone)")
