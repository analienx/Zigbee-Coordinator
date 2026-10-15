"""Versioned G6 envelope and modulo clock calculations. No hardware access."""
import struct, sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"g5"))
import p7_diag_decode as g5

HEALTH_COUNTERS=("af_success", "af_no_route", "af_cca_failure", "af_no_ack",
    "af_other_failure", "uart_rejected", "queue_rejected", "rx_overflow",
    "parse_error", "fcs_error", "nv_ambiguous", "nv_failure", "queue_accepted",
    "uart_tx_idle", "af_confirm_total", "zdo_dispatch")

def decode(raw):
    if len(raw)<18 or len(raw)>144 or raw[:4]!=b"P7G6" or raw[4] not in (1,2): raise ValueError("BAD_G6_HEADER")
    if struct.unpack_from("<H",raw,len(raw)-2)[0]!=g5.crc16(raw[:-2]):raise ValueError("G6_CRC_MISMATCH")
    if raw[6]!=1 or raw[7]!=0 or raw[12:16]!=bytes(4): raise ValueError("UNSUPPORTED_CLOCK_EPOCH")
    period=struct.unpack_from("<I",raw,8)[0]
    if not period: raise ValueError("UNKNOWN_CLOCK_PERIOD")
    if raw[5]:
        if raw[5]>5 or len(raw)!=18: raise ValueError("BAD_G6_STATUS")
        return {"version":raw[4],"status":raw[5],"tick_period_us":period,"reboot_identity":None}
    if raw[4]==2:
        if len(raw)!=118: raise ValueError("BAD_HEALTH_LENGTH")
        body=raw[16:-2]
        if body[0]!=len(HEALTH_COUNTERS) or body[1] not in (0,1) or body[2:4]!=bytes(2):
            raise ValueError("BAD_HEALTH_METADATA")
        values=struct.unpack_from("<16I",body,4)
        kind,arg,tick,now,contention=struct.unpack_from("<HHIII",body,68)
        if (body[1]==0 and (kind or arg or tick)) or (body[1] and kind not in (15,26)):
            raise ValueError("BAD_FIRST_FAULT")
        if kind==26 and not arg>>8: raise ValueError("MISSING_NV_FAILURE_SITE")
        if body[84] not in (0,1) or body[85] not in (0,1):
            raise ValueError("BAD_RUNTIME_CONCENTRATOR")
        heap_total,heap_free,heap_errors=struct.unpack_from("<III",body,88)
        return {"version":2,"status":0,"tick_period_us":period,"reboot_identity":None,
            "counters":dict(zip(HEALTH_COUNTERS,values)),"sample_tick":now,
            "writer_contention_dropped":contention,
            "first_fault":({"kind":g5.KINDS[kind],"arg":arg,"tick":tick,
                **({"status":arg&255,"site":arg>>8} if kind==26 else {})} if body[1] else None),
            "runtime_concentrator":{"enable":body[84],"route_cache":body[85],
                "discovery_seconds":body[86],"radius":body[87]},
            "heap":{"total_bytes":heap_total,"free_bytes":heap_free,"free_error_count":heap_errors,
                "accounting_consistent":heap_free<=heap_total}}
    snap=g5.decode(raw[16:-2])
    return {"version":1,"status":0,"tick_period_us":period,"reboot_identity":None,"snapshot":snap}

def elapsed_ms(begin, end, period_us, *, same_boot):
    if same_boot is not True: raise ValueError("BOOT_BOUNDARY_UNKNOWN")
    delta=(end-begin)&0xffffffff
    if delta>=0x80000000: raise ValueError("AMBIGUOUS_WRAP_OR_REGRESSION")
    if period_us<=0: raise ValueError("UNKNOWN_CLOCK_PERIOD")
    return delta*period_us/1000

def timing_report(envelope, *, same_boot):
    snap=envelope.get("snapshot",{}); ev=snap.get("events",[])
    out={"host_reception":"UNKNOWN", "radio_health":"UNKNOWN", "physical_tx":"UNKNOWN"}
    if any(e["kind"]=="UART_TX_FINISHED" for e in ev): out["physical_tx"]="UART_IDLE_OBSERVED"
    if snap.get("isr_dropped",0):
        out["stage_durations_ms"]={}; out["timing_evidence"]="INCOMPLETE_WRITER_CONTENTION"
        return out
    # Never span boot records or incomplete history. A latest eight-event
    # snapshot can have evicted the beginning of a stage: duration stays None.
    starts={}; durations={}
    for e in ev:
        if e["kind"]=="BOOT_ENTER": starts.clear()
        k=e["kind"]
        if k in ("MT_RX","ZDO_INIT_ENTER"): starts[k]=e["tick"]
        pairs={"SRSP_SEND_ATTEMPTED":"MT_RX","ZDO_INIT_EXIT":"ZDO_INIT_ENTER"}
        if k in pairs and pairs[k] in starts:
            durations[pairs[k]+"_to_"+k]=elapsed_ms(starts.pop(pairs[k]),e["tick"],envelope["tick_period_us"],same_boot=same_boot)
    out["stage_durations_ms"]=durations
    return out

def selftest():
    assert elapsed_ms(100,247,1000,same_boot=True)==147
    assert elapsed_ms(100,1645,1000,same_boot=True)==1545
    assert elapsed_ms(0xfffffff0,24,1000,same_boot=True)==40
    assert elapsed_ms(0,40000,1000,same_boot=True)==40000
    for a,b,known in ((10,9,True),(0,0x80000000,True),(9,0,False),(0,147,None)):
        try:elapsed_ms(a,b,1000,same_boot=known)
        except ValueError:pass
        else:raise AssertionError("BAD_CLOCK_COMPARISON")
    assert g5.classify({"host_timeout_40s":True,"uart_fifo_loaded":True})=="UNKNOWN_TIMEOUT_NOT_CRASH"
    assert g5.classify({"queue_high_water":158,"queue_current":0})=="NOT_STUCK_HIGHWATER_ONLY"
    assert g5.classify({"diag_rtt_ms":147})==g5.classify({"diag_rtt_ms":1545})=="UNKNOWN_RTT_ONLY"
    env={"tick_period_us":1000,"snapshot":{"events":[{"kind":"MT_RX","tick":0xffffff00},
        {"kind":"SRSP_SEND_ATTEMPTED","tick":0x10},{"kind":"UART_FIFO_LOADED","tick":0x20}]}}
    r=timing_report(env,same_boot=True)
    assert r["stage_durations_ms"]["MT_RX_to_SRSP_SEND_ATTEMPTED"]==272
    assert r["physical_tx"]=="UNKNOWN" and r["host_reception"]=="UNKNOWN"
    env["snapshot"]["isr_dropped"]=1
    assert timing_report(env,same_boot=True)["stage_durations_ms"]=={}
    env["snapshot"]={"events":[{"kind":"UART_ACCEPTED","tick":1},{"kind":"UART_ACCEPTED","tick":2},
        {"kind":"UART_TX_FINISHED","tick":3}]}
    assert timing_report(env,same_boot=True)["stage_durations_ms"]=={}
    print("PASS 147ms/1545ms/40s/wrap/reboot/unknown timing regressions")

if __name__=="__main__":
    if "--selftest" in sys.argv:selftest()
    else: print(decode(bytes.fromhex(sys.argv[1])))
