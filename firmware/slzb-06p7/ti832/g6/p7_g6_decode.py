"""Versioned G6 envelope and modulo clock calculations. No hardware access."""
import struct, sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"g5"))
import p7_diag_decode as g5

def decode(raw):
    if len(raw)<16 or raw[:4]!=b"P7G6" or raw[4]!=1: raise ValueError("BAD_G6_HEADER")
    if raw[6]!=1 or raw[7]!=0 or raw[12:16]!=bytes(4): raise ValueError("UNSUPPORTED_CLOCK_EPOCH")
    period=struct.unpack_from("<I",raw,8)[0]
    if not period: raise ValueError("UNKNOWN_CLOCK_PERIOD")
    if raw[5]:
        if raw[5]>5 or len(raw)!=16: raise ValueError("BAD_G6_STATUS")
        return {"status":raw[5],"tick_period_us":period,"reboot_identity":None}
    snap=g5.decode(raw[16:])
    return {"status":0,"tick_period_us":period,"reboot_identity":None,"snapshot":snap}

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
    # Never span boot records or incomplete history. A latest eight-event
    # snapshot can have evicted the beginning of a stage: duration stays None.
    starts={}; durations={}
    for e in ev:
        if e["kind"]=="BOOT_ENTER": starts.clear()
        k=e["kind"]
        if k in ("MT_RX","ZDO_INIT_ENTER","UART_ACCEPTED"): starts[k]=e["tick"]
        pairs={"SRSP_QUEUED":"MT_RX","ZDO_INIT_EXIT":"ZDO_INIT_ENTER","UART_TX_FINISHED":"UART_ACCEPTED"}
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
        {"kind":"SRSP_QUEUED","tick":0x10},{"kind":"UART_FIFO_LOADED","tick":0x20}]}}
    r=timing_report(env,same_boot=True)
    assert r["stage_durations_ms"]["MT_RX_to_SRSP_QUEUED"]==272
    assert r["physical_tx"]=="UNKNOWN" and r["host_reception"]=="UNKNOWN"
    print("PASS 147ms/1545ms/40s/wrap/reboot/unknown timing regressions")

if __name__=="__main__":
    if "--selftest" in sys.argv:selftest()
    else: print(decode(bytes.fromhex(sys.argv[1])))
