#!/usr/bin/env python3
"""Host decoder + offline classifier for the P7 G5 flight recorder.
Bounded, deterministic, allocation-light. Never infers host reception from
UART acceptance, a host timeout from a crash, or stuck transport from a
high-water mark. UNKNOWN is a first-class conclusion."""
from __future__ import annotations
import struct, sys

MAGIC=b"P7D1"; SCHEMA=1; HDR=16; EV=12; MAX_EVENTS=8
KINDS={1:"BOOT_ENTER",2:"NV_READ_BEGIN",3:"NV_RESTORED",4:"NV_NEW",5:"NV_AMBIGUOUS",
 6:"ZDO_INIT_ENTER",7:"ZDO_INIT_EXIT",8:"DEV_STATE",9:"MT_RX",10:"SRSP_QUEUED",
 11:"UART_ACCEPTED",12:"UART_TX_FINISHED",13:"UART_REJECTED",14:"QUEUE_DEPTH",15:"FAULT",16:"RESET_SOURCE"}

def crc16(data: bytes) -> int:
    crc=0xFFFF
    for b in data:
        crc ^= b<<8
        for _ in range(8):
            crc=((crc<<1)^0x1021)&0xFFFF if crc&0x8000 else (crc<<1)&0xFFFF
    return crc

def encode(events, boot_gen=1, dropped=0, nv_state=0, reset_known=0) -> bytes:
    ev=list(events)[-MAX_EVENTS:]
    out=bytearray(MAGIC); out+=bytes([SCHEMA,nv_state,len(ev),reset_known])
    out+=struct.pack("<II",boot_gen,dropped)
    for seq,tick,kind,arg in ev: out+=struct.pack("<IIHH",seq,tick,kind,arg)
    out+=struct.pack("<H",crc16(bytes(out))); return bytes(out)

def decode(raw: bytes) -> dict:
    if len(raw)<HDR+2 or raw[:4]!=MAGIC: raise ValueError("BAD_MAGIC_OR_SHORT")
    schema,nv_state,n,reset_known=raw[4],raw[5],raw[6],raw[7]
    if schema!=SCHEMA: raise ValueError("VERSION_MISMATCH")
    if n>MAX_EVENTS: raise ValueError("EVENT_COUNT_OVERSIZED")
    if len(raw)!=HDR+n*EV+2: raise ValueError("LENGTH_MISMATCH")
    body,got=raw[:-2],struct.unpack("<H",raw[-2:])[0]
    if crc16(body)!=got: raise ValueError("CRC_MISMATCH")
    boot_gen,dropped=struct.unpack_from("<II",raw,8)
    events=[]
    for i in range(n):
        seq,tick,kind,arg=struct.unpack_from("<IIHH",raw,HDR+i*EV)
        if kind not in KINDS: raise ValueError("UNKNOWN_EVENT_KIND")
        events.append({"seq":seq,"tick":tick,"kind":KINDS[kind],"arg":arg})
    if any(events[i]["seq"]>=events[i+1]["seq"] for i in range(len(events)-1)):
        raise ValueError("SEQ_NOT_MONOTONIC")
    return {"schema":schema,"nv_state":nv_state,"reset_known":bool(reset_known),
            "boot_generation":boot_gen,"dropped":dropped,"events":events}

def classify(obs: dict) -> str:
    """obs keys (all optional): host_timeout_40s, srsp_queued, uart_accepted,
    uart_tx_finished, host_received, queue_high_water, queue_current,
    diag_rtt_ms, nv_state, snapshot (decoded dict), stale_generation."""
    if obs.get("stale_generation"): return "UNKNOWN_STALE_GENERATION"
    if obs.get("nv_state")=="ambiguous": return "UNKNOWN_NV_AMBIGUOUS"
    if obs.get("host_timeout_40s"):
        # 40s ZDO SRSP timeout alone proves only: no matching SRSP received.
        if obs.get("srsp_queued") and not obs.get("uart_tx_finished"):
            return "SRSP_QUEUED_TX_NOT_FINISHED"
        if obs.get("uart_tx_finished") and not obs.get("host_received"):
            return "UNKNOWN_HOST_RECEPTION_UNPROVEN"  # wire-done != received
        if not obs.get("srsp_queued"): return "UNKNOWN_TIMEOUT_NOT_CRASH"
        return "UNKNOWN_TIMEOUT_NOT_CRASH"
    hw,cur=obs.get("queue_high_water"),obs.get("queue_current")
    if hw is not None and cur is not None:
        if hw>=158 and cur==0: return "NOT_STUCK_HIGHWATER_ONLY"
        if cur>0 and obs.get("uart_tx_finished") is False and obs.get("diag_rtt_ms",0)>0:
            return "POSSIBLE_TX_STALL_DEPTH_PERSISTS"  # requires persistence, not RTT alone
    if obs.get("diag_rtt_ms") is not None and not obs.get("srsp_queued"):
        return "UNKNOWN_RTT_ONLY"  # 147-1545ms delayed diag != stuck transport
    if obs.get("uart_accepted") and not obs.get("host_received"):
        return "UNKNOWN_HOST_RECEPTION_UNPROVEN"
    return "UNKNOWN_INSUFFICIENT_EVIDENCE"

GOLDEN_EVENTS=[(1,0,1,0),(2,4,16,0xFFFF),(3,9,3,0),(4,12,10,0)]
GOLDEN_HEX=encode(GOLDEN_EVENTS,boot_gen=7,dropped=0,nv_state=1,reset_known=0).hex()

def must(v,msg):
    if not v: raise AssertionError(msg)

def selftest() -> None:
    raw=bytes.fromhex(GOLDEN_HEX); d=decode(raw)
    must(d["boot_generation"]==7 and len(d["events"])==4,"GOLDEN_DECODE")
    must(encode(GOLDEN_EVENTS,boot_gen=7,nv_state=1).hex()==GOLDEN_HEX,"GOLDEN_STABLE")
    for bad in (b"",b"P7D1",raw[:-1],raw+b"\x00",raw[:4]+b"\x02"+raw[5:],
                raw[:6]+b"\x09"+raw[7:],raw[:-2]+b"\x00\x00"):
        try: decode(bad)
        except ValueError: continue
        raise AssertionError("MALFORMED_ACCEPTED")
    cases=[
      ({"host_timeout_40s":True},"UNKNOWN_TIMEOUT_NOT_CRASH"),
      ({"host_timeout_40s":True,"srsp_queued":True},"SRSP_QUEUED_TX_NOT_FINISHED"),
      ({"queue_high_water":158,"queue_current":0},"NOT_STUCK_HIGHWATER_ONLY"),
      ({"diag_rtt_ms":1545},"UNKNOWN_RTT_ONLY"),
      ({"diag_rtt_ms":147},"UNKNOWN_RTT_ONLY"),
      ({"uart_accepted":True},"UNKNOWN_HOST_RECEPTION_UNPROVEN"),
      ({"uart_accepted":True,"uart_tx_finished":True},"UNKNOWN_HOST_RECEPTION_UNPROVEN"),
      ({"nv_state":"ambiguous"},"UNKNOWN_NV_AMBIGUOUS"),
      ({"stale_generation":True},"UNKNOWN_STALE_GENERATION"),
      ({},"UNKNOWN_INSUFFICIENT_EVIDENCE"),
      ({"queue_high_water":158,"queue_current":3,"uart_tx_finished":False,"diag_rtt_ms":900},
       "POSSIBLE_TX_STALL_DEPTH_PERSISTS"),
    ]
    for obs,want in cases: must(classify(obs)==want,f"CLASSIFY {obs} -> {classify(obs)} != {want}")
    print(f"PASS P7 crashdiag decoder; golden={GOLDEN_HEX}; {len(cases)} classify cases")

if __name__=="__main__":
    if "--selftest" in sys.argv: selftest()
    elif len(sys.argv)>1: print(decode(bytes.fromhex(sys.argv[1])))
    else: print("usage: --selftest | <hex>")
