#!/usr/bin/env python3
"""Host decoder + offline classifier for the P7 G5 flight recorder.
Never infers host reception from UART acceptance, a crash from a host
timeout, or stuck transport from a high-water mark or a single sample.
Missing evidence is not observed-false. UNKNOWN is first-class."""
from __future__ import annotations
import struct, sys

MAGIC=b"P7D1"; SCHEMA=1; HDR=28; EV=12; MAX_EVENTS=8; RING=64
KINDS={1:"BOOT_ENTER",2:"NV_READ_BEGIN",3:"NV_RESTORED",4:"NV_NEW",5:"NV_AMBIGUOUS",
 6:"ZDO_INIT_ENTER",7:"ZDO_INIT_EXIT",8:"DEV_STATE",9:"MT_RX",10:"SRSP_QUEUED",
 11:"UART_ACCEPTED",12:"UART_TX_FINISHED",13:"UART_REJECTED",14:"QUEUE_DEPTH",15:"FAULT",16:"RESET_SOURCE",
 17:"ZDO_DISPATCH",18:"NPI_Q_ACCEPT",19:"NPI_Q_REJECT",20:"PARSE_ERR",21:"FCS_ERR",22:"OVERFLOW",23:"UART_FIFO_LOADED"}
NV_NAMES={0:"unknown",1:"restored",2:"new",3:"ambiguous"}

def crc16(data: bytes) -> int:
    crc=0xFFFF
    for b in data:
        crc ^= b<<8
        for _ in range(8):
            crc=((crc<<1)^0x1021)&0xFFFF if crc&0x8000 else (crc<<1)&0xFFFF
    return crc

def encode(events, boot_gen=1, dropped=0, nv_state=0, reset_known=0, reset_source=0, total=None, isr_dropped=0) -> bytes:
    ev=list(events)[-MAX_EVENTS:]
    if total is None: total=ev[-1][0] if ev else 0
    out=bytearray(MAGIC); out+=bytes([SCHEMA,nv_state,len(ev),reset_known])
    out+=struct.pack("<II",boot_gen,dropped)
    out+=bytes([reset_source if reset_known else 0,reset_known,0,0])
    out+=struct.pack("<II",total,isr_dropped)
    for seq,tick,kind,arg in ev: out+=struct.pack("<IIHH",seq,tick,kind,arg)
    out+=struct.pack("<H",crc16(bytes(out))); return bytes(out)

def decode(raw: bytes) -> dict:
    if len(raw)<HDR+2 or raw[:4]!=MAGIC: raise ValueError("BAD_MAGIC_OR_SHORT")
    schema,nv_state,n,reset_known=raw[4],raw[5],raw[6],raw[7]
    if schema!=SCHEMA: raise ValueError("VERSION_MISMATCH")
    if nv_state not in NV_NAMES: raise ValueError("NV_STATE_OUT_OF_RANGE")
    if reset_known not in (0,1): raise ValueError("RESET_KNOWN_OUT_OF_RANGE")
    if n==0: raise ValueError("EMPTY_SNAPSHOT")
    if n>MAX_EVENTS: raise ValueError("EVENT_COUNT_OVERSIZED")
    if len(raw)!=HDR+n*EV+2: raise ValueError("LENGTH_MISMATCH")
    body,got=raw[:-2],struct.unpack("<H",raw[-2:])[0]
    if crc16(body)!=got: raise ValueError("CRC_MISMATCH")
    reset_source=raw[16]
    if raw[17] not in (0,1) or raw[17]!=reset_known: raise ValueError("RESET_KNOWN_INCONSISTENT")
    if raw[18]!=0 or raw[19]!=0: raise ValueError("RESERVED_NONZERO")
    if not reset_known and reset_source!=0: raise ValueError("RESET_SOURCE_UNMASKED")
    boot_gen,dropped=struct.unpack_from("<II",raw,8)
    total,isr_dropped=struct.unpack_from("<II",raw,20)
    if boot_gen==0: raise ValueError("BOOT_GENERATION_ZERO")
    events=[]
    for i in range(n):
        seq,tick,kind,arg=struct.unpack_from("<IIHH",raw,HDR+i*EV)
        if kind not in KINDS: raise ValueError("UNKNOWN_EVENT_KIND")
        if seq==0: raise ValueError("SEQ_ZERO_INVALID")
        events.append({"seq":seq,"tick":tick,"kind":KINDS[kind],"arg":arg})
    for a,b in zip(events,events[1:]):
        want=1 if a["seq"]==0xFFFFFFFF else a["seq"]+1  # contiguous records, seq 0 skipped
        if b["seq"]!=want: raise ValueError("SEQ_NOT_CONTIGUOUS")
        if b["tick"]<a["tick"]:
            boot_reset=b["kind"]=="BOOT_ENTER"
            tick_wrap=a["tick"]>0xFF000000 and b["tick"]<0x01000000
            if not (boot_reset or tick_wrap): raise ValueError("TICK_REGRESSION")
    if events and not any(e["seq"]==0xFFFFFFFF for e in events):
        # Unconditional (non-wrap window): snapshot always ends at the last
        # record, so total == last seq and dropped == evictions beyond ring.
        if total!=events[-1]["seq"]: raise ValueError("TOTAL_MISMATCH")
        if dropped!=max(0,total-RING): raise ValueError("DROPPED_MISMATCH")
    # Only the LATEST RESET_SOURCE event belongs to the current boot and
    # must match the header; earlier ones are preserved pre-reset history
    # (their boot may have had a different/unknown reset source).
    rs_events=[e for e in events if e["kind"]=="RESET_SOURCE"]
    if rs_events:
        e=rs_events[-1]
        if reset_known and e["arg"]!=reset_source: raise ValueError("RESET_SOURCE_EVENT_MISMATCH")
        if not reset_known and e["arg"]!=0xFFFF: raise ValueError("RESET_SOURCE_EVENT_UNMASKED")
    return {"schema":schema,"nv_state":nv_state,"reset_known":bool(reset_known),
            "reset_source":reset_source if reset_known else None,
            "boot_generation":boot_gen,"dropped":dropped,"total":total,"isr_dropped":isr_dropped,"events":events}

def _snap(obs):
    s=obs.get("snapshot")
    return s if isinstance(s,dict) else None

def classify(obs: dict) -> str:
    snap=_snap(obs)
    if obs.get("stale_generation"): return "UNKNOWN_STALE_GENERATION"
    nv=obs.get("nv_state")
    if snap is not None and nv is None: nv=NV_NAMES.get(snap.get("nv_state"))
    if nv=="ambiguous" or nv==3: return "UNKNOWN_NV_AMBIGUOUS"
    if obs.get("host_timeout_40s"):
        if obs.get("srsp_queued") is True and obs.get("uart_tx_finished") is False:
            return "SRSP_QUEUED_TX_NOT_FINISHED"
        if obs.get("uart_tx_finished") is True and obs.get("host_received") is not True:
            return "UNKNOWN_HOST_RECEPTION_UNPROVEN"
        return "UNKNOWN_TIMEOUT_NOT_CRASH"
    hw,cur=obs.get("queue_high_water"),obs.get("queue_current")
    if hw is not None and cur is not None and hw>=158 and cur==0:
        return "NOT_STUCK_HIGHWATER_ONLY"
    samples=obs.get("queue_current_samples")
    persistent=isinstance(samples,list) and len(samples)>=2 and all(type(x) is int and x>0 for x in samples)
    if persistent and obs.get("uart_tx_finished") is False:
        return "POSSIBLE_TX_STALL_DEPTH_PERSISTS"
    if obs.get("diag_rtt_ms") is not None and not obs.get("srsp_queued") and cur is None and not persistent:
        return "UNKNOWN_RTT_ONLY"
    if obs.get("uart_accepted") and obs.get("host_received") is not True:
        return "UNKNOWN_HOST_RECEPTION_UNPROVEN"
    return "UNKNOWN_INSUFFICIENT_EVIDENCE"

GOLDEN_EVENTS=[(1,0,1,0),(2,4,16,0xFFFF),(3,9,3,0),(4,12,10,0)]
# Independent literal oracle (byte layout per MT_SYS_ENDPOINT_SPEC.md);
# the C host test emits the same snapshot and CI cross-decodes it.
GOLDEN_HEX="5037443101010400070000000000000000000000040000000000000001000000000000000100000002000000040000001000ffff030000000900000003000000040000000c0000000a0000003319"

def must(v,msg):
    if not v: raise AssertionError(msg)

def selftest() -> None:
    raw=bytes.fromhex(GOLDEN_HEX); d=decode(raw)
    must(d["boot_generation"]==7 and len(d["events"])==4,"GOLDEN_DECODE")
    must(encode(GOLDEN_EVENTS,boot_gen=7,nv_state=1).hex()==GOLDEN_HEX,"GOLDEN_STABLE")
    must(classify({"snapshot":d})=="UNKNOWN_INSUFFICIENT_EVIDENCE","SNAPSHOT_CLASSIFY")
    amb=decode(encode([(1,0,1,0)],nv_state=3)); must(classify({"snapshot":amb})=="UNKNOWN_NV_AMBIGUOUS","SNAPSHOT_NV_AMBIG")
    wrap=decode(encode([(4294967295,0,1,0),(1,1,1,0)])); must(wrap["events"][1]["seq"]==1,"SEQ_WRAP")
    ext=decode(encode([(1,0,17,0),(2,1,18,0),(3,2,21,0)])); must([e["kind"] for e in ext["events"]]==["ZDO_DISPATCH","NPI_Q_ACCEPT","FCS_ERR"],"EXTENDED_KINDS")
    for bad in (b"",b"P7D1",raw[:-1],raw+b"\x00",raw[:4]+b"\x02"+raw[5:],
                raw[:6]+b"\x09"+raw[7:],raw[:-2]+b"\x00\x00",
                encode([(1,0,1,0)],nv_state=99),encode([(0,0,1,0)])):
        try: decode(bad)
        except ValueError: continue
        raise AssertionError("MALFORMED_ACCEPTED")
    cases=[
      ({"host_timeout_40s":True},"UNKNOWN_TIMEOUT_NOT_CRASH"),
      ({"host_timeout_40s":True,"srsp_queued":True},"UNKNOWN_TIMEOUT_NOT_CRASH"),
      ({"host_timeout_40s":True,"srsp_queued":True,"uart_tx_finished":False},"SRSP_QUEUED_TX_NOT_FINISHED"),
      ({"host_timeout_40s":True,"srsp_queued":True,"uart_fifo_loaded":True},"UNKNOWN_TIMEOUT_NOT_CRASH"),
      ({"uart_fifo_loaded":True},"UNKNOWN_INSUFFICIENT_EVIDENCE"),
      ({"queue_high_water":158,"queue_current":0},"NOT_STUCK_HIGHWATER_ONLY"),
      ({"queue_high_water":158,"queue_current":3,"uart_tx_finished":False,"diag_rtt_ms":1},"UNKNOWN_INSUFFICIENT_EVIDENCE"),
      ({"diag_rtt_ms":1545},"UNKNOWN_RTT_ONLY"),
      ({"diag_rtt_ms":147},"UNKNOWN_RTT_ONLY"),
      ({"uart_accepted":True},"UNKNOWN_HOST_RECEPTION_UNPROVEN"),
      ({"uart_accepted":True,"uart_tx_finished":True},"UNKNOWN_HOST_RECEPTION_UNPROVEN"),
      ({"nv_state":"ambiguous"},"UNKNOWN_NV_AMBIGUOUS"),
      ({"stale_generation":True},"UNKNOWN_STALE_GENERATION"),
      ({},"UNKNOWN_INSUFFICIENT_EVIDENCE"),
      ({"queue_current_samples":[3,3],"uart_tx_finished":False},"POSSIBLE_TX_STALL_DEPTH_PERSISTS"),
    ]
    for obs,want in cases: must(classify(obs)==want,f"CLASSIFY {obs} -> {classify(obs)} != {want}")
    print(f"PASS P7 crashdiag decoder; golden={GOLDEN_HEX}; {len(cases)} classify cases")

if __name__=="__main__":
    if "--selftest" in sys.argv: selftest()
    elif len(sys.argv)>1: print(decode(bytes.fromhex(sys.argv[1])))
    else: print("usage: --selftest | <hex>")
