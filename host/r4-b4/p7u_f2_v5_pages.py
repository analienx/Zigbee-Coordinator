"""Strict, read-only, offline P7U SYS F2 v5 two-page decoder.

Only sanitized scalar records escape; no nonce/boot identity/raw frames are
written. A page without its matching partner is NOT an incident diagnosis.
No serial port, sockets, MQTT, radio, ESP action or subprocesses.
"""
from __future__ import annotations
from dataclasses import dataclass

PAGE_BYTES=160
RING_COUNT=16
STAGES={1:"NPI_REQUEST",2:"NPI_HANDOFF",3:"MT_ENTER",
        4:"MT_EXIT",5:"NPI_QUEUED",6:"TL_SUBMIT_ATTEMPT",
        7:"TL_ACCEPTED",8:"TL_REJECTED",9:"RESERVE_EXHAUSTED"}
FIELD_OFFSETS={
  "npiWakes":32,"npiLastTick":36,"mtEntered":40,
  "mtLastEnteredTick":44,"mtExited":48,"mtLastExitedTick":52,
  "eventTotal":56,"reserveUsed":60,"reserveExhausted":64,
  "reserveReleaseFault":68,"reserveActive":72,
  "allSrspProduced":76,"allSrspAllocationFailed":80,
  "allSrspFramingFailed":84,"allSrspTlRejected":88,
  "uartTxCallbackOk":92,"uartTxCallbackError":96,
  "uartRxBytes":100,"validityFlags":104,"eventCount":108,
  "clockTickPeriodUs":112,
  "npiRequests":116,"uartWriteAccepted":120,
  "uartWriteRejected":124,"uartStateFlags":128,
  "firstUartFaultKind":132,"firstUartFaultTick":136,
  "b1FirstFailure":140,
}

class FlightEvidenceRejected(ValueError):
    pass

def _u32(raw:bytes,off:int)->int:
    return int.from_bytes(raw[off:off+4],"little")

def _header(raw:bytes,page:int,nonce:bytes):
    if type(raw) is not bytes or len(raw)!=PAGE_BYTES or type(nonce) is not bytes or len(nonce)!=8:
        raise FlightEvidenceRejected("V5_LENGTH_OR_TYPE")
    if raw[:4]!=b"R4D5" or raw[4]!=5 or raw[5]!=page or raw[6:8]!=b"\xa0\x00":
        raise FlightEvidenceRejected("V5_MAGIC_VERSION_OR_PAGE")
    if raw[8:16]!=nonce:
        raise FlightEvidenceRejected("V5_NONCE_NOT_MATCHED")
    seq,tick=_u32(raw,24),_u32(raw,28)
    if seq==0:
        raise FlightEvidenceRejected("V5_ZERO_SEQUENCE")
    return seq,tick,raw[16:24]

def decode_pair(page1:bytes,page2:bytes,nonce:bytes)->dict:
    a,tick,boot=_header(page1,1,nonce)
    b,tick2,boot2=_header(page2,2,nonce)
    if a!=b or tick!=tick2 or boot!=boot2:
        raise FlightEvidenceRejected("V5_CROSS_PAGE_MISMATCH")
    # Page1 144..159 contains two immutable 8-byte anomaly records
    # only when bit2 is asserted. A zero bit requires all bytes zero.
    counters={name:_u32(page1,off) for name,off in FIELD_OFFSETS.items()}
    f=counters["validityFlags"]
    if f & ~7 or (f&2)!=2 or not 0<counters["clockTickPeriodUs"]<=100000:
        raise FlightEvidenceRejected("V5_FLAGS_OR_TICK")
    if (bool(f&1))!=(boot!=bytes(8)):
        raise FlightEvidenceRejected("V5_BOOT_VALIDITY")
    if (counters["firstUartFaultKind"]>5 or
        counters["b1FirstFailure"]>255 or
        counters["uartStateFlags"] & 0xfff0 or
        (counters["firstUartFaultKind"]==0 and counters["firstUartFaultTick"]!=0)):
        raise FlightEvidenceRejected("V5_UART_FAULT_PROVENANCE")
    if counters["reserveActive"]>3 or counters["eventCount"]>16 or (
        counters["mtExited"]>counters["mtEntered"]):
        raise FlightEvidenceRejected("V5_COUNTER_CONSTRAINT")
    if counters["eventCount"]!=min(counters["eventTotal"],16):
        raise FlightEvidenceRejected("V5_EVENT_COUNT")
    if (counters["reserveUsed"]<counters["reserveActive"] or
        counters["reserveReleaseFault"]>counters["reserveUsed"]):
        raise FlightEvidenceRejected("V5_RESERVE_CONSTRAINT")
    def decode_event(chunk:bytes, allow_empty:bool=False)->dict|None:
        if allow_empty and chunk == bytes(8):
            return None
        stamp=_u32(chunk,0)
        cmd=int.from_bytes(chunk[4:6],"little")
        stage,result=chunk[6],chunk[7]
        if stage not in STAGES or (stage==8 and result==0):
            raise FlightEvidenceRejected("V5_BAD_EVENT")
        return {"tick":stamp,"stage":STAGES[stage],"result":result,
                "mtSubsystem":("AF" if ((cmd>>8)&31)==4 else
                               "SYS" if ((cmd>>8)&31)==1 else
                               "ZDO" if ((cmd>>8)&31)==5 else "OTHER")}
    frozen=bool(f&4)
    if not frozen and any(page1[144:160]):
        raise FlightEvidenceRejected("V5_ANOMALY_WITHOUT_VALIDITY")
    prev=decode_event(page1[144:152],True) if frozen else None
    first=decode_event(page1[152:160]) if frozen else None
    if frozen and (first is None or first["stage"] not in (
            "TL_REJECTED","RESERVE_EXHAUSTED") or first["result"]==0):
        raise FlightEvidenceRejected("V5_INVALID_FROZEN_ANOMALY")
    entries=[]
    for i in range(RING_COUNT):
        off=32+i*8
        chunk=page2[off:off+8]
        if i>=counters["eventCount"]:
            if any(chunk):
                raise FlightEvidenceRejected("V5_UNUSED_RING_DIRTY")
            continue
        # Deliberately do not export raw command identifiers.
        entries.append(decode_event(chunk))
    if counters["eventCount"]:
        # UInt32 ticks are modular. A recent event just before wrap is
        # valid even when its raw value exceeds snapshotTick after wrap.
        # Half-range rejects a recent-looking future event, but events
        # older than half a wrap are ambiguous and cannot be certified.
        delta=(tick-entries[-1]["tick"]) & 0xffffffff
        if delta >= 0x80000000:
            raise FlightEvidenceRejected("V5_TICK_HALF_RANGE_UNQUALIFIED")
    if counters["mtEntered"]!=counters["mtExited"]:
        localization="MT_DISPATCH_IN_FLIGHT_AT_LAST_GOOD_SAMPLE"
    elif counters["allSrspAllocationFailed"]>0:
        localization="OUTBOUND_ALLOCATION_FAILURE_OBSERVED"
    elif counters["reserveExhausted"]>0:
        localization="RESERVE_EXHAUSTION_OBSERVED"
    elif counters["allSrspTlRejected"]>0:
        localization="UART_SUBMISSION_REJECTION_OBSERVED"
    else:
        localization="NO_DIRECT_FAILURE_PROVEN"
    # Snapshot is historical, not a hang detector or proof of current state.
    return {
       "schema":"p7u-f2-v5-sanitized-pair-v1",
       "sequence":a,"radioEpochHardwareVerified":False,
       "sampleTick":tick,"tickPeriodUs":counters.pop("clockTickPeriodUs"),
       "counters":{k:v for k,v in counters.items() if k!="validityFlags"},
       "events":entries,"firstAnomaly":first,"preAnomaly":prev,
       "localization":localization,
       "hardwareESPBridgeObserved":False,
       "heapFreeBytesKnown":False,"stackMarginKnown":False,
       "currentHangProven":False,"radioBootIdentityExported":False,
    }
