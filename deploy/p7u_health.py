#!/usr/bin/env python3
"""Read-only P7 diagnostics through an existing connection owner, or saved frames.

This module opens no serial port/socket and performs no recovery action. The
owner's exchange callback must serialize MT SREQs, match their SRSPs, and remove
late replies after a timeout before establishing a new connection generation.
"""
from __future__ import annotations
import argparse
import asyncio
import json
import math
import sys
import time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"firmware/slzb-06p7/ti832/g6"))
import p7_g6_decode as decoder

SCHEMA="p7u-health-observation/v1"


def request_frame(version=2):
    if version not in (1,2): raise ValueError("UNSUPPORTED_REQUEST_VERSION")
    body=bytes((2,0x21,0xF0,version,0))
    return b"\xfe"+body+bytes((_xor(body),))


def _xor(data):
    value=0
    for byte in data: value^=byte
    return value


def decode_frame(raw):
    """Exactly one complete SYS/F0 SRSP; no resync or arbitrary packet capture."""
    if not isinstance(raw,bytes) or len(raw)<5 or len(raw)>149 or raw[0]!=0xFE:
        raise ValueError("BAD_MT_FRAME")
    if len(raw)!=raw[1]+5: raise ValueError("BAD_MT_LENGTH")
    if raw[2:4]!=b"\x61\xf0": raise ValueError("UNMATCHED_MT_SRSP")
    if _xor(raw[1:])!=0: raise ValueError("BAD_MT_FCS")
    return decoder.decode(raw[4:-1])


class DiagnosticClient:
    """One bounded probe at a time, using the host's established MT owner.

    A timeout or malformed/unmatched response poisons this connection generation:
    there is no transaction nonce in SYS/F0, so an old late SRSP must never be
    accepted as the next probe. The owner must drain/invalidate its matcher and
    establish a new session boundary before constructing another client.
    """
    def __init__(self,exchange,*,session):
        if not callable(exchange): raise ValueError("OWNER_EXCHANGE_REQUIRED")
        if not isinstance(session,str) or not 1<=len(session)<=128:
            raise ValueError("OPAQUE_SESSION_REQUIRED")
        self.exchange=exchange
        self.session=session
        self.pending=False
        self.poisoned=False

    async def probe(self,*,version=2,timeout_seconds=2):
        if not isinstance(timeout_seconds,(int,float)) or isinstance(timeout_seconds,bool) or not math.isfinite(timeout_seconds) or not 0<timeout_seconds<=10:
            raise ValueError("PROBE_TIMEOUT_OUT_OF_RANGE")
        if self.pending: raise RuntimeError("PROBE_ALREADY_PENDING")
        if self.poisoned: raise RuntimeError("OWNER_SESSION_BOUNDARY_REQUIRED")
        frame=request_frame(version)
        self.pending=True
        begin=time.monotonic()
        result={"schema":SCHEMA,"session":self.session,"request_version":version,
            "host_time":begin,"reboot_identity_known":False}
        try:
            raw=await asyncio.wait_for(self.exchange(frame),timeout_seconds)
            decoded=decode_frame(raw)
            if decoded["version"]!=version: raise ValueError("UNMATCHED_DIAGNOSTIC_VERSION")
            result.update(result="response",diagnostic=decoded)
        except asyncio.TimeoutError:
            self.poisoned=True
            result.update(result="timeout",requires_session_boundary=True)
        except (ValueError,TypeError):
            self.poisoned=True
            result.update(result="invalid_response",requires_session_boundary=True)
        except BaseException:
            # Cancellation or owner failure can also leave a late SRSP queued.
            self.poisoned=True
            raise
        finally:
            self.pending=False
        result["elapsed_ms"]=(time.monotonic()-begin)*1000
        return result


def _count(value):
    return type(value) is int and 0<=value<=0xFFFFFFFF


def assess(samples,*,network=None,same_boot=False):
    """Assess saved observations. Diagnostics alone never prove mesh health.

    same_boot must come from independent boot/session evidence. A session token
    is not a firmware reboot identity; the current firmware has no unique one.
    """
    if not isinstance(samples,list) or not 1<=len(samples)<=256:
        raise ValueError("SAMPLE_COUNT_OUT_OF_RANGE")
    if type(same_boot) is not bool: raise ValueError("BAD_SAME_BOOT_ASSERTION")
    sessions=set()
    previous_time=None
    valid=[]
    results=[]
    for sample in samples:
        if not isinstance(sample,dict) or sample.get("schema")!=SCHEMA:
            raise ValueError("BAD_OBSERVATION_SCHEMA")
        session=sample.get("session")
        if not isinstance(session,str) or not 1<=len(session)<=128: raise ValueError("BAD_SESSION")
        sessions.add(session)
        at=sample.get("host_time")
        if isinstance(at,bool) or not isinstance(at,(int,float)) or not math.isfinite(at) or at<0:
            raise ValueError("BAD_HOST_TIME")
        if previous_time is not None and at<previous_time: raise ValueError("HOST_TIME_REGRESSION")
        previous_time=at
        result=sample.get("result")
        if result not in ("response","timeout","invalid_response"): raise ValueError("BAD_PROBE_RESULT")
        results.append(result)
        if result=="response":
            diag=sample.get("diagnostic")
            if not isinstance(diag,dict) or diag.get("version") not in (1,2) or type(diag.get("status")) is not int or not 0<=diag["status"]<=5:
                raise ValueError("BAD_DIAGNOSTIC_RESPONSE")
            if diag["version"]==2 and diag["status"]==0:
                counters=diag.get("counters")
                if not isinstance(counters,dict) or set(counters)!=set(decoder.HEALTH_COUNTERS) or not all(_count(v) for v in counters.values()):
                    raise ValueError("BAD_HEALTH_COUNTERS")
                if not _count(diag.get("sample_tick")) or not _count(diag.get("writer_contention_dropped")):
                    raise ValueError("BAD_HEALTH_TIME_OR_LOSS")
                heap=diag.get("heap")
                if not isinstance(heap,dict) or not all(_count(heap.get(k)) for k in ("total_bytes","free_bytes","free_error_count")):
                    raise ValueError("BAD_HEAP_SAMPLE")
                valid.append(diag)
    report={"schema":"p7u-health-assessment/v1","transport":"UNKNOWN",
        "network":"UNKNOWN","counter_delta":None,"reboot_identity_known":False,
        "automatic_actions":[],"limits":["Diagnostic replies prove the host MT round trip, not RF delivery.",
            "Counters and first fault are per boot; SRAM retention is unqualified.",
            "AF status is the reported completion status, not a radio trace or root cause."]}
    if results[-1]=="response": report["transport"]="MT_REPLY_RECEIVED"
    if results[-1]=="invalid_response": report["transport"]="INVALID_OR_UNMATCHED_REPLY"
    if results[-1]=="timeout": report["transport"]="PROBE_TIMEOUT"
    if len(results)>=2 and results[-2:]==["timeout","timeout"]:
        report["transport"]="REPEATED_TIMEOUT_TRANSPORT_OR_COORDINATOR_UNRESPONSIVE"
    if len(sessions)!=1:
        report["delta_status"]="SESSION_BOUNDARY_UNKNOWN"
    elif same_boot and len(valid)>=2:
        first,last=valid[0],valid[-1]
        boundary=any(((b["sample_tick"]-a["sample_tick"])&0xFFFFFFFF)>=0x80000000 or
            any(b["counters"][k]<a["counters"][k] for k in decoder.HEALTH_COUNTERS)
            for a,b in zip(valid,valid[1:]))
        if boundary:
            report["delta_status"]="COUNTER_RESET_OR_BOOT_BOUNDARY"
        elif any(first["counters"][k]==0xFFFFFFFF or last["counters"][k]==0xFFFFFFFF for k in decoder.HEALTH_COUNTERS):
            report["delta_status"]="SATURATED_COUNTER_DELTA_UNKNOWN"
        else:
            report["delta_status"]="DECLARED_SAME_BOOT"
            report["counter_delta"]={k:last["counters"][k]-first["counters"][k] for k in decoder.HEALTH_COUNTERS}
    else: report["delta_status"]="SAME_BOOT_NOT_ESTABLISHED"
    if valid:
        latest=valid[-1]
        report["recording_loss_observed"]=bool(latest["writer_contention_dropped"])
        report["nv_fault_observed"]=bool(latest["counters"]["nv_failure"] or latest["counters"]["nv_ambiguous"])
        report["heap"]={"latest_total_bytes":latest["heap"]["total_bytes"],
            "latest_free_bytes":latest["heap"]["free_bytes"],
            "minimum_sampled_free_bytes":min(d["heap"]["free_bytes"] for d in valid),
            "free_error_count":latest["heap"]["free_error_count"],
            "actual_low_water_or_largest_block":"UNKNOWN"}
        if latest["heap"]["free_error_count"] or latest["heap"]["free_bytes"]>latest["heap"]["total_bytes"]:
            report["network"]="STOP_TRIAL_ALLOCATOR_FAULT_EVIDENCE"
        if report["nv_fault_observed"]: report["network"]="STOP_TRIAL_NV_FAULT_EVIDENCE"
    if network is not None:
        required=("attempted","succeeded","timed_out","representative_awake_routers")
        if not isinstance(network,dict) or not all(_count(network.get(k)) for k in required):
            raise ValueError("BAD_NETWORK_EVIDENCE")
        window=network.get("window_seconds")
        if isinstance(window,bool) or not isinstance(window,(int,float)) or not math.isfinite(window) or window<0 or type(network.get("host_connected")) is not bool:
            raise ValueError("BAD_NETWORK_WINDOW")
        if network["succeeded"]+network["timed_out"]>network["attempted"]:
            raise ValueError("INCONSISTENT_NETWORK_OUTCOMES")
        if report["network"]=="UNKNOWN" and network["host_connected"] and network["attempted"]>=3 and network["timed_out"]==network["attempted"] and network["representative_awake_routers"]>=2 and window>=30:
            report["network"]="POSSIBLE_NETWORK_STALL_REQUIRES_INVESTIGATION"
        elif report["network"]=="UNKNOWN" and network["succeeded"]>0:
            report["network"]="APPLICATION_PROGRESS_OBSERVED"
    report["recovery"]={"automatic_reset_budget":0,"automatic_retry_budget":0,
        "owner_reconnect_budget_after_evidence_capture":1,
        "steps":["Pause the soak and preserve counters, owner logs and representative transaction outcomes.",
            "Inspect host connection and known awake routers; a timeout alone is not a firmware crash.",
            "If needed, perform at most one owner-managed reconnect with a fresh response matcher; stop if it fails.",
            "Radio reset or stock rollback requires the separately proven recovery procedure and operator decision."]}
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest="command",required=True)
    decode=sub.add_parser("decode");decode.add_argument("frame_hex")
    check=sub.add_parser("assess");check.add_argument("saved_json",type=Path)
    args=parser.parse_args()
    try:
        if args.command=="decode": result=decode_frame(bytes.fromhex(args.frame_hex))
        else:
            if args.saved_json.stat().st_size>1024*1024: raise ValueError("INPUT_TOO_LARGE")
            saved=json.loads(args.saved_json.read_text(encoding="utf-8"))
            result=assess(saved["samples"],network=saved.get("network"),same_boot=saved.get("same_boot",False))
    except (ValueError,KeyError,OSError,TypeError) as error:
        parser.exit(2,"Invalid saved evidence: "+type(error).__name__+"\n")
    print(json.dumps(result,indent=2))


if __name__=="__main__": main()
