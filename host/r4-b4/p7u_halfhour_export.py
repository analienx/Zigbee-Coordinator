#!/usr/bin/env python3
"""Passive immutable half-hour F2 evidence export, without serial, MQTT, or service control."""
from __future__ import annotations
import argparse
import collections
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import time

DEFAULT_ROOT = Path("/config/zigbee2mqtt/p7u-b4-diagnostics")
GEN_RX = re.compile(r"generation-[0-9a-f-]{36}\Z")
FILE_RX = re.compile(r"f2_([0-9]{8}T[0-9]{6}Z)\.json\Z")
MAX_JOURNAL = 4 * 1024 * 1024
SIMPLE = set("""schema kind utc probeLatencyMs monotonicReceiveNs abi minor sequence validityMask
srspDepth srspHighWater asyncDepth asyncHighWater srspEnqueued uartTxFinishedEvents
radioEpochTag radioEpochHardwareVerified resetReason imageRuntimeAttested hostPackage
hostRunId ownerGeneration processUptimeMs reason skipReason notSubmittedReason
submissionState timingQuality sourceAbi failureClass hostTimeoutKind hostTimeoutAtMs
hostTimeoutDropped""".split())
MT = set("""allProduced allEnqueued allAllocFailed allSendFailed allNpiReceived
allFramedQueued allFramingFailed allTlSubmitted allTlRejected afDataProduced
afDataEnqueued afDataAllocFailed afDataSendFailed afDataNpiReceived
afDataFramedQueued afDataFramingFailed afDataTlSubmitted afDataTlRejected""".split())
UART = set("""npiRequests mtEntered mtReturned uartWriteAccepted uartWriteRejected
uartCallbackOk uartCallbackError uartLengthMismatch stateFlags uartRxBytes
firstFaultKind firstFaultStatusBits firstFaultExpected firstFaultActual firstFaultFlags
firstFaultTick firstFaultCommand npiWakes b1FirstFailure tickPeriodUs""".split())
WIRE = set("""rxRawBytes rxChunks unpiParsedFrames unpiParseErrors unpiBufferedBytes
txQueuedBytes txQueuedFrames txQueuedRawBuffers measurement""".split())
HOST = set("""initialized mutexIdle mutexQueued waitressPending diagnosticQuarantined scope
adapterQueuePending adapterClosing interpanLocked""".split())
WAITRESS = {"active", "timedOut", "resolved", "rawMapEntries"}
SRSP = {"ok", "timeout", "maxLatencyMs", "lastLatencyMs"}
PATHS = [
    "uartTxFinishedEvents", "mtLifecycle.allProduced", "mtLifecycle.allEnqueued",
    "mtLifecycle.allTlSubmitted", "mtLifecycle.allTlRejected",
    "mtLifecycle.afDataProduced", "mtLifecycle.afDataEnqueued",
    "mtLifecycle.afDataTlSubmitted", "mtLifecycle.afDataTlRejected",
    "uartProgress.npiRequests", "uartProgress.mtEntered", "uartProgress.mtReturned",
    "uartProgress.uartWriteAccepted", "uartProgress.uartWriteRejected",
    "uartProgress.uartCallbackOk", "uartProgress.uartCallbackError",
    "uartProgress.uartLengthMismatch", "uartProgress.uartRxBytes",
    "hostEvidence.wire.rxRawBytes", "hostEvidence.wire.unpiParsedFrames",
    "hostEvidence.wire.unpiParseErrors", "hostEvidence.wire.txQueuedFrames",
] + [f"hostEvidence.srsp.{sub}.{item}"
     for sub in ("AF", "ZDO", "SYS", "UTIL") for item in ("ok", "timeout")]


def utc(ts: int) -> str:
    return dt.datetime.fromtimestamp(ts / 1000, dt.timezone.utc).isoformat(timespec="seconds")


def safe_num_or_bool(value):
    return value if value is None or type(value) in (int, bool) else None


def fields(d, names, allow_strings=()):
    if not isinstance(d, dict):
        return {}
    return {k: (v[:150] if k in allow_strings and isinstance(v, str)
                else safe_num_or_bool(v))
            for k, v in d.items() if k in names
            and (v is None or type(v) in (int, bool)
                 or (k in allow_strings and isinstance(v, str)))}



CONGESTION = set("""srspQueuedBytes asyncQueuedBytes srspBytesHighWater asyncBytesHighWater
maxSrspQueueAgeTicks maxAsyncQueueAgeTicks maxReadyServiceGapTicks""".split())
FLIGHT_COUNTERS = set("""npiWakes npiLastTick mtEntered mtLastEnteredTick mtExited mtLastExitedTick
eventTotal reserveUsed reserveExhausted reserveReleaseFault reserveActive allSrspProduced
allSrspAllocationFailed allSrspFramingFailed allSrspTlRejected uartTxCallbackOk uartTxCallbackError
uartRxBytes validityFlags eventCount clockTickPeriodUs npiRequests uartWriteAccepted
uartWriteRejected uartStateFlags firstUartFaultKind firstUartFaultTick b1FirstFailure""".split())

def project_flight(flight):
    if not isinstance(flight, dict) or flight.get("abi") != 5 or flight.get("source") != "RADIO_READ_ONLY":
        raise ValueError("INVALID_V5_EXPORT_ABI")
    out = {"abi": 5, "source": "RADIO_READ_ONLY"}
    for key in ("pageSequence", "eventCount"):
        value = flight.get(key)
        if type(value) is not int or not 0 <= value <= 0xffffffff:
            raise ValueError("INVALID_V5_EXPORT_SCALAR")
        out[key] = value
    if not 1 <= out["pageSequence"] or out["eventCount"] > 16:
        raise ValueError("INVALID_V5_EXPORT_BOUNDS")
    counters = flight.get("counters")
    if not isinstance(counters, dict):
        raise ValueError("INVALID_V5_EXPORT_COUNTERS")
    out["counters"] = {}
    for key in FLIGHT_COUNTERS & counters.keys():
        value = counters[key]
        if type(value) is not int or not 0 <= value <= 0xffffffff:
            raise ValueError("INVALID_V5_EXPORT_COUNTER_VALUE")
        out["counters"][key] = value
    def event(value):
        if not isinstance(value, dict) or value.get("subsystem") not in ("SYS", "AF", "ZDO", "OTHER"):
            raise ValueError("INVALID_V5_EXPORT_EVENT")
        if (type(value.get("tick")) is not int or not 0 <= value["tick"] <= 0xffffffff or
                type(value.get("stage")) is not int or not 1 <= value["stage"] <= 9 or
                type(value.get("result")) is not int or not 0 <= value["result"] <= 255):
            raise ValueError("INVALID_V5_EXPORT_EVENT_SCALAR")
        return {key: value[key] for key in ("tick", "stage", "subsystem", "result")}
    events = flight.get("events")
    if not isinstance(events, list) or len(events) != out["eventCount"]:
        raise ValueError("INVALID_V5_EXPORT_EVENT_COUNT")
    out["events"] = [event(value) for value in events]
    for key in ("firstAnomaly", "preAnomaly"):
        value = flight.get(key)
        out[key] = None if value is None else event(value)
    return out


def project_first_warning(value):
    if not isinstance(value, dict) or value.get('schema')!='p7u-host-first-warning-v1':
        raise ValueError('FIRST_WARNING_EXPORT_SCHEMA')
    def number(x):return type(x) is int and 0<=x<=9007199254740991
    commands={'ping','version','register','dataRequest','dataRequestExt','dataRequestSrcRtg',
        'startupFromApp','nodeDescReq','activeEpReq','simpleDescReq','mgmtLqiReq','mgmtRtgReq',
        'mgmtBindReq','mgmtNwkUpdateReq','permitJoin','getDeviceInfo','getExtAddr','setTxPower','OTHER'}
    subs={'AF','SYS','ZDO','UTIL'}
    if value.get('trigger') not in {'PENDING_SLOW','SLOW_ACK','SRSP_TIMEOUT'} or not number(value.get('capturedMonoMs')):
        raise ValueError('FIRST_WARNING_EXPORT_TRIGGER')
    if value.get('scope')!='HOST_WARNING_NOT_RADIO_FAULT_PROOF':raise ValueError('FIRST_WARNING_EXPORT_SCOPE')
    op=value.get('operation')
    if not isinstance(op,dict) or op.get('operation') not in commands or op.get('subsystem') not in subs:
        raise ValueError('FIRST_WARNING_EXPORT_OPERATION')
    nums={'operationId','startedMonoMs','timeoutMs','warningAfterMs','elapsedMs'}
    if any(not number(op.get(k)) for k in nums):raise ValueError('FIRST_WARNING_EXPORT_OPERATION_NUMBER')
    if op.get('timerLatenessMs') is not None and not number(op['timerLatenessMs']):raise ValueError('FIRST_WARNING_EXPORT_LATENESS')
    out={k:value[k] for k in ('schema','trigger','capturedMonoMs','scope')}
    out['operation']={k:op[k] for k in nums|{'operation','subsystem','timerLatenessMs'}}
    ingress=value.get('ingressTiming')
    if not isinstance(ingress,dict) or any(ingress.get(k) is not None and not number(ingress[k])
        for k in ('lastRxMonoMs','lastParsedMonoMs')):raise ValueError('FIRST_WARNING_EXPORT_INGRESS')
    out['ingressTiming']={k:ingress.get(k) for k in ('lastRxMonoMs','lastParsedMonoMs')}
    history=value.get('recentOperations')
    if not isinstance(history,list) or not 1<=len(history)<=16:raise ValueError('FIRST_WARNING_EXPORT_HISTORY_BOUND')
    out['recentOperations']=[]
    numbers={'atMonoMs','operationId','rxRawBytes','parsedFrames','parseErrors','bufferedBytes','queueDepth','waiterMapEntries'}
    for row in history:
        if not isinstance(row,dict) or any(not number(row.get(k)) for k in numbers) or row.get('subsystem') not in subs or \
            row.get('operation') not in commands or row.get('phase') not in {'OFFERED','ACK','TIMEOUT','ERROR'}:
            raise ValueError('FIRST_WARNING_EXPORT_HISTORY')
        out['recentOperations'].append({k:row[k] for k in numbers|{'subsystem','operation','phase'}})
    last=value.get('lastFlight');out['lastFlight']=None
    if last is not None:
        if not isinstance(last,dict) or not number(last.get('ageMs')) or last.get('ageBasis')!='HOST_MONOTONIC_SINCE_SAMPLE_ENQUEUE':
            raise ValueError('FIRST_WARNING_EXPORT_FLIGHT_AGE')
        receipt=last.get('receipt');record=last.get('record')
        if not isinstance(receipt,dict) or not number(receipt.get('sequence')) or not number(receipt.get('committedBytes')) or \
            not isinstance(receipt.get('sha256'),str) or not re.fullmatch('[a-f0-9]{64}',receipt['sha256']) or \
            not isinstance(record,dict) or record.get('kind')!='FLIGHT':raise ValueError('FIRST_WARNING_EXPORT_FLIGHT_RECEIPT')
        out['lastFlight']={'ageMs':last['ageMs'],'ageBasis':last['ageBasis'],
            'receipt':{k:receipt[k] for k in ('sequence','sha256','committedBytes')},'record':project(record)}
    return out


V6_COUNTERS=set('''monitorFlags tickPeriodUs monitorChecks lastCheckTick maxCheckGapTicks npiWakes npiLastTick
stackDispatchEntered stackLastEnteredTick stackDispatchExited stackLastExitedTick stackActiveService uartComplete
uartLastCompleteTick faultMask firstObservedStage mtFastBudgetTicks mtOtherBudgetTicks srspQueueBudgetTicks
asyncQueueBudgetTicks uartBudgetTicks mtStageId mtSinceTick txStageId txSinceTick srspQueuedBytes asyncQueuedBytes selectedFaultStage'''.split())
V6_FAULT_NUMBERS=set('''stage stageId enteredTick observedTick ageTicks budgetTicks pendingFlags mtStageId txStageId
srspQueuedBytes asyncQueuedBytes npiWakes stackDispatchEntered stackDispatchExited uartComplete eventCount eventTotal
srspProducedAtMtEnter srspProducedAtObservation stackActiveService observationFlags'''.split())
def project_stage(v):
    def nums(obj,keys):
        if not isinstance(obj,dict) or set(obj)!=keys or any(type(obj[k]) is not int or not 0<=obj[k]<=0xffffffff for k in keys):
            raise ValueError('V6_EXPORT_NUMBERS')
        return {k:obj[k] for k in keys}
    def command(x):
        if not isinstance(x,dict) or set(x)!={'subsystem','operation'} or x['subsystem'] not in {'AF','SYS','ZDO','OTHER'} or x['operation'] not in {
            'dataRequest','dataRequestExt','dataRequestSrcRtg','register','ping','version','OTHER'}:raise ValueError('V6_EXPORT_COMMAND')
        return dict(x)
    if not isinstance(v,dict) or set(v)!={'abi','source','scope','ownerScope','pageSequence','nativeTick','counters','mtOperation','txOperation','fault'} or \
        v['abi']!=6 or v['source']!='RADIO_READ_ONLY' or v['scope']!='OVERDUE_OBSERVATION_NOT_PERMANENT_FAULT' or \
        v['ownerScope']!='STAGE_LOCAL_MT_FRAME_LOCAL_QUEUE_TX':raise ValueError('V6_EXPORT_SCHEMA')
    out={k:v[k] for k in ('abi','source','scope','ownerScope')}
    out.update(nums({k:v[k] for k in ('pageSequence','nativeTick')},{'pageSequence','nativeTick'}))
    out['counters']=c=nums(v['counters'],V6_COUNTERS)
    if not out['pageSequence'] or not c['monitorFlags']&1 or c['monitorFlags']>7 or not 0<c['tickPeriodUs']<=100000 or c['faultMask']>15 or \
        not 0<=c['firstObservedStage']<=4 or not 0<=c['selectedFaultStage']<=4 or bool(c['faultMask'])!=bool(c['selectedFaultStage']):
        raise ValueError('V6_EXPORT_FLAGS')
    out['mtOperation']=command(v['mtOperation']);out['txOperation']=command(v['txOperation']);out['fault']=None
    f=v['fault']
    if f is not None:
        if not isinstance(f,dict) or set(f)!=V6_FAULT_NUMBERS|{'subsystem','operation','events'}:raise ValueError('V6_EXPORT_FAULT_KEYS')
        p=nums({k:f[k] for k in V6_FAULT_NUMBERS},V6_FAULT_NUMBERS)
        if p['stage']!=c['selectedFaultStage'] or not p['stageId'] or not p['budgetTicks'] or not p['budgetTicks']<=p['ageTicks']<0x80000000 or \
            (p['observedTick']-p['enteredTick'])&0xffffffff!=p['ageTicks'] or p['eventCount']!=min(p['eventTotal'],16) or \
            p['pendingFlags']>63 or p['observationFlags']!=p['pendingFlags'] or not isinstance(f['events'],list) or len(f['events'])!=p['eventCount']:
            raise ValueError('V6_EXPORT_FAULT')
        p.update(command({k:f[k] for k in ('subsystem','operation')}));p['events']=[]
        for e in f['events']:
            if not isinstance(e,dict) or set(e)!={'tick','stage','result','subsystem','operation'}:raise ValueError('V6_EXPORT_EVENT_KEYS')
            q=nums({k:e[k] for k in ('tick','stage','result')},{'tick','stage','result'})
            if not 1<=q['stage']<=9 or q['result']>255 or (q['stage']==8 and not q['result']):raise ValueError('V6_EXPORT_EVENT')
            q.update(command({k:e[k] for k in ('subsystem','operation')}));p['events'].append(q)
        out['fault']=p
    elif c['selectedFaultStage']:raise ValueError('V6_EXPORT_MISSING_FAULT')
    return out

def project(original: dict) -> dict:
    d = fields(original, SIMPLE, {"schema", "kind", "monotonicReceiveNs",
                "hostPackage", "hostRunId", "ownerGeneration", "reason",
                "skipReason", "notSubmittedReason", "submissionState",
                "timingQuality", "failureClass", "hostTimeoutKind"})
    for key, names in (("mtLifecycle", MT), ("uartProgress", UART), ("congestion", CONGESTION)):
        if key in original:
            d[key] = fields(original[key], names)
    if original.get("kind") == "FLIGHT":
        d["flightV5"] = project_flight(original.get("flightV5"))
    if original.get('kind')=='FIRST_WARNING':
        d['firstWarning']=project_first_warning(original.get('firstWarning'))
    if original.get('kind')=='STAGE':
        d['stageV6']=project_stage(original.get('stageV6'))
    host = original.get("hostEvidence")
    if isinstance(host, dict):
        h = fields(host, HOST, {"scope"})
        h["wire"] = fields(host.get("wire"), WIRE, {"measurement"})
        h["waitressAccounting"] = fields(host.get("waitressAccounting"), WAITRESS)
        srsp = host.get("srsp")
        h["srsp"] = {sub: fields(srsp.get(sub), SRSP)
                     for sub in ("AF", "ZDO", "SYS", "UTIL")} if isinstance(srsp, dict) else {}
        d["hostEvidence"] = h
    return d


def snapshot(root: Path):
    for _ in range(5):
        pointer_before = (root / "current-v2.json").read_bytes()
        gen = json.loads(pointer_before).get("active")
        if not isinstance(gen, str) or not GEN_RX.fullmatch(gen):
            raise ValueError("UNTRUSTED_GENERATION")
        folder = root / gen
        man_before = (folder / "manifest-v2.json").read_bytes()
        path = folder / "events-v2.jsonl"
        if path.stat().st_size > MAX_JOURNAL:
            raise ValueError("JOURNAL_EXCEEDS_LIMIT")
        raw = path.read_bytes()
        if (pointer_before != (root / "current-v2.json").read_bytes()
                or man_before != (folder / "manifest-v2.json").read_bytes()):
            time.sleep(.1)
            continue
        man = json.loads(man_before)
        if not raw.endswith(b"\n") and raw:
            raise ValueError("TORN_JOURNAL")
        if man.get("committedBytes") != len(raw) or man.get("schema") != "p7u-f2-worker-v2":
            raise ValueError("MANIFEST_MISMATCH")
        prev, output = "0" * 64, []
        last_valid_seq, last_valid_host = None, None
        for seq, line in enumerate(raw.splitlines(), 1):
            frame = json.loads(line)
            data = frame.get("data")
            if not isinstance(data, dict):
                raise ValueError("NONOBJECT_EVENT")
            expected = hashlib.sha256(json.dumps(
                {"seq": seq, "previous": prev, "data": data},
                ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()
            if frame.get("seq") != seq or frame.get("previous") != prev or frame.get("sha") != expected:
                raise ValueError("INVALID_HASH_CHAIN_AT_" + str(seq))
            prev = expected
            if data.get("kind") == "VALID":
                last_valid_seq, last_valid_host = seq, data.get("hostRunId")
            output.append((seq, data))
        if (man.get("sequence") != len(output) or man.get("head") != prev
                or man.get("lastValidSeq") != last_valid_seq
                or man.get("lastValidHostRun") != last_valid_host):
            raise ValueError("INVALID_MANIFEST_HEAD")
        return gen, man, raw, output
    raise RuntimeError("CONCURRENT_JOURNAL_COMMIT")


def metric(row: dict, path: str):
    for k in path.split("."):
        if not isinstance(row, dict):
            return None
        row = row.get(k)
    return row if type(row) is int and row >= 0 else None


def deltas(valid):
    results = {}
    for path in PATHS:
        values = [metric(r, path) for r in valid]
        values = [v for v in values if v is not None]
        if len(values) >= 2:
            results[path] = {"first": values[0], "last": values[-1],
                             "delta": values[-1] - values[0],
                             "counterReset": any(b < a for a, b in zip(values, values[1:]))}
    return results


def analyze(rows, start, end):
    selected = [(seq, project(v)) for seq, v in rows
                if type(v.get("utc")) is int and start <= v["utc"] < end]
    events = [{"journalSequence": seq, **v} for seq, v in selected]
    counts = dict(collections.Counter(x.get("kind", "UNKNOWN") for x in events))
    valid = [x for x in events if x.get("kind") == "VALID"]
    flights = [x for x in events if x.get("kind") == "FLIGHT"]
    failures = [x for x in events if x.get("kind") == "FAILED"]
    warnings = [x for x in events if x.get('kind')=='FIRST_WARNING']
    stages = [x for x in events if x.get('kind')=='STAGE']
    segments = []
    for v in valid:
        owner = (v.get("hostRunId"), v.get("ownerGeneration"))
        if not segments or segments[-1]["owner"] != owner:
            segments.append({"owner": owner, "samples": []})
        segments[-1]["samples"].append(v)
    for s in segments:
        samples = s.pop("samples")
        s["owner"] = {"hostRunId": s["owner"][0], "ownerGeneration": s["owner"][1]}
        s["fromUtc"], s["toUtc"] = utc(samples[0]["utc"]), utc(samples[-1]["utc"])
        s["validSamples"] = len(samples)
        s["deltas"] = deltas(samples)
        s["lastNative"] = samples[-1].get("uartProgress", {})
        s["lastCongestion"] = samples[-1].get("congestion", {})
        s["lastMtLifecycle"] = samples[-1].get("mtLifecycle", {})
        s["lastHostSrsp"] = samples[-1].get("hostEvidence", {}).get("srsp", {})
    issues = []
    if not events: issues.append("NO_JOURNAL_EVENTS_IN_WINDOW")
    if not valid: issues.append("NO_VALID_NATIVE_F2_IN_WINDOW")
    if valid and (end - valid[-1]["utc"]) > 300_000:
        issues.append("VALID_F2_ABSENT_FOR_FINAL_5_MINUTES")
    if failures: issues.append("F2_OR_HOST_FAILURE_EVENT_RECORDED")
    if warnings: issues.append('HOST_FIRST_WARNING_CAPTURED')
    if any(x['stageV6']['fault'] is not None for x in stages):issues.append('NATIVE_OVERDUE_STAGE_OBSERVED')
    if any(s["deltas"].get("hostEvidence.srsp.AF.timeout", {}).get("delta", 0) > 0
           for s in segments): issues.append("AF_SRSP_TIMEOUTS_INCREASED")
    if any(s["deltas"].get("uartProgress.uartWriteRejected", {}).get("delta", 0) > 0
           or s["deltas"].get("uartProgress.uartCallbackError", {}).get("delta", 0) > 0
           for s in segments): issues.append("UART_TX_ERROR_COUNT_INCREASED")
    return {
        "startUtc": utc(start), "endUtc": utc(end),
        "durationSeconds": 1800,
        "summary": {
            "status": "DEGRADED" if not valid else ("WARNING" if issues else "HEALTHY_OBSERVED"),
            "countsByKind": counts, "nativeF2Valid": len(valid),
            "nativeMinorCounts": dict(collections.Counter(str(x.get("minor")) for x in valid)),
            "nativeV5Flights": len(flights),
            'hostFirstWarnings':len(warnings),
            'nativeV6Stages':len(stages),
            'lastStageUtc':utc(stages[-1]['utc']) if stages else None,
            'lastStageCounters':stages[-1]['stageV6']['counters'] if stages else None,
            'overdueStagesObserved':sorted({x['stageV6']['fault']['stage'] for x in stages if x['stageV6']['fault'] is not None}),
            'firstWarningTriggers':dict(collections.Counter(x['firstWarning']['trigger'] for x in warnings)),
            "lastFlightUtc": utc(flights[-1]["utc"]) if flights else None,
            "lastFlightCounters": flights[-1]["flightV5"]["counters"] if flights else None,
            "lastValidUtc": utc(valid[-1]["utc"]) if valid else None,
            "lastValidGapFromWindowEndSeconds": round((end - valid[-1]["utc"]) / 1000, 1) if valid else None,
            "skipReasons": dict(collections.Counter(x.get("reason") or x.get("skipReason") for x in events if x.get("kind") == "SKIPPED")),
            "failureClasses": dict(collections.Counter(x.get("failureClass") for x in failures)),
            "issues": issues, "ownerSegments": segments,
        },
        "events": events,
    }


def durable_replace(path: Path, raw: bytes):
    fd, tmp = tempfile.mkstemp(prefix=".partial-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        dirfd = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(dirfd)
        finally: os.close(dirfd)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--window-end", type=int, default=None, help="UTC Unix milliseconds; aligned to half hour")
    args = p.parse_args()
    now = int(time.time() * 1000)
    end = args.window_end if args.window_end is not None else (now // 1_800_000) * 1_800_000
    start = end - 1_800_000
    if (end % 1_800_000 or end > now or now - end > 86_400_000):
        raise ValueError("INVALID_OR_STALE_CLOSED_WINDOW")
    gen, man, raw, rows = snapshot(args.root)
    report = {
        "schema": "p7u-f2-comprehensive-30m-v1", "captureUtc": utc(now),
        "exporterVersion": "V6_STAGE_ADDITIVE_20261029",
        "readOnlyPassive": True,
        "noSerialAccessOrZnpRequests": True,
        "source": {
            "activeGeneration": gen,
            "verified": True,
            "journalAllRecords": len(rows),
            "journalSha256": hashlib.sha256(raw).hexdigest(),
            "journalHead": man["head"],
            "manifestSequence": man["sequence"],
            "manifestCommittedBytes": man["committedBytes"],
        },
        **analyze(rows, start, end),
    }
    print(json.dumps({"windowStartUtc": utc(start), "windowEndUtc": utc(end),
        "summary": report["summary"]["status"],
        "validF2": report["summary"]["nativeF2Valid"],
        "events": len(report["events"]), "issues": report["summary"]["issues"]}, separators=(",", ":")))
    if args.dry_run: return
    output = args.root / "30min-dumps"
    output.mkdir(mode=0o700, exist_ok=True)
    os.chmod(output, 0o700)
    with (output / ".writer.lock").open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        name = "f2_" + dt.datetime.fromtimestamp(start/1000, dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".json"
        dest = output / name
        if dest.exists():
            existing = json.loads(dest.read_text())
            if existing.get("schema") != report["schema"] or existing.get("startUtc") != utc(start):
                raise ValueError("EXISTING_DUMP_CONFLICT")
            print("ALREADY_IMMUTABLY_EXPORTED", dest)
            return
        body = (json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode()
        durable_replace(dest, body)
        digest = hashlib.sha256(body).hexdigest()
        durable_replace(output / (name + ".sha256"), (digest + "  " + name + "\n").encode())
        durable_replace(output / "latest.json", (json.dumps({
            "schema": report["schema"], "filename": name, "sha256": digest,
            "status": report["summary"]["status"], "endUtc": utc(end),
            "validF2": report["summary"]["nativeF2Valid"],
            "nativeV5Flights": report["summary"]["nativeV5Flights"],
            "issues": report["summary"]["issues"]}, indent=2) + "\n").encode())
        for item in output.iterdir():
            match = FILE_RX.fullmatch(item.name)
            if not match:
                continue
            stamp = int(dt.datetime.strptime(match.group(1), "%Y%m%dT%H%M%SZ")
                        .replace(tzinfo=dt.timezone.utc).timestamp()*1000)
            if now - (stamp + 1_800_000) > 86_400_000:
                item.unlink()
                sidecar = output / (item.name + ".sha256")
                if sidecar.exists(): sidecar.unlink()
        print("EXPORTED", dest, digest)

if __name__ == "__main__":
    main()
