"use strict";
/** P7U native SYS F2 diagnostic evidence writer v2.
 * ONLY receives bounded structured records over Worker IPC. No UART,
 * MQTT, adapter, HA API or network modules. Disk failures stop sampling.
 * History v1 is preserved untouched; v2 never promotes orphaned data.
 */
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const {parentPort, workerData, isMainThread} = require("node:worker_threads");

const SCHEMA = "p7u-f2-worker-v2";
const LIMIT = 4 * 1024 * 1024;
// Minor4 retains the complete legacy progress fields and adds congestion.
// Keep a fixed per-record bound with room for saturated counters + owner data.
const RECORD_LIMIT = 4096;
const COUNT_LIMIT = 4096;
const RETENTION_MS = 24 * 60 * 60 * 1000;
const GENERATION = /^generation-[a-f0-9-]{36}$/;
const POINTER = "current-v2.json";
const allowed = new Set([
    "schema", "kind", "utc", "probeLatencyMs", "monotonicReceiveNs", "reason",
    "sourceAbi", "imageRuntimeAttested", "abi", "minor", "sequence", "validityMask",
    "srspDepth", "srspHighWater", "asyncDepth", "asyncHighWater", "srspEnqueued",
    "uartTxFinishedEvents", "mtLifecycle", "uartProgress", "congestion", "radioEpochTag", "radioEpochHardwareVerified",
    "resetReason", "hostPackage", "firmwareSourceClaim", "failureClass",
    "submissionState", "timingQuality", "hostRunId", "ownerGeneration",
    "processUptimeMs", "hostTimeoutKind", "hostTimeoutAtMs", "hostTimeoutDropped",
    "hostEvidence", "flightV5", "firstWarning"
]);
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");
const encode = (v) => Buffer.from(JSON.stringify(v) + "\n", "utf8");
const fail = (reason) => {throw Error("P7U_F2_WRITER_HOLD_" + reason);};
function hold(check, reason) {if (!check) fail(reason);}
function exists(file) {
    try {fs.lstatSync(file); return true;}
    catch (error) {if (error.code === "ENOENT") return false; throw error;}
}
function sameRecord(entry) {
    hold(entry && typeof entry === "object" && !Array.isArray(entry), "RECORD_SHAPE");
    hold(Object.keys(entry).every(k => allowed.has(k)), "RECORD_FIELD");
    hold(["VALID", "SKIPPED", "FAILED", "QUARANTINED", "OWNER_CLOSED", "FLIGHT", "FIRST_WARNING"].includes(entry.kind), "KIND");
    hold(Number.isSafeInteger(entry.utc) && entry.utc > 0, "UTC");
    hold(typeof entry.monotonicReceiveNs === "string" &&
        /^[0-9]{1,32}$/.test(entry.monotonicReceiveNs), "MONOTONIC");
    hold(typeof entry.hostRunId === "string" &&
        /^[a-f0-9-]{36}$/.test(entry.hostRunId), "RUN");
    hold(typeof entry.ownerGeneration === "string" &&
        /^[a-f0-9-]{36}$/.test(entry.ownerGeneration), "OWNER");
    /* V5 flights share fsync/hash chain but are NOT legacy native VALID.
     * Reject unknown nested keys, raw payloads, identity, nonce and boot. */
    if (entry.kind === "FLIGHT") {
        const keys=["schema","kind","utc","monotonicReceiveNs","hostRunId",
                    "ownerGeneration","processUptimeMs","probeLatencyMs","flightV5",
                    "radioEpochTag","radioEpochHardwareVerified","hostEvidence"];
        hold(Object.keys(entry).length === keys.length &&
             Object.keys(entry).every(k=>keys.includes(k)), "V5_FLIGHT_TOP_LEVEL");
        const flight=entry.flightV5;
        const exact=(x,keys)=>x && typeof x==="object" && !Array.isArray(x) &&
            Object.keys(x).length===keys.length && Object.keys(x).every(k=>keys.includes(k));
        const num=v=>Number.isSafeInteger(v) && v>=0 && v<=0xffffffff;
        const fields=["npiWakes","npiLastTick","mtEntered","mtLastEnteredTick",
            "mtExited","mtLastExitedTick","eventTotal","reserveUsed",
            "reserveExhausted","reserveReleaseFault","reserveActive",
            "allSrspProduced","allSrspAllocationFailed","allSrspFramingFailed",
            "allSrspTlRejected","uartTxCallbackOk","uartTxCallbackError",
            "uartRxBytes","validityFlags","eventCount","clockTickPeriodUs",
            "npiRequests","uartWriteAccepted","uartWriteRejected","uartStateFlags",
            "firstUartFaultKind","firstUartFaultTick","b1FirstFailure"];
        hold(exact(flight,["abi","pageSequence","eventCount","counters","events","source",
             "firstAnomaly","preAnomaly"]) &&
            flight.abi===5 && flight.source==="RADIO_READ_ONLY" &&
            num(flight.pageSequence) && flight.pageSequence>0 &&
            num(flight.eventCount) && flight.eventCount<=16 &&
            exact(flight.counters,fields) && fields.every(k=>num(flight.counters[k])) &&
            flight.counters.eventCount===flight.eventCount &&
            flight.counters.reserveActive<=3 &&
            flight.counters.reserveUsed>=flight.counters.reserveActive &&
            flight.counters.reserveReleaseFault<=flight.counters.reserveUsed &&
            flight.counters.mtExited<=flight.counters.mtEntered &&
            flight.counters.firstUartFaultKind<=5 &&
            flight.counters.b1FirstFailure<=255 &&
            (flight.counters.uartStateFlags&0xfff0)===0 &&
            (flight.counters.firstUartFaultKind!==0 || flight.counters.firstUartFaultTick===0) &&
            flight.counters.clockTickPeriodUs>0 &&
            flight.counters.clockTickPeriodUs<=100000 &&
            flight.counters.validityFlags<=7 &&
            (flight.counters.validityFlags&2)===2 &&
            flight.counters.eventCount===Math.min(flight.counters.eventTotal,16) &&
            Array.isArray(flight.events) &&
            flight.events.length===flight.eventCount, "V5_FLIGHT_COUNTERS");
        hold(entry.radioEpochHardwareVerified===false &&
            (entry.radioEpochTag===null ||
             (typeof entry.radioEpochTag==="string" &&
              /^[a-f0-9]{24}$/.test(entry.radioEpochTag))) &&
            (entry.hostEvidence===null ||
             (entry.hostEvidence!==undefined &&
              typeof entry.hostEvidence==="object" &&
              !Array.isArray(entry.hostEvidence))),
            "V5_EPOCH_AND_PASSIVE_HOST");
        const names=["AF","SYS","ZDO","OTHER"];
        for(const event of flight.events) {
            hold(exact(event,["tick","stage","subsystem","result"]) &&
                num(event.tick) && num(event.result) && num(event.stage) &&
                event.stage>=1 && event.stage<=9 &&
                !(event.stage===8 && event.result===0) &&
                names.includes(event.subsystem), "V5_FLIGHT_EVENT");
        }
        const validAnomaly=(event,required)=>event!==null &&
            exact(event,["tick","stage","subsystem","result"]) &&
            num(event.tick) && num(event.result) && num(event.stage) &&
            event.stage>=1 && event.stage<=9 &&
            !(event.stage===8 && event.result===0) &&
            names.includes(event.subsystem) &&
            (!required || ((event.stage===8 || event.stage===9) && event.result!==0));
        if ((flight.counters.validityFlags&4)===4) {
            hold(validAnomaly(flight.firstAnomaly,true) &&
                (flight.preAnomaly===null || validAnomaly(flight.preAnomaly,false)),
                "V5_FROZEN_ANOMALY");
        } else {
            hold(flight.firstAnomaly===null && flight.preAnomaly===null,
                 "V5_UNQUALIFIED_ANOMALY");
        }
        hold(Number.isSafeInteger(entry.probeLatencyMs) &&
            entry.probeLatencyMs>=0 && entry.probeLatencyMs<=30000 &&
            Number.isSafeInteger(entry.processUptimeMs) &&
            entry.processUptimeMs>=0, "V5_FLIGHT_TIMING");
    } else {
        hold(!Object.hasOwn(entry,"flightV5"),"V5_FLIGHT_ONLY");
    }
    if(entry.kind==="FIRST_WARNING") {
        const exact=(x,keys)=>x && typeof x==="object" && !Array.isArray(x) &&
            Object.keys(x).length===keys.length && Object.keys(x).every(k=>keys.includes(k));
        const num=v=>Number.isSafeInteger(v) && v>=0;
        const names=["ping","version","register","dataRequest","dataRequestExt","dataRequestSrcRtg",
            "startupFromApp","nodeDescReq","activeEpReq","simpleDescReq","mgmtLqiReq","mgmtRtgReq",
            "mgmtBindReq","mgmtNwkUpdateReq","permitJoin","getDeviceInfo","getExtAddr","setTxPower","OTHER"];
        const subs=["AF","ZDO","SYS","UTIL"];
        hold(entry.schema==="p7u-b4-native-sample-v1" && exact(entry,["schema","kind","utc","monotonicReceiveNs","hostRunId","ownerGeneration",
            "processUptimeMs","firstWarning","hostEvidence"]),"FIRST_WARNING_FIELDS");
        const w=entry.firstWarning;
        hold(exact(w,["schema","trigger","capturedMonoMs","operation","ingressTiming","recentOperations","scope","lastFlight"]) &&
            w.schema==="p7u-host-first-warning-v1" && ["PENDING_SLOW","SLOW_ACK","SRSP_TIMEOUT"].includes(w.trigger) &&
            num(w.capturedMonoMs) && w.scope==="HOST_WARNING_NOT_RADIO_FAULT_PROOF","FIRST_WARNING_HEADER");
        const op=w.operation;
        hold(exact(op,["operationId","subsystem","operation","startedMonoMs","timeoutMs","warningAfterMs","elapsedMs","timerLatenessMs"]) &&
            num(op.operationId) && op.operationId>0 && subs.includes(op.subsystem) && names.includes(op.operation) &&
            num(op.startedMonoMs) && num(op.timeoutMs) && op.timeoutMs>0 && op.timeoutMs<=3600000 &&
            num(op.warningAfterMs) && op.warningAfterMs===Math.min(4000,Math.max(250,Math.floor(op.timeoutMs*2/3))) &&
            num(op.elapsedMs) && w.capturedMonoMs-op.startedMonoMs===op.elapsedMs &&
            (w.trigger==="PENDING_SLOW" ? op.timerLatenessMs===Math.max(0,op.elapsedMs-op.warningAfterMs) :
                op.timerLatenessMs===null),"FIRST_WARNING_OPERATION");
        hold(exact(w.ingressTiming,["lastRxMonoMs","lastParsedMonoMs"]) &&
            Object.values(w.ingressTiming).every(v=>v===null || (num(v) && v<=w.capturedMonoMs)),"FIRST_WARNING_INGRESS");
        hold(Array.isArray(w.recentOperations) && w.recentOperations.length>0 && w.recentOperations.length<=16,
            "FIRST_WARNING_HISTORY_BOUND");
        for(const e of w.recentOperations)hold(exact(e,["atMonoMs","operationId","subsystem","operation","phase",
            "rxRawBytes","parsedFrames","parseErrors","bufferedBytes","queueDepth","waiterMapEntries"]) &&
            num(e.atMonoMs) && e.atMonoMs<=w.capturedMonoMs && num(e.operationId) && e.operationId>0 &&
            subs.includes(e.subsystem) && names.includes(e.operation) && ["OFFERED","ACK","TIMEOUT","ERROR"].includes(e.phase) &&
            ["rxRawBytes","parsedFrames","parseErrors","bufferedBytes","queueDepth","waiterMapEntries"].every(k=>num(e[k])),
            "FIRST_WARNING_HISTORY_FIELDS");
        const last=w.lastFlight;
        if(last!==null){
            hold(exact(last,["record","receipt","ageMs","ageBasis"]) && num(last.ageMs) &&
                last.ageBasis==="HOST_MONOTONIC_SINCE_SAMPLE_ENQUEUE" &&
                exact(last.receipt,["sequence","sha256","committedBytes"]) &&
                num(last.receipt.sequence) && last.receipt.sequence>0 && num(last.receipt.committedBytes) &&
                last.receipt.committedBytes>0 && /^[a-f0-9]{64}$/.test(last.receipt.sha256) &&
                last.record?.kind==="FLIGHT" && last.record.hostRunId===entry.hostRunId &&
                last.record.ownerGeneration===entry.ownerGeneration,"FIRST_WARNING_LAST_FLIGHT");
            sameRecord(last.record); // Full existing privacy/metric validation, not a hash-only claim.
        }
        hold(num(entry.processUptimeMs),"FIRST_WARNING_UPTIME");
    } else hold(!Object.hasOwn(entry,"firstWarning"),"FIRST_WARNING_ONLY");
    if (entry.kind === "VALID") {
        hold(entry.abi === 4 && Number.isSafeInteger(entry.sequence) &&
            entry.sequence > 0, "VALID_SEQUENCE");
        hold(Number.isSafeInteger(entry.validityMask) &&
            entry.validityMask >= 0, "VALID_MASK");
        // Earlier v4.1 records may omit minor. Any explicit unknown minor
        // must fail closed rather than being counted as a native VALID reply.
        hold(entry.minor === undefined || entry.minor === 1 ||
            entry.minor === 2 || entry.minor === 3 || entry.minor === 4, "F2_UNSUPPORTED_MINOR");
        if (entry.minor === 2 || entry.minor === 3 || entry.minor === 4) {
            hold(entry.validityMask === 0x00FFFFEC ||
                entry.validityMask === 0x00FFFFFF || (entry.minor === 4 && entry.validityMask === 0x01FFFFFF),
                "F2_V42_VALIDITY_MASK");
            hold(Object.hasOwn(entry, "mtLifecycle") &&
                entry.mtLifecycle !== null, "F2_V42_MISSING_CAUSAL_COUNTERS");
        }
        if (entry.minor === 1 || entry.minor === undefined) {
            hold(entry.validityMask === 0x2C || entry.validityMask === 0x3F,
                "F2_V41_VALIDITY_MASK");
        }
        if (Object.hasOwn(entry, "mtLifecycle") && entry.mtLifecycle !== null) {
            const v = entry.mtLifecycle;
            const fields = ["allProduced", "allEnqueued", "allAllocFailed",
                "allSendFailed", "allNpiReceived", "allFramedQueued",
                "allFramingFailed", "allTlSubmitted", "allTlRejected",
                "afDataProduced", "afDataEnqueued", "afDataAllocFailed",
                "afDataSendFailed", "afDataNpiReceived", "afDataFramedQueued",
                "afDataFramingFailed", "afDataTlSubmitted", "afDataTlRejected"];
            hold((entry.minor === 2 || entry.minor === 3 || entry.minor === 4) && v && typeof v === "object" &&
                !Array.isArray(v) &&
                Object.keys(v).length === fields.length &&
                Object.keys(v).every(k => fields.includes(k)) &&
                fields.every(k => Number.isSafeInteger(v[k]) &&
                    v[k] >= 0 && v[k] <= 0xFFFFFFFF),
                "F2_V42_LIFECYCLE_SHAPE");
        }
        if (entry.minor === 1 || entry.minor === undefined) {
            hold(!Object.hasOwn(entry, "mtLifecycle") ||
                entry.mtLifecycle === null, "F2_V41_NO_CAUSAL_CLAIM");
        }
        if (entry.minor === 3 || entry.minor === 4) {
            const v = entry.uartProgress;
            const fields = ["npiRequests", "mtEntered", "mtReturned", "uartWriteAccepted",
                "uartWriteRejected", "uartCallbackOk", "uartCallbackError", "uartLengthMismatch",
                "stateFlags", "uartRxBytes", "firstFaultKind", "firstFaultStatusBits",
                "firstFaultExpected", "firstFaultActual", "firstFaultFlags", "firstFaultTick",
                "firstFaultCommand", "npiWakes", "b1FirstFailure", "tickPeriodUs"];
            hold(v && typeof v === "object" && !Array.isArray(v) &&
                Object.keys(v).length === fields.length && Object.keys(v).every(k => fields.includes(k)) &&
                fields.every(k => Number.isSafeInteger(v[k]) && v[k] >= 0 && v[k] <= 0xFFFFFFFF) &&
                v.firstFaultKind <= 5 && v.b1FirstFailure <= 255 &&
                v.tickPeriodUs > 0 && v.tickPeriodUs <= 100000 && v.firstFaultCommand <= 65535 &&
                !(v.stateFlags & 0xFFF0) && !(v.firstFaultFlags & 0xFFF0) &&
                (v.firstFaultKind !== 0 || fields.slice(11,17).every(k => v[k] === 0)),
                "F2_V43_PROGRESS_SHAPE");
        } else {
            hold(entry.uartProgress === undefined || entry.uartProgress === null, "F2_OLD_MINOR_NO_PROGRESS_CLAIM");
        }
        if (entry.minor === 4) {
            const v = entry.congestion;
            const fields = ["srspQueuedBytes", "asyncQueuedBytes", "srspBytesHighWater", "asyncBytesHighWater",
                "maxSrspQueueAgeTicks", "maxAsyncQueueAgeTicks", "maxReadyServiceGapTicks"];
            hold(entry.validityMask === 0x01FFFFFF && v && typeof v === "object" && !Array.isArray(v) &&
                Object.keys(v).length === fields.length && Object.keys(v).every(k => fields.includes(k)) &&
                fields.every(k => Number.isSafeInteger(v[k]) && v[k] >= 0 && v[k] <= 0xFFFFFFFF) &&
                v.srspQueuedBytes <= v.srspBytesHighWater && v.asyncQueuedBytes <= v.asyncBytesHighWater,
                "F2_V44_CONGESTION_SHAPE");
        } else {
            hold(entry.congestion === undefined || entry.congestion === null, "F2_OLD_MINOR_NO_CONGESTION_CLAIM");
        }
    }
    if (entry.kind !== "VALID") {
        hold(entry.uartProgress === undefined || entry.uartProgress === null, "F2_NON_NATIVE_NO_PROGRESS_CLAIM");
        hold(entry.congestion === undefined || entry.congestion === null, "F2_NON_NATIVE_NO_CONGESTION_CLAIM");
    }
    if ("hostEvidence" in entry && entry.hostEvidence !== null) {
        const e = entry.hostEvidence;
        const obj = v => v !== null && typeof v === "object" && !Array.isArray(v);
        const exact = (v, keys) => obj(v) &&
            Object.keys(v).length === keys.length &&
            Object.keys(v).every(k => keys.includes(k));
        const num = v => Number.isSafeInteger(v) && v >= 0;
        const expected = ["initialized", "mutexIdle", "mutexQueued", "waitressPending",
            "diagnosticQuarantined", "srsp", "scope", "adapterQueuePending",
            "adapterClosing", "interpanLocked"];
        // Version-additive only: historical hash-chain records have no wire
        // metrics. Do not rewrite/recompute past evidence to add them.
        if (Object.hasOwn(e, "wire")) expected.push("wire");
        if (Object.hasOwn(e, "waitressAccounting")) expected.push("waitressAccounting");
        hold(exact(e, expected), "HOST_EVIDENCE_FIELDS");
        if (Object.hasOwn(e, "wire")) {
            const w = e.wire;
            hold(exact(w, ["rxRawBytes", "rxChunks", "unpiParsedFrames",
                "unpiParseErrors", "unpiBufferedBytes", "txQueuedBytes",
                "txQueuedFrames", "txQueuedRawBuffers", "measurement"]) &&
                ["rxRawBytes", "rxChunks", "unpiParsedFrames", "unpiParseErrors",
                    "unpiBufferedBytes", "txQueuedBytes", "txQueuedFrames",
                    "txQueuedRawBuffers"].every(k => num(w[k])) &&
                w.measurement === "EXISTING_OWNER_STREAM_ONLY",
                "HOST_WIRE_EVIDENCE_SHAPE");
        }
        if (Object.hasOwn(e, "waitressAccounting")) {
            const c = e.waitressAccounting;
            hold(exact(c, ["active", "timedOut", "resolved", "rawMapEntries"]) &&
                num(c.active) && num(c.timedOut) && num(c.resolved) &&
                num(c.rawMapEntries) &&
                c.active + c.timedOut + c.resolved === c.rawMapEntries,
                "HOST_WAITRESS_ACCOUNTING");
        }
        hold(typeof e.initialized === "boolean" &&
            typeof e.mutexIdle === "boolean" &&
            num(e.mutexQueued) && num(e.waitressPending) &&
            typeof e.diagnosticQuarantined === "boolean" &&
            e.scope === "HOST_OWNER_LIFETIME_ONLY" &&
            (e.adapterQueuePending === null || num(e.adapterQueuePending)) &&
            typeof e.adapterClosing === "boolean" &&
            typeof e.interpanLocked === "boolean", "HOST_EVIDENCE_STATE");
        const subsystemNames = ["AF", "ZDO", "SYS", "UTIL"];
        hold(exact(e.srsp, subsystemNames), "HOST_EVIDENCE_SUBSYSTEMS");
        for (const subsystem of subsystemNames) {
            const stats = e.srsp[subsystem];
            hold(exact(stats, ["ok", "timeout", "maxLatencyMs", "lastLatencyMs"]) &&
                num(stats.ok) && num(stats.timeout) &&
                num(stats.maxLatencyMs) && stats.maxLatencyMs <= 3600000 &&
                (stats.lastLatencyMs === null ||
                    (num(stats.lastLatencyMs) &&
                        stats.lastLatencyMs <= stats.maxLatencyMs)),
                "HOST_EVIDENCE_STATS");
        }
    }
    if (["hostTimeoutKind", "hostTimeoutAtMs", "hostTimeoutDropped"].some(k => k in entry)) {
        hold(entry.kind === "FAILED" &&
            ["AF_SREQ_TIMEOUT", "ZDO_SREQ_TIMEOUT", "SYS_SREQ_TIMEOUT", "UTIL_SREQ_TIMEOUT"].includes(entry.hostTimeoutKind) &&
            Number.isSafeInteger(entry.hostTimeoutAtMs) && entry.hostTimeoutAtMs >= 0 &&
            Number.isSafeInteger(entry.hostTimeoutDropped) && entry.hostTimeoutDropped >= 0 &&
            entry.submissionState === "NO_DIAGNOSTIC_REQUEST", "HOST_TIMEOUT_RECORD");
    }
    const data = encode(entry);
    hold(data.length <= (entry.kind==="FIRST_WARNING" ? 16384 : RECORD_LIMIT), "RECORD_SIZE");
    return data;
}
function manifestInit() {
    return {
        schema: SCHEMA, generation: crypto.randomUUID(), sequence: 0,
        committedBytes: 0, head: "0".repeat(64), lastValidSeq: null,
        lastValidHostRun: null
    };
}
function validateManifest(m) {
    hold(m && m.schema === SCHEMA && Number.isSafeInteger(m.sequence) &&
        m.sequence >= 0 && Number.isSafeInteger(m.committedBytes) &&
        m.committedBytes >= 0 && m.committedBytes <= LIMIT &&
        /^[a-f0-9-]{36}$/.test(m.generation) &&
        /^[a-f0-9]{64}$/.test(m.head), "MANIFEST_INVALID");
}
function syncDir(dir) {
    const fd = fs.openSync(dir, "r");
    try {fs.fsyncSync(fd);} finally {fs.closeSync(fd);}
}
function atomicManifest(dir, next) {
    const name = path.join(dir, ".manifest-" + crypto.randomUUID());
    const fd = fs.openSync(name, "wx", 0o600);
    try {
        const payload = encode(next);
        const count = fs.writeSync(fd, payload, 0, payload.length);
        hold(count === payload.length, "SHORT_MANIFEST");
        fs.fsyncSync(fd);
    } finally {fs.closeSync(fd);}
    fs.renameSync(name, path.join(dir, "manifest-v2.json"));
    syncDir(dir);
}
function recover(dir) {
    hold(!fs.readdirSync(dir).some(name => name.startsWith(".manifest-")),
        "ORPHANED_MANIFEST");
    const md = path.join(dir, "manifest-v2.json");
    const log = path.join(dir, "events-v2.jsonl");
    hold(exists(md) === exists(log), "PARTIAL_INITIALIZATION");
    if (!exists(md)) {
        const fd = fs.openSync(log, "wx", 0o600);
        try {fs.fsyncSync(fd);} finally {fs.closeSync(fd);}
        syncDir(dir);
        const m = manifestInit();
        atomicManifest(dir, m);
        return m;
    }
    hold(!fs.lstatSync(md).isSymbolicLink() && !fs.lstatSync(log).isSymbolicLink(),
        "SYMLINK");
    hold(fs.statSync(md).isFile() && fs.statSync(md).size <= 4096 &&
        fs.statSync(log).isFile(), "HISTORY_FILES");
    const m = JSON.parse(fs.readFileSync(md, "utf8"));
    validateManifest(m);
    const stat = fs.statSync(log);
    hold(stat.size === m.committedBytes, "ORPHANED_OR_TORN_SUFFIX");
    hold(stat.size <= LIMIT, "LOG_OVERSIZED");
    const fd = fs.openSync(log, "r");
    let content;
    try {
        content = Buffer.alloc(stat.size);
        const n = fs.readSync(fd, content, 0, stat.size, 0);
        hold(n === stat.size, "SHORT_REPLAY");
    } finally {fs.closeSync(fd);}
    hold(stat.size === 0 || content.at(-1) === 10, "TORN_LOG");
    let previous = "0".repeat(64), seq = 0, lastValid = null, validHost = null;
    for (const l of content.toString("utf8").split("\n").filter(Boolean)) {
        const frame = JSON.parse(l);
        hold(frame && frame.seq === ++seq && frame.previous === previous &&
            frame.data && frame.sha === sha(Buffer.from(JSON.stringify({
                seq: frame.seq, previous: frame.previous, data: frame.data
            }))), "REPLAY_CHAIN");
        sameRecord(frame.data);
        previous = frame.sha;
        if (frame.data.kind === "VALID") {
            lastValid = seq;
            validHost = frame.data.hostRunId;
        }
    }
    hold(seq === m.sequence && previous === m.head &&
        lastValid === m.lastValidSeq && validHost === m.lastValidHostRun,
        "REPLAY_MANIFEST_MISMATCH");
    return m;
}
function recordsAt(dir) {
    return fs.readFileSync(path.join(dir, "events-v2.jsonl"), "utf8")
        .split("\n").filter(Boolean).map(line => JSON.parse(line).data);
}
function cleanupPrevious(root, previous) {
    if (!previous) return;
    hold(previous === "legacy-root-v2" || GENERATION.test(previous), "PREVIOUS_PATH");
    const dir = previous === "legacy-root-v2" ? root : path.join(root, previous);
    if (!exists(dir)) return;
    hold(fs.lstatSync(dir).isDirectory() && !fs.lstatSync(dir).isSymbolicLink(),
        "PREVIOUS_DIRECTORY");
    if (dir !== root) {
        hold(fs.readdirSync(dir).every(name =>
            ["events-v2.jsonl", "manifest-v2.json"].includes(name)), "PREVIOUS_EXTRA_FILE");
    }
    for (const name of ["events-v2.jsonl", "manifest-v2.json"]) {
        const file = path.join(dir, name);
        if (exists(file)) {
            hold(fs.lstatSync(file).isFile() && !fs.lstatSync(file).isSymbolicLink(),
                "PREVIOUS_FILE");
            fs.unlinkSync(file);
        }
    }
    if (dir !== root) fs.rmdirSync(dir);
    syncDir(root);
}
function rotate(state, records) {
    let next, bytes;
    records = records.slice(-COUNT_LIMIT);
    // Rotation rebases only the storage hash-chain sequence. Native F2
    // sequences and host owner IDs remain untouched in every record.
    do {
        next = manifestInit();
        const frames = [];
        for (const data of records) {
            const frame = {seq: ++next.sequence, previous: next.head, data};
            next.head = sha(Buffer.from(JSON.stringify(frame)));
            frames.push(encode({...frame, sha: next.head}));
            if (data.kind === "VALID") {
                next.lastValidSeq = next.sequence;
                next.lastValidHostRun = data.hostRunId;
            }
        }
        bytes = Buffer.concat(frames);
        if (bytes.length > LIMIT) records.shift();
    } while (bytes.length > LIMIT);
    next.committedBytes = bytes.length;
    const name = "generation-" + next.generation;
    const dir = path.join(state.baseRoot, name);
    fs.mkdirSync(dir, {mode: 0o700});
    const logFd = fs.openSync(path.join(dir, "events-v2.jsonl"), "wx", 0o600);
    try {
        fs.writeFileSync(logFd, bytes);
        fs.fsyncSync(logFd);
    } finally {fs.closeSync(logFd);}
    atomicManifest(dir, next);
    syncDir(state.baseRoot);
    const previous = state.root === state.baseRoot ? "legacy-root-v2" : path.basename(state.root);
    const pending = path.join(state.baseRoot, ".current-v2.pending");
    const pointerFd = fs.openSync(pending, "wx", 0o600);
    try {
        fs.writeFileSync(pointerFd, encode({schema: "p7u-f2-pointer-v1", active: name, previous}));
        fs.fsyncSync(pointerFd);
    } finally {fs.closeSync(pointerFd);}
    // Complete immutable generation first; one pointer rename publishes it.
    // A crash before this rename never promotes an orphaned generation.
    fs.renameSync(pending, path.join(state.baseRoot, POINTER));
    syncDir(state.baseRoot);
    state.root = dir;
    state.manifest = next;
    state.records = records;
    cleanupPrevious(state.baseRoot, previous);
    return {sequence: next.sequence, sha256: next.head, committedBytes: next.committedBytes};
}
function open(root, now = Date.now()) {
    hold(typeof root === "string" && path.isAbsolute(root) &&
        root.endsWith(path.sep + "p7u-b4-diagnostics"), "ROOT_PATH");
    fs.mkdirSync(root, {recursive: true, mode: 0o700});
    const st = fs.lstatSync(root);
    hold(st.isDirectory() && !st.isSymbolicLink() &&
        (typeof process.getuid !== "function" || st.uid === process.getuid()),
        "PRIVATE_DIRECTORY");
    // The retired v1 collector created this same directory with the default
    // umask (often 0755). Narrow its permissions without deleting or opening
    // the old history. A foreign-owned directory is never changed.
    if ((st.mode & 0o777) !== 0o700) fs.chmodSync(root, 0o700);
    hold((fs.lstatSync(root).mode & 0o777) === 0o700, "PRIVATE_DIRECTORY");
    hold(!exists(path.join(root, ".current-v2.pending")), "ORPHANED_POINTER");
    const pointerPath = path.join(root, POINTER);
    let active = root;
    if (exists(pointerPath)) {
        hold(fs.lstatSync(pointerPath).isFile() && !fs.lstatSync(pointerPath).isSymbolicLink() &&
            fs.statSync(pointerPath).size <= 4096, "POINTER_FILE");
        const pointer = JSON.parse(fs.readFileSync(pointerPath, "utf8"));
        hold(pointer.schema === "p7u-f2-pointer-v1" && GENERATION.test(pointer.active) &&
            (pointer.previous === null || pointer.previous === "legacy-root-v2" ||
             (typeof pointer.previous === "string" && GENERATION.test(pointer.previous))) &&
            pointer.previous !== pointer.active, "POINTER_SCHEMA");
        active = path.join(root, pointer.active);
        hold(fs.lstatSync(active).isDirectory() && !fs.lstatSync(active).isSymbolicLink(),
            "ACTIVE_DIRECTORY");
        hold(exists(path.join(active, "manifest-v2.json")) &&
            exists(path.join(active, "events-v2.jsonl")), "ACTIVE_HISTORY_MISSING");
        // Validate the selected generation before removing a specifically
        // recorded retired generation. Unknown directories remain HOLD.
        recover(active);
        cleanupPrevious(root, pointer.previous);
        hold(!fs.readdirSync(root).some(name => name.startsWith("generation-") &&
            name !== pointer.active), "ORPHANED_GENERATION");
        hold(!exists(path.join(root, "manifest-v2.json")) &&
            !exists(path.join(root, "events-v2.jsonl")), "UNSELECTED_LEGACY_LOG");
    } else {
        hold(!fs.readdirSync(root).some(name => name.startsWith("generation-")),
            "ORPHANED_GENERATION");
    }
    const state = {baseRoot: root, root: active, manifest: recover(active), records: recordsAt(active)};
    const retained = state.records.filter(record => record.utc >= now - RETENTION_MS);
    if (active === root || retained.length !== state.records.length || retained.length > COUNT_LIMIT) {
        rotate(state, retained);
    }
    return state;
}
function expire(state, now = Date.now()) {
    const retained = state.records.filter(record => record.utc >= now - RETENTION_MS);
    if (retained.length !== state.records.length) rotate(state, retained);
}
function commit(state, data, now = Date.now()) {
    sameRecord(data);
    hold(data.utc >= now - RETENTION_MS && data.utc <= now + 60_000, "RECORD_TIME");
    const retained = state.records.filter(record => record.utc >= now - RETENTION_MS);
    const current = state.manifest;
    const seq = current.sequence + 1;
    const frame = {seq, previous: current.head, data};
    const frameHash = sha(Buffer.from(JSON.stringify(frame)));
    const bytes = encode({...frame, sha: frameHash});
    if (retained.length !== state.records.length || retained.length >= COUNT_LIMIT ||
        bytes.length > LIMIT - current.committedBytes) {
        return rotate(state, [...retained, data]);
    }
    const log = path.join(state.root, "events-v2.jsonl");
    const fd = fs.openSync(log, "a");
    try {
        const wrote = fs.writeSync(fd, bytes, 0, bytes.length);
        hold(wrote === bytes.length, "SHORT_WRITE");
        fs.fsyncSync(fd);
    } finally {fs.closeSync(fd);}
    const next = {
        ...current, sequence: seq,
        committedBytes: current.committedBytes + bytes.length,
        head: frameHash,
        lastValidSeq: data.kind === "VALID" ? seq : current.lastValidSeq,
        lastValidHostRun: data.kind === "VALID" ? data.hostRunId : current.lastValidHostRun
    };
    // Source of truth is the committed manifest, not an independent
    // last-good file. ACK is emitted only after rename + directory fsync.
    atomicManifest(state.root, next);
    state.manifest = next;
    state.records.push(data);
    return {sequence: seq, sha256: frameHash, committedBytes: next.committedBytes};
}
if (!isMainThread) {
    let state;
    let expiryTimer;
    const fatal = reason => {
        clearTimeout(expiryTimer);
        parentPort.postMessage({type: "fatal", reason});
        parentPort.removeAllListeners("message");
        process.exitCode = 3;
        parentPort.close();
    };
    const scheduleExpiry = () => {
        clearTimeout(expiryTimer);
        if (state.records.length === 0) return;
        const oldest = Math.min(...state.records.map(record => record.utc));
        // Exact expiry deadline, with a <=60s wall-clock recheck for clock
        // adjustments. Housekeeping continues if sampling is quarantined.
        expiryTimer = setTimeout(() => {
            try {expire(state); scheduleExpiry();}
            catch (e) {fatal(e.message);}
        }, Math.max(1, Math.min(60_000, oldest + RETENTION_MS + 1 - Date.now())));
        expiryTimer.unref();
    };
    try {
        hold(workerData && workerData.schema === SCHEMA, "INIT_SCHEMA");
        state = open(workerData.root);
        scheduleExpiry();
        parentPort.postMessage({type: "ready", generation: state.manifest.generation,
            sequence: state.manifest.sequence});
    } catch (e) {
        parentPort.postMessage({type: "fatal", reason: e.message});
        process.exitCode = 2;
    }
    if (state) {
        parentPort.on("message", (message) => {
            try {
                hold(message && message.type === "append" &&
                    Number.isSafeInteger(message.id), "IPC_SCHEMA");
                const receipt = commit(state, message.record);
                scheduleExpiry();
                parentPort.postMessage({type: "committed", id: message.id, receipt});
            } catch (e) {
                fatal(e.message);
            }
        });
    } else {
        parentPort.close();
    }
}
module.exports = {open, commit, expire, sameRecord, recover, SCHEMA, LIMIT, COUNT_LIMIT, RETENTION_MS};
