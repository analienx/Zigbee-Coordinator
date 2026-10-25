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
const RECORD_LIMIT = 3072;
const COUNT_LIMIT = 4096;
const RETENTION_MS = 24 * 60 * 60 * 1000;
const GENERATION = /^generation-[a-f0-9-]{36}$/;
const POINTER = "current-v2.json";
const allowed = new Set([
    "schema", "kind", "utc", "probeLatencyMs", "monotonicReceiveNs", "reason",
    "sourceAbi", "imageRuntimeAttested", "abi", "minor", "sequence", "validityMask",
    "srspDepth", "srspHighWater", "asyncDepth", "asyncHighWater", "srspEnqueued",
    "uartTxFinishedEvents", "radioEpochTag", "radioEpochHardwareVerified",
    "resetReason", "hostPackage", "firmwareSourceClaim", "failureClass",
    "submissionState", "timingQuality", "hostRunId", "ownerGeneration",
    "processUptimeMs", "hostTimeoutKind", "hostTimeoutAtMs", "hostTimeoutDropped",
    "hostEvidence"
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
    hold(["VALID", "SKIPPED", "FAILED", "QUARANTINED", "OWNER_CLOSED"].includes(entry.kind), "KIND");
    hold(Number.isSafeInteger(entry.utc) && entry.utc > 0, "UTC");
    hold(typeof entry.monotonicReceiveNs === "string" &&
        /^[0-9]{1,32}$/.test(entry.monotonicReceiveNs), "MONOTONIC");
    hold(typeof entry.hostRunId === "string" &&
        /^[a-f0-9-]{36}$/.test(entry.hostRunId), "RUN");
    hold(typeof entry.ownerGeneration === "string" &&
        /^[a-f0-9-]{36}$/.test(entry.ownerGeneration), "OWNER");
    if (entry.kind === "VALID") {
        hold(entry.abi === 4 && Number.isSafeInteger(entry.sequence) &&
            entry.sequence > 0, "VALID_SEQUENCE");
        hold(Number.isSafeInteger(entry.validityMask) &&
            entry.validityMask >= 0, "VALID_MASK");
    }
    if ("hostEvidence" in entry && entry.hostEvidence !== null) {
        const e = entry.hostEvidence;
        const obj = v => v !== null && typeof v === "object" && !Array.isArray(v);
        const exact = (v, keys) => obj(v) &&
            Object.keys(v).length === keys.length &&
            Object.keys(v).every(k => keys.includes(k));
        const num = v => Number.isSafeInteger(v) && v >= 0;
        hold(exact(e, ["initialized", "mutexIdle", "mutexQueued", "waitressPending",
            "diagnosticQuarantined", "srsp", "scope", "adapterQueuePending",
            "adapterClosing", "interpanLocked"]), "HOST_EVIDENCE_FIELDS");
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
    hold(data.length <= RECORD_LIMIT, "RECORD_SIZE");
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
