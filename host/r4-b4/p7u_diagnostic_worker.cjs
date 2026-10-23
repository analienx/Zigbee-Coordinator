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
const allowed = new Set([
    "schema", "kind", "utc", "probeLatencyMs", "monotonicReceiveNs", "reason",
    "sourceAbi", "imageRuntimeAttested", "abi", "minor", "sequence", "validityMask",
    "srspDepth", "srspHighWater", "asyncDepth", "asyncHighWater", "srspEnqueued",
    "uartTxFinishedEvents", "radioEpochTag", "radioEpochHardwareVerified",
    "resetReason", "hostPackage", "firmwareSourceClaim", "failureClass",
    "submissionState", "timingQuality", "hostRunId", "ownerGeneration",
    "processUptimeMs"
]);
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");
const encode = (v) => Buffer.from(JSON.stringify(v) + "\n", "utf8");
const fail = (reason) => {throw Error("P7U_F2_WRITER_HOLD_" + reason);};
function hold(check, reason) {if (!check) fail(reason);}
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
    const md = path.join(dir, "manifest-v2.json");
    const log = path.join(dir, "events-v2.jsonl");
    hold(fs.existsSync(md) === fs.existsSync(log), "PARTIAL_INITIALIZATION");
    if (!fs.existsSync(md)) {
        const fd = fs.openSync(log, "wx", 0o600);
        try {fs.fsyncSync(fd);} finally {fs.closeSync(fd);}
        syncDir(dir);
        const m = manifestInit();
        atomicManifest(dir, m);
        return m;
    }
    hold(!fs.lstatSync(md).isSymbolicLink() && !fs.lstatSync(log).isSymbolicLink(),
        "SYMLINK");
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
function open(root) {
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
    return {root, manifest: recover(root)};
}
function commit(state, data) {
    const record = sameRecord(data);
    const current = state.manifest;
    const seq = current.sequence + 1;
    const frame = {seq, previous: current.head, data};
    const frameHash = sha(Buffer.from(JSON.stringify(frame)));
    const bytes = encode({...frame, sha: frameHash});
    hold(bytes.length < LIMIT - current.committedBytes, "CAPACITY");
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
    return {sequence: seq, sha256: frameHash, committedBytes: next.committedBytes};
}
if (!isMainThread) {
    let state;
    try {
        hold(workerData && workerData.schema === SCHEMA, "INIT_SCHEMA");
        state = open(workerData.root);
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
                parentPort.postMessage({type: "committed", id: message.id, receipt});
            } catch (e) {
                parentPort.postMessage({type: "fatal", reason: e.message});
                parentPort.removeAllListeners("message");
                process.exitCode = 3;
                parentPort.close();
            }
        });
    } else {
        parentPort.close();
    }
}
module.exports = {open, commit, sameRecord, recover, SCHEMA};
