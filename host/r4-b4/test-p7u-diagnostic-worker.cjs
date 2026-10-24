"use strict";
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {Worker} = require("node:worker_threads");
const {spawnSync} = require("node:child_process");
const crypto = require("node:crypto");
const workerModule = require("./p7u_diagnostic_worker.cjs");
function fixture(kind = "VALID") {
    return {
        schema: "p7u-b4-native-sample-v1", kind, utc: Date.now(),
        monotonicReceiveNs: "1234000000123",
        hostRunId: "8e2cdca6-17b6-4a4c-a951-a78742ad89e1",
        ownerGeneration: "28ca5f87-b319-4c93-93d3-23d0f46a316d",
        probeLatencyMs: 20,
        abi: 4, sequence: 1, validityMask: 0x2c
    };
}
function dir() {
    const parent = fs.mkdtempSync(path.join(os.tmpdir(), "p7u-writer-"));
    const root = path.join(parent, "p7u-b4-diagnostics");
    return {root, cleanup: () => fs.rmSync(parent, {recursive: true, force: true})};
}
function seedLegacy(root, rows) {
    fs.mkdirSync(root, {recursive: true, mode: 0o700});
    const manifest = {schema: workerModule.SCHEMA, generation: crypto.randomUUID(),
        sequence: 0, committedBytes: 0, head: "0".repeat(64),
        lastValidSeq: null, lastValidHostRun: null};
    const frames = [];
    for (const data of rows) {
        const frame = {seq: ++manifest.sequence, previous: manifest.head, data};
        manifest.head = crypto.createHash("sha256").update(JSON.stringify(frame)).digest("hex");
        frames.push(JSON.stringify({...frame, sha: manifest.head}) + "\n");
        if (data.kind === "VALID") {
            manifest.lastValidSeq = manifest.sequence;
            manifest.lastValidHostRun = data.hostRunId;
        }
    }
    const raw = frames.join("");
    manifest.committedBytes = Buffer.byteLength(raw);
    fs.writeFileSync(path.join(root, "events-v2.jsonl"), raw);
    fs.writeFileSync(path.join(root, "manifest-v2.json"), JSON.stringify(manifest) + "\n");
}
test("durable append+manifest replay with VALID and SKIPPED, no raw radio data", () => {
    const x = dir();
    try {
        const state = workerModule.open(x.root);
        const first = workerModule.commit(state, fixture());
        assert.equal(first.sequence, 1);
        const skipped = fixture("SKIPPED");
        delete skipped.abi; delete skipped.sequence; delete skipped.validityMask;
        skipped.reason = "BUSY_OTA";
        assert.equal(workerModule.commit(state, skipped).sequence, 2);
        const other = workerModule.open(x.root);
        assert.equal(other.manifest.lastValidSeq, 1);
        assert.equal(other.manifest.sequence, 2);
        assert.equal(fs.readFileSync(path.join(other.root, "events-v2.jsonl"), "utf8")
            .trim().split("\n").length, 2);
        assert.equal(fs.existsSync(path.join(x.root, "last-good.json")), false);
    } finally {x.cleanup();}
});
test("committed record with simulated lost ACK remains exactly one durable record", () => {
    const x=dir();
    try {
        const state=workerModule.open(x.root);
        workerModule.commit(state, fixture());
        const replay=workerModule.open(x.root);
        assert.equal(replay.manifest.sequence, 1);
        assert.equal(replay.manifest.lastValidSeq, 1);
    } finally {x.cleanup();}
});
test("worker death after log fsync before manifest is HOLD, never auto-truncated", () => {
    const x=dir();
    try {
        const state=workerModule.open(x.root);
        workerModule.commit(state, fixture());
        const log=path.join(state.root, "events-v2.jsonl");
        fs.appendFileSync(log, '{"partial":');
        const before=fs.readFileSync(log);
        assert.throws(() => workerModule.open(x.root), /ORPHANED_OR_TORN_SUFFIX/);
        assert.deepEqual(fs.readFileSync(log), before);
    } finally {x.cleanup();}
});
test("tampering with committed content fails chain verification", () => {
    const x=dir();
    try {
        const state=workerModule.open(x.root);
        workerModule.commit(state, fixture());
        const log=path.join(state.root, "events-v2.jsonl");
        const item=JSON.parse(fs.readFileSync(log, "utf8"));
        item.data.abi=5;
        fs.writeFileSync(log, JSON.stringify(item)+"\n");
        assert.throws(() => workerModule.open(x.root), /REPLAY_CHAIN|ORPHANED_OR_TORN_SUFFIX/);
    } finally {x.cleanup();}
});
test("private directory and records reject secrets and oversized events", () => {
    const x=dir();
    try {
        const state=workerModule.open(x.root);
        assert.throws(() => workerModule.commit(state, {...fixture(), ieeeAddr:"0x0123"}),
            /RECORD_FIELD/);
        assert.throws(() => workerModule.commit(state,
            {...fixture(), reason:"r".repeat(8192)}), /RECORD_SIZE/);
    } finally {x.cleanup();}
});

test("owned legacy directory becomes private while preserving v1 history", () => {
    const x = dir();
    try {
        fs.mkdirSync(x.root, {mode: 0o755});
        fs.chmodSync(x.root, 0o755);
        const old = Buffer.from('{"schema":"p7u-b4-native-history-v1","rows":[]}\n');
        fs.writeFileSync(path.join(x.root, "history.json"), old);
        workerModule.open(x.root);
        assert.equal(fs.statSync(x.root).mode & 0o777, 0o700);
        assert.deepEqual(fs.readFileSync(path.join(x.root, "history.json")), old);
    } finally {x.cleanup();}
});

test("a diagnostic directory symlink is rejected without changing its target", () => {
    const x = dir();
    const target = fs.mkdtempSync(path.join(os.tmpdir(), "p7u-untrusted-"));
    try {
        fs.chmodSync(target, 0o755);
        fs.symlinkSync(target, x.root);
        assert.throws(() => workerModule.open(x.root), /PRIVATE_DIRECTORY/);
        assert.equal(fs.statSync(target).mode & 0o777, 0o755);
    } finally {x.cleanup(); fs.rmSync(target, {recursive: true, force: true});}
});

test("retention rotates at 24h without new records and preserves v1 evidence", () => {
    const x = dir();
    try {
        const now = Date.now();
        const old = {...fixture(), utc: now - workerModule.RETENTION_MS + 2};
        seedLegacy(x.root, [old, {...fixture(), sequence: 2, utc: now}]);
        const legacy = Buffer.from('{"schema":"p7u-b4-native-history-v1","rows":[]}\n');
        fs.writeFileSync(path.join(x.root, "history.json"), legacy);
        const state = workerModule.open(x.root, now);
        const before = state.root;
        workerModule.expire(state, now + 3);
        assert.notEqual(state.root, before);
        assert.equal(fs.existsSync(before), false);
        assert.deepEqual(state.records.map(r => r.sequence), [2]);
        assert.deepEqual(workerModule.open(x.root, now + 3).records.map(r => r.sequence), [2]);
        assert.equal(fs.readdirSync(x.root).filter(n => n.startsWith("generation-")).length, 1);
        assert.deepEqual(fs.readFileSync(path.join(x.root, "history.json")), legacy);
    } finally {x.cleanup();}
});

test("ring saturates record count and byte bounds without disabling collection", () => {
    const x = dir();
    try {
        const now = Date.now();
        seedLegacy(x.root, Array.from({length: workerModule.COUNT_LIMIT}, (_, i) =>
            ({...fixture(), sequence: i + 1, utc: now})));
        const state = workerModule.open(x.root, now);
        workerModule.commit(state, {...fixture(), sequence: workerModule.COUNT_LIMIT + 1, utc: now}, now);
        assert.equal(state.records.length, workerModule.COUNT_LIMIT);
        assert.equal(state.records[0].sequence, 2);
        assert.ok(state.manifest.committedBytes <= workerModule.LIMIT);
        assert.equal(workerModule.open(x.root, now).manifest.sequence, workerModule.COUNT_LIMIT);
    } finally {x.cleanup();}
    const y = dir();
    try {
        const now = Date.now();
        const row = {...fixture(), reason: "r".repeat(2000), utc: now};
        const rows = [];
        // Leave less room than one frame while keeping the seeded legacy
        // log within the production 4MiB validation bound.
        let size = 0;
        for (let i = 1; ; i++) {
            const data = {...row, sequence: i};
            const frameSize = Buffer.byteLength(JSON.stringify({seq: i,
                previous: "0".repeat(64), data, sha: "0".repeat(64)}) + "\n");
            if (size + frameSize > workerModule.LIMIT) break;
            size += frameSize;
            rows.push(data);
        }
        const count = rows.length;
        seedLegacy(y.root, rows);
        const state = workerModule.open(y.root, now);
        workerModule.commit(state, {...row, sequence: count + 1}, now);
        assert.ok(state.manifest.committedBytes <= workerModule.LIMIT);
        assert.ok(state.records.length <= count);
        assert.equal(state.records.at(-1).sequence, count + 1);
        workerModule.open(y.root, now);
    } finally {y.cleanup();}
});

test("pointer rename failure preserves selected generation and never promotes orphan", () => {
    const x = dir();
    const original = fs.renameSync;
    try {
        const now = Date.now();
        const state = workerModule.open(x.root, now);
        workerModule.commit(state, {...fixture(), utc: now}, now);
        const pointer = fs.readFileSync(path.join(x.root, "current-v2.json"));
        const selected = state.root;
        fs.renameSync = (from, to) => {
            if (path.basename(to) === "current-v2.json") throw Error("synthetic pointer rename failure");
            return original(from, to);
        };
        assert.throws(() => workerModule.expire(state, now + workerModule.RETENTION_MS + 1),
            /synthetic pointer rename failure/);
        assert.deepEqual(fs.readFileSync(path.join(x.root, "current-v2.json")), pointer);
        assert.equal(workerModule.recover(selected).sequence, 1);
        assert.throws(() => workerModule.open(x.root, now), /ORPHANED_POINTER/);
    } finally {fs.renameSync = original; x.cleanup();}
});

test("missing selected generation files never become an empty replacement history", () => {
    const x = dir();
    try {
        const state = workerModule.open(x.root);
        fs.unlinkSync(path.join(state.root, "events-v2.jsonl"));
        fs.unlinkSync(path.join(state.root, "manifest-v2.json"));
        assert.throws(() => workerModule.open(x.root), /ACTIVE_HISTORY_MISSING/);
        assert.deepEqual(fs.readdirSync(state.root), []);
    } finally {x.cleanup();}
});

test("crash after pointer commit cleans only the explicitly retired generation", () => {
    const x = dir();
    const original = fs.unlinkSync;
    try {
        const now = Date.now();
        const state = workerModule.open(x.root, now);
        workerModule.commit(state, {...fixture(), utc: now}, now);
        const retired = state.root;
        fs.unlinkSync = file => {
            if (path.dirname(file) === retired) throw Error("synthetic retired cleanup failure");
            return original(file);
        };
        assert.throws(() => workerModule.expire(state, now + workerModule.RETENTION_MS + 1),
            /synthetic retired cleanup failure/);
        fs.unlinkSync = original;
        const pointer = JSON.parse(fs.readFileSync(path.join(x.root, "current-v2.json")));
        assert.equal(pointer.previous, path.basename(retired));
        assert.equal(workerModule.recover(path.join(x.root, pointer.active)).sequence, 0);
        assert.equal(workerModule.open(x.root, now + workerModule.RETENTION_MS + 1).manifest.sequence, 0);
        assert.equal(fs.existsSync(retired), false);
        assert.equal(fs.readdirSync(x.root).filter(n => n.startsWith("generation-")).length, 1);
    } finally {fs.unlinkSync = original; x.cleanup();}
});

test("Python verifier reads the actual worker-rotated pointer generation", () => {
    const x = dir();
    try {
        const now = Date.now();
        const state = workerModule.open(x.root, now);
        for (let i = 1; i <= 3; i++) {
            workerModule.commit(state, {...fixture(), utc: now, sequence: i,
                monotonicReceiveNs: String(i * 1000000000)}, now);
        }
        const python = spawnSync("python", [path.join(__dirname, "p7u_f2_acceptance.py"),
            "--history-dir", x.root], {encoding: "utf8"});
        assert.equal(python.status, 0, python.stderr || python.stdout);
        assert.equal(JSON.parse(python.stdout).protocol, "PASS");
    } finally {x.cleanup();}
});

test("worker expires history with no further IPC after sampling stops", async () => {
    const x = dir();
    const w = new Worker(path.join(__dirname, "p7u_diagnostic_worker.cjs"), {
        workerData: {schema: workerModule.SCHEMA, root: x.root}
    });
    try {
        await new Promise((resolve, reject) => {
            const timer = setTimeout(() => reject(Error("worker startup timeout")), 3000);
            w.once("message", message => {
                clearTimeout(timer);
                message.type === "ready" ? resolve() : reject(Error(message.reason));
            });
            w.once("error", reject);
        });
        await new Promise((resolve, reject) => {
            const timer = setTimeout(() => reject(Error("worker ACK timeout")), 3000);
            w.once("message", message => {
                clearTimeout(timer);
                message.type === "committed" ? resolve() : reject(Error(message.reason));
            });
            w.postMessage({type: "append", id: 1, record: {...fixture(),
                utc: Date.now() - workerModule.RETENTION_MS + 2000}});
        });
        const pointerBefore = fs.readFileSync(path.join(x.root, "current-v2.json"), "utf8");
        await new Promise(resolve => setTimeout(resolve, 2600));
        const pointerAfter = fs.readFileSync(path.join(x.root, "current-v2.json"), "utf8");
        assert.notEqual(pointerAfter, pointerBefore);
        const active = path.join(x.root, JSON.parse(pointerAfter).active);
        assert.equal(fs.readFileSync(path.join(active, "events-v2.jsonl"), "utf8"), "");
        assert.equal(JSON.parse(fs.readFileSync(path.join(active, "manifest-v2.json"))).sequence, 0);
    } finally {await w.terminate(); x.cleanup();}
});
test("actual worker thread delivers ACK only after read-back committed manifest", async () => {
    const x=dir();
    const w=new Worker(path.join(__dirname,"p7u_diagnostic_worker.cjs"), {
        workerData: {schema:"p7u-f2-worker-v2",root:x.root}
    });
    try {
        const ready=await new Promise((resolve,reject)=>{
            const timer=setTimeout(()=>reject(Error("worker startup timeout")),3000);
            w.once("message", m=>{clearTimeout(timer);m.type==="ready"?resolve(m):reject(Error(m.reason));});
            w.once("error",reject);
        });
        assert.equal(ready.sequence,0);
        const ack=await new Promise((resolve,reject)=>{
            const timer=setTimeout(()=>reject(Error("worker ACK timeout")),3000);
            w.once("message",m=>{clearTimeout(timer);m.type==="committed"?resolve(m):reject(Error(m.reason));});
            w.postMessage({type:"append",id:1,record:fixture()});
        });
        assert.equal(ack.receipt.sequence,1);
        assert.equal(workerModule.open(x.root).manifest.sequence,1);
    } finally {
        await w.terminate();
        x.cleanup();
    }
});
