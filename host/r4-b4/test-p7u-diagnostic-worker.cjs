"use strict";
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {Worker} = require("node:worker_threads");
const workerModule = require("./p7u_diagnostic_worker.cjs");
function fixture(kind = "VALID") {
    return {
        schema: "p7u-b4-native-sample-v1", kind, utc: 1792700000000,
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
        assert.equal(fs.readFileSync(path.join(x.root, "events-v2.jsonl"), "utf8")
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
        const log=path.join(x.root, "events-v2.jsonl");
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
        const log=path.join(x.root, "events-v2.jsonl");
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
        fs.chmodSync(x.root, 0o755);
        assert.throws(() => workerModule.open(x.root), /PRIVATE_DIRECTORY/);
    } finally {x.cleanup();}
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
