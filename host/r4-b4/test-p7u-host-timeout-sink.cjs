"use strict";
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {spawnSync} = require("node:child_process");
const {Worker} = require("node:worker_threads");
const {createHostTimeoutSink} = require("./p7u_host_timeout_sink.cjs");
const journal = require("./p7u_diagnostic_worker.cjs");
const root = process.env.B4_HERDSMAN_ROOT;
assert.ok(root && root.startsWith("/tmp/"), "GitHub-hosted real compiled pinned herdsman required");
const {Znp} = require(path.join(root, "dist/adapter/z-stack/znp/znp.js"));
const {Subsystem} = require(path.join(root, "dist/adapter/z-stack/unpi/constants.js"));
const {ZStackAdapter} = require(path.join(root, "dist/adapter/z-stack/adapter/zStackAdapter.js"));
const {Controller} = require(path.join(root, "dist/controller/controller.js"));
const hostRunId = "8e2cdca6-17b6-4a4c-a951-a78742ad89e1";
const ownerGeneration = "28ca5f87-b319-4c93-93d3-23d0f46a316d";
const event = {at_ms: 10, kind: "AF_SREQ_TIMEOUT", dropped: 0};

test("first timeout per subsystem only, passive and bounded, disabled means no evidence", () => {
    const rows = [];
    let enabled = false;
    const sink = createHostTimeoutSink(row => rows.push(row), () => enabled);
    sink(event);assert.equal(rows.length, 0);
    enabled = true;
    for (let i = 0; i < 1000; i++) sink({...event, at_ms: i});
    assert.equal(rows.length, 1);
    assert.equal(rows[0].submissionState, "NO_DIAGNOSTIC_REQUEST");
    assert.equal(rows[0].kind, "FAILED");
    assert.equal(rows[0].hostTimeoutKind, "AF_SREQ_TIMEOUT");
    assert.equal("validityMask" in rows[0], false);
    for (const kind of ["ZDO_SREQ_TIMEOUT", "SYS_SREQ_TIMEOUT", "UTIL_SREQ_TIMEOUT"]) sink({...event, kind});
    assert.equal(rows.length, 4);
});

test("reject raw error, unknown fields, unknown subsystem and invalid monotonic fields", () => {
    let count = 0;
    const sink = createHostTimeoutSink(() => count++, () => true);
    for (const bad of [{...event, raw: "secret synthetic packet"}, {...event, kind: "OTHER"},
                       {...event, at_ms: -1}, {...event, dropped: NaN}, {...event, at_ms: 1.5}]) {
        assert.throws(() => sink(bad), /HOST_TIMEOUT_EVENT_INVALID/);
    }
    assert.equal(count, 0);
});

test("ambiguous IPC is never retried for the same subsystem", () => {
    let calls = 0;
    const sink = createHostTimeoutSink(() => {calls++;throw Error("synthetic missing ACK");}, () => true);
    assert.throws(() => sink(event), /missing ACK/);
    sink(event);assert.equal(calls, 1);
});

test("actual compiled ZNP observes genuine Waitress timeout; callback failures preserve production error", async () => {
    const znp = new Znp("/dev/never-opened", 115200, false);
    znp.initialized = true;
    const writes = [];
    const rows = [];
    znp.unpiWriter.writeFrame = frame => writes.push(frame.commandID);
    znp.b4SetHostTimeoutSink(createHostTimeoutSink(row => {rows.push(row);throw Error("worker failed");}, () => true));
    await assert.rejects(znp.requestWithReply(Subsystem.SYS, "ping", {}, undefined, 15), /^Error: SRSP - SYS - ping after 15ms$/);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].hostTimeoutKind, "SYS_SREQ_TIMEOUT");
    assert.deepEqual(writes, [1], "no F0/F2/reset command was sent");
    znp.b4SetHostTimeoutSink(undefined);
    await assert.rejects(znp.requestWithReply(Subsystem.SYS, "ping", {}, undefined, 15));
    assert.equal(rows.length, 1);
    assert.deepEqual(writes, [1, 1]);
});

test("worker validates passive timeout shape without fabricating a native counter", () => {
    const rows = [];
    createHostTimeoutSink(row => rows.push({...row, hostRunId, ownerGeneration}), () => true)(event);
    assert.doesNotThrow(() => journal.sameRecord(rows[0]));
    for (const change of [{hostTimeoutKind: "OTHER"}, {hostTimeoutDropped: -1},
                           {kind: "VALID"}, {submissionState: "SENT"}]) {
        assert.throws(() => journal.sameRecord({...rows[0], ...change}), /HOST_TIMEOUT_RECORD|VALID_SEQUENCE/);
    }
});

test("real owner timeout -> sink -> actual worker fsync -> verified history: old F2 samples cannot pass across failure", async () => {
    const parent = fs.mkdtempSync(path.join(os.tmpdir(), "p7u-passive-timeout-"));
    const history = path.join(parent, "p7u-b4-diagnostics");
    const state = journal.open(history);
    for (let i = 1; i <= 3; i++) journal.commit(state, {schema: "synthetic-test", kind: "VALID", utc: Date.now(),
        monotonicReceiveNs: String(i), abi: 4, sequence: i, validityMask: 0x2c, hostRunId, ownerGeneration});
    const worker = new Worker(path.join(__dirname, "p7u_diagnostic_worker.cjs"), {
        workerData: {schema: journal.SCHEMA, root: history}});
    const waitMessage = type => new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(Error("worker timeout")), 3000);
        worker.once("message", msg => {clearTimeout(timer);msg.type === type ? resolve(msg) : reject(Error(msg.reason || msg.type));});
        worker.once("error", reject);
    });
    try {
        await waitMessage("ready");
        const ack = waitMessage("committed");
        const znp = new Znp("/dev/never-opened", 115200, false);
        znp.initialized = true;
        const writes = [];
        znp.unpiWriter.writeFrame = frame => writes.push(frame.commandID);
        const adapter = Object.create(ZStackAdapter.prototype);
        adapter.znp = znp;
        const controller = Object.create(Controller.prototype);
        controller.adapter = adapter;
        controller.b4SetHostTimeoutSinkFromExistingOwner(createHostTimeoutSink(record => worker.postMessage({type: "append", id: 1,
            record: {...record, hostRunId, ownerGeneration}}), () => true));
        await assert.rejects(znp.requestWithReply(Subsystem.SYS, "ping", {}, undefined, 15), /SRSP - SYS - ping after 15ms/);
        assert.equal((await ack).receipt.sequence, 4);
        const recovered = journal.open(history);
        assert.equal(recovered.records.length, 4);
        assert.equal(recovered.records[3].hostTimeoutKind, "SYS_SREQ_TIMEOUT");
        assert.equal(recovered.records[3].kind, "FAILED");
        assert.equal(recovered.manifest.lastValidSeq, 3, "preserved last-good samples remain distinguishable from failure");
        const verdict = spawnSync("python", [path.join(__dirname, "p7u_f2_acceptance.py"), "--history-dir", history], {encoding: "utf8"});
        assert.equal(verdict.status, 0, verdict.stderr || verdict.stdout);
        assert.equal(JSON.parse(verdict.stdout).protocol, "INSUFFICIENT");
        assert.deepEqual(writes, [1]);
    } finally {
        await worker.terminate();
        fs.rmSync(parent, {recursive: true, force: true});
    }
});
