"use strict";
// Real compiled pinned ZStackAdapter/Znp/Waitress; only UART and clock mocked.
const {test} = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const {performance} = require("node:perf_hooks");
const root = process.env.B4_HERDSMAN_ROOT;
if (!root || !path.isAbsolute(root) || !root.startsWith("/tmp/")) throw Error("compiled hosted source required");
const mod = p => require(path.join(root, "dist", p));
const {Znp} = mod("adapter/z-stack/znp/znp.js");
const {ZStackAdapter} = mod("adapter/z-stack/adapter/zStackAdapter.js");
const {Frame} = mod("adapter/z-stack/unpi/frame.js");
const {Type, Subsystem} = mod("adapter/z-stack/unpi/constants.js");
const F2_REPLY_MS = 20000;
const allowed = {enabled:true, hostIdle:true, otaActive:false, stillAllowed:()=>true};

function body(nonce, seq = 1) {
    const d = Buffer.alloc(160);
    d.write("R4D4"); d[4] = 4; d.writeUInt16LE(160, 6);
    d.writeUInt32LE(0x2c, 12); d.writeUInt32LE(seq, 28);
    d.writeUInt32LE(2, 44); nonce.copy(d, 132);
    d[156] = 255; d[157] = 1;
    return d;
}
async function flush() { for (let i = 0; i < 12; i++) await Promise.resolve(); }
function setup(t) {
    let clock = 100_000;
    t.mock.method(performance, "now", () => clock);
    t.mock.timers.enable({apis:["setTimeout"]});
    const znp = new Znp("/dev/never-opened", 115200, false);
    znp.initialized = true;
    const adapter = Object.create(ZStackAdapter.prototype);
    Object.assign(adapter, {znp, queue:{count:()=>0}, closing:false, interpanLock:false,
        b4DiagInFlight:false, b4NextAllowedMs:0});
    const sent = [];
    const passive = [];
    znp.b4SetHostTimeoutSink(e => passive.push(e));
    znp.unpiWriter.writeFrame = f => sent.push(f);
    const receive = (data, cmd = 242) => znp.onUnpiParsed(new Frame(Type.SRSP, Subsystem.SYS, cmd, data));
    const advance = async ms => {clock += ms; t.mock.timers.tick(ms); await flush();};
    const offer = () => adapter.b4ReadOnlyDiagnosticsV4(allowed);
    const progress = async () => {
        const p = znp.requestWithReply(Subsystem.SYS, "ping", {}, undefined, 6000);
        receive(Buffer.from([1, 0]), 1); await p;
    };
    const progressAF = async () => {
        const p = znp.requestWithReply(Subsystem.AF, "dataRequest", {
            dstaddr:0, destendpoint:1, srcendpoint:1, clusterid:6, transid:1,
            options:0, radius:30, len:0, data:Buffer.alloc(0),
        }, undefined, 6000);
        znp.onUnpiParsed(new Frame(Type.SRSP, Subsystem.AF, 1, Buffer.from([0])));
        await p;
    };
    return {znp, adapter, sent, passive, receive, advance, offer, progress, progressAF};
}

test("F2 delayed beyond the former6s deadline validates once through real transport", async t => {
    const h = setup(t); const p = h.offer();
    assert.equal(h.sent.length, 1);
    await h.advance(7900);
    h.receive(body(h.sent[0].data));
    assert.equal((await p).sequence, 1);
    assert.equal(h.znp.b4IsDiagPoisoned(), false);
    assert.equal(h.znp.waitress.waiters.size, 0);
});

test("F2 never resubmits without both cooldown and matched production SRSP progress", async t => {
    const h = setup(t); const p = h.offer(); await h.advance(F2_REPLY_MS);
    assert.equal(await p, undefined);
    assert.equal(h.adapter.b4GetV4Outcome().reason, "F2_REPLY_TIMEOUT");
    assert.deepEqual(h.passive, [], "a diagnostic is not a production SYS timeout");
    assert.equal(h.znp.waitress.waiters.size, 0);
    assert.equal(h.znp.b4CanProbeV4(), false); // F2 cooldown held
    assert.equal(h.znp.b4CanProbe(), true); // legacy F0 isn't coupled to F2 cooldown
    assert.equal(await h.offer(), undefined);
    assert.equal(h.adapter.b4GetV4Outcome().reason, "F2_TIMEOUT_COOLDOWN");
    await h.advance(60_001);
    // An unsolicited or stale SYS response is not matched production progress.
    h.receive(Buffer.from([1,0]), 1);
    assert.equal(await h.offer(), undefined);
    assert.equal(h.adapter.b4GetV4Outcome().reason, "F2_OWNER_PROGRESS_REQUIRED");
    assert.equal(h.sent.filter(f => f.commandID === 242).length, 1);
    await h.progress();
    const next = h.offer(); const f = h.sent.at(-1);
    h.receive(body(f.data, 2));
    assert.equal((await next).sequence, 2);
    assert.equal(h.znp.b4F2ConsecutiveTimeouts, 0);
});

test("matched production progress alone cannot shorten the timeout cooldown", async t => {
    const h = setup(t); const p = h.offer(); await h.advance(F2_REPLY_MS); await p;
    await h.progress(); await h.advance(59_999);
    assert.equal(await h.offer(), undefined);
    assert.equal(h.adapter.b4GetV4Outcome().reason, "F2_TIMEOUT_COOLDOWN");
    assert.equal(h.sent.filter(f => f.commandID === 242).length, 1);
});

test("active AF owns the mutex: F2 skips without queueing or writing", async t => {
    const h = setup(t);
    const p = h.znp.requestWithReply(Subsystem.AF, "dataRequest", {
        dstaddr:0, destendpoint:1, srcendpoint:1, clusterid:6, transid:1,
        options:0, radius:30, len:0, data:Buffer.alloc(0),
    }, undefined, 6000);
    assert.equal(await h.offer(), undefined);
    assert.equal(h.znp.queue.count, 0);
    assert.equal(h.sent.length, 1);
    assert.equal(h.sent[0].subsystem, Subsystem.AF);
    h.znp.onUnpiParsed(new Frame(Type.SRSP, Subsystem.AF, 1, Buffer.from([0])));
    await p;
});

test("old nonce response cannot consume a newer request waiter", async t => {
    const h = setup(t); const old = h.offer(); const a = Buffer.from(h.sent[0].data);
    await h.advance(F2_REPLY_MS); await old; await h.advance(60_001); await h.progress();
    const current = h.offer(); const b = Buffer.from(h.sent.at(-1).data);
    assert.notDeepEqual(a, b);
    h.receive(body(a, 1)); await flush();
    assert.equal(h.znp.waitress.waiters.size, 1, "late response must leave current waiter active");
    h.receive(body(b, 2));
    assert.equal((await current).sequence, 2);
    assert.equal(h.znp.waitress.waiters.size, 0);
});

test("three consecutive lost F2 replies hard-quarantine diagnostics but ordinary SYS stays live", async t => {
    const h = setup(t);
    for (let i = 0; i < 3; i++) {
        const p = h.offer(); await h.advance(F2_REPLY_MS); await p;
        if (i !== 2) {await h.advance(60_001); await h.progress();}
    }
    assert.equal(h.adapter.b4GetV4Outcome().reason, "F2_TIMEOUT_BUDGET_EXHAUSTED");
    assert.equal(h.znp.b4IsDiagPoisoned(), true);
    assert.equal(h.znp.waitress.waiters.size, 0);
    for (let i = 0; i < 5; i++) {
        await h.advance(60_001);
        if (i % 2) await h.progressAF(); else await h.progress();
        assert.equal(await h.offer(), undefined);
        assert.equal(h.adapter.b4GetV4Outcome().kind, "QUARANTINED");
    }
    assert.equal(h.sent.filter(f => f.commandID === 242).length, 3);
    assert.deepEqual(h.passive, []);
});

test("correct nonce with invalid canonical body permanently quarantines without retry", async t => {
    const h = setup(t); const p = h.offer(); const d = body(h.sent[0].data); d[4] = 3;
    h.receive(d); assert.equal(await p, undefined);
    assert.equal(h.adapter.b4GetV4Outcome().reason, "INVALID_NATIVE_RESPONSE");
    await h.advance(60_001); await h.progress();
    assert.equal(await h.offer(), undefined);
    assert.equal(h.adapter.b4GetV4Outcome().kind, "QUARANTINED");
    assert.equal(h.sent.filter(f => f.commandID === 242).length, 1);
});

test("F2 timeout does not suppress a genuine production SYS timeout", async t => {
    const h = setup(t); let p = h.offer(); await h.advance(F2_REPLY_MS); await p;
    p = h.znp.requestWithReply(Subsystem.SYS, "ping", {}, undefined, 6000);
    const rejected = assert.rejects(p, /SRSP - SYS - ping after 6000ms/);
    await h.advance(6000); await rejected;
    assert.deepEqual(h.passive.map(e => e.kind), ["SYS_SREQ_TIMEOUT"]);
});

test("F0 remains permanently quarantined after one ambiguous timeout", async t => {
    const h = setup(t);
    const p = h.znp.requestWithReply(Subsystem.SYS, "r4DiagReadOnly", {}, undefined, 6000);
    const rejected = assert.rejects(p, /after 6000ms/); await h.advance(6000); await rejected;
    await h.advance(60_001); await h.progress();
    await assert.rejects(h.znp.requestWithReply(Subsystem.SYS, "r4DiagReadOnly", {}, undefined, 6000), /poisoned/);
    assert.equal(h.sent.filter(f => f.commandID === 240).length, 1);
    assert.deepEqual(h.passive, []);
});

test("seeded 1000-cycle soak: loss, late/out-of-order replies and ordinary traffic share one owner", async t => {
    const h = setup(t); let seed = 0x72e4; let seq = 0; let dropped = null;
    const random = () => {seed = (Math.imul(seed,1664525) + 1013904223) >>> 0; return seed;};
    let successes = 0; let failures = 0;
    for (let i = 0; i < 1000; i++) {
        await h.advance(60_001);
        if (i % 2) await h.progressAF(); else await h.progress();
        const pending = h.offer(); const nonce = Buffer.from(h.sent.at(-1).data); seq++;
        if (dropped !== null) {
            h.receive(body(dropped.nonce, dropped.seq));
            assert.equal(h.znp.waitress.waiters.size, 1);
            dropped = null;
        }
        // At most two consecutive lost replies: this soak exercises recovery,
        // while the independent budget test exercises terminal quarantine.
        const lose = random() % 7 === 0 && h.znp.b4F2ConsecutiveTimeouts < 2;
        if (lose) {
            await h.advance(F2_REPLY_MS); assert.equal(await pending, undefined);
            dropped = {nonce,seq}; failures++;
        } else {
            await h.advance(random() % 5000);
            h.receive(body(nonce, seq)); assert.equal((await pending).sequence, seq); successes++;
        }
        assert.equal(h.znp.waitress.waiters.size, 0);
        assert.equal(h.znp.queue.isIdle(), true);
        assert.equal(h.znp.queue.count, 0);
        assert.equal(h.znp.b4IsDiagPoisoned(), false);
    }
    assert.ok(successes > 700); assert.ok(failures > 50);
    assert.equal(h.sent.filter(f => f.commandID === 242).length, 1000);
    assert.equal(h.sent.filter(f => f.commandID === 1 && f.subsystem === Subsystem.SYS).length, 500);
    assert.equal(h.sent.filter(f => f.commandID === 1 && f.subsystem === Subsystem.AF).length, 500);
    assert.deepEqual(h.passive, []);
});

test("busy ZNP mutex has a precise admission reason; no additional diagnostic frame", async t => {
    const h = setup(t);
    let release;
    const busy = h.znp.queue.run(() => new Promise(resolve => {release = resolve;}));
    assert.equal(h.znp.b4GetPassiveOwnerMetrics().mutexIdle, false);
    const count = h.sent.length;
    assert.equal(await h.offer(), undefined);
    assert.equal(h.adapter.b4GetV4Outcome().reason, "ZNP_MUTEX_BUSY");
    assert.equal(h.sent.length, count, "no F2 wire request may follow busy admission");
    release();
    await busy;
});
test("pending Waitress gate distinct from mutex and never writes an F2", async t => {
    const h = setup(t);
    const waiter = h.znp.waitress.waitFor({type:Type.SRSP,subsystem:Subsystem.SYS,command:"ping"},10000);
    const count = h.sent.length;
    assert.equal(await h.offer(), undefined);
    assert.equal(h.adapter.b4GetV4Outcome().reason, "ZNP_WAITRESS_PENDING");
    assert.equal(h.znp.b4GetPassiveOwnerMetrics().waitressPending, 1);
    assert.equal(h.sent.length, count);
    h.znp.waitress.remove(waiter.ID);
});
test("no-wire passive ack/timeout accounting distinguishes AF from SYS and F2", async t => {
    const h = setup(t);
    const before = h.znp.b4GetPassiveOwnerMetrics();
    assert.deepEqual(before.srsp.AF, {ok:0,timeout:0,maxLatencyMs:0,lastLatencyMs:null});
    await h.progressAF();
    const p = h.znp.requestWithReply(Subsystem.SYS, "ping", {}, undefined, 6000);
    const rejected = assert.rejects(p, /SRSP - SYS - ping after 6000ms/);
    await h.advance(6000); await rejected;
    const after = h.znp.b4GetPassiveOwnerMetrics();
    assert.equal(after.srsp.AF.ok,1);
    assert.equal(after.srsp.SYS.timeout,1);
    assert.equal(after.srsp.SYS.ok,0);
    assert.equal(after.srsp.AF.timeout,0);
    const f2 = h.offer();await h.advance(F2_REPLY_MS);await f2;
    const afterF2 = h.znp.b4GetPassiveOwnerMetrics();
    assert.equal(afterF2.srsp.SYS.timeout,1,"F2 timeout must not inflate production SYS statistics");
    assert.equal(afterF2.srsp.AF.ok,1);
    assert.equal(afterF2.scope,"HOST_OWNER_LIFETIME_ONLY");
});
test("gating across adapter owner/OTA and outer pending queue has no extra ZNP submissions", async t => {
    const h = setup(t);
    for (const [input,expected] of [
        [{...allowed,hostIdle:false},"HOST_NOT_IDLE"],
        [{...allowed,otaActive:true},"OTA_ACTIVE_OR_UNKNOWN"],
        [{...allowed,stillAllowed:()=>false},"OWNER_OR_OTA_GUARD_REVOKED"],
    ]) {
        assert.equal(await h.adapter.b4ReadOnlyDiagnosticsV4(input),undefined);
        assert.equal(h.adapter.b4GetV4Outcome().reason,expected);
    }
    h.adapter.queue={count:()=>2};
    assert.equal(await h.offer(),undefined);
    assert.equal(h.adapter.b4GetV4Outcome().reason,"ADAPTER_QUEUE_PENDING");
    assert.equal(h.sent.length,0);
});
