/* Actual compiled pinned herdsman 10.9.1 classes, simulated input only.
 * Run AFTER host/r4-b4/herdsman_overlay.py and "pnpm run build".
 * No serial/USB/host integration is opened by this test.
 */
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const root = process.env.B4_HERDSMAN_ROOT;
if (!root || !path.isAbsolute(root) || !root.startsWith("/tmp/")) {
    throw new Error("disposable pinned checkout absolute /tmp path required");
}
function mod(p) { return require(path.join(root, "dist", ...p.split("/"))); }
const {ZpiObject} = mod("adapter/z-stack/znp/zpiObject.js");
const {Znp} = mod("adapter/z-stack/znp/znp.js");
const {ZStackAdapter} = mod("adapter/z-stack/adapter/zStackAdapter.js");
const {Frame} = mod("adapter/z-stack/unpi/frame.js");
const {Type, Subsystem} = mod("adapter/z-stack/unpi/constants.js");

function frame() {
    const data = Buffer.alloc(132);
    data.write("R4D3", 0, "ascii");
    data.writeUInt8(3, 4);
    data.writeUInt16LE(132, 6);
    data.writeUInt32LE(0x10, 12);
    data.writeUInt32LE(8, 28);
    data.writeUInt32LE(0xffffffff, 48);
    return data;
}
function fakeOwner(data = frame()) {
    let calls = 0;
    const owner = Object.create(ZStackAdapter.prototype);
    owner.queue = {count() { return 0; }};
    owner.closing = false;
    owner.interpanLock = false;
    owner.b4DiagInFlight = false;
    owner.b4NextAllowedMs = 0;
    owner.znp = {
        poisoned: false,
        b4CanProbe() {return !this.poisoned;},
        b4PoisonDiagSession() {this.poisoned = true;},
        async requestWithReply(system, command, payload, waiterID, timeout) {
            calls++;
            assert.equal(system, Subsystem.SYS);
            assert.equal(command, "r4DiagReadOnly");
            assert.deepEqual(payload, {});
            assert.equal(timeout, 1200);
            return {payload: {diagnostic: data}};
        },
    };
    return {owner, calls() {return calls;}};
}
const allow = {enabled: true, hostIdle: true, otaActive: false};

test("D03/D04: real ZpiObject understands fixed 132-byte SYS F0 response", () => {
    const packet = new Frame(Type.SRSP, Subsystem.SYS, 240, frame()).toBuffer();
    const unpi = Frame.fromBuffer(132, packet.length - 1, packet);
    const object = ZpiObject.fromUnpiFrame(unpi);
    assert.equal(object.command.name, "r4DiagReadOnly");
    assert.equal(object.payload.diagnostic.length, 132);
    const bad = Buffer.from(packet);
    bad[bad.length - 1] ^= 1;
    assert.throws(() => Frame.fromBuffer(132, bad.length - 1, bad), /checksum/);
    assert.throws(() => ZpiObject.fromUnpiFrame(
        new Frame(Type.SRSP, Subsystem.SYS, 240, Buffer.alloc(131))
    ));
});

test("D18/D24: all stock/OTA/busy/default-disabled controls send zero requests", async () => {
    const {owner, calls} = fakeOwner();
    for (const opts of [
        {enabled: false, hostIdle: true, otaActive: false},
        {enabled: true, hostIdle: false, otaActive: false},
        {enabled: true, hostIdle: true, otaActive: true},
    ]) assert.equal(await owner.b4ReadOnlyDiagnostics(opts), undefined);
    owner.queue = {count() {return 2;}};
    assert.equal(await owner.b4ReadOnlyDiagnostics(allow), undefined);
    owner.queue = {count() {return 0;}};
    owner.closing = true;
    assert.equal(await owner.b4ReadOnlyDiagnostics(allow), undefined);
    owner.closing = false;
    owner.interpanLock = true;
    assert.equal(await owner.b4ReadOnlyDiagnostics(allow), undefined);
    assert.equal(calls(), 0);
});

test("D04/D08/D11: strict validity, no radio epoch, max u32 not unknown", async () => {
    const {owner, calls} = fakeOwner();
    const sample = await owner.b4ReadOnlyDiagnostics(allow);
    assert.deepEqual(sample, {
        abi: 3, validityMask: 0x10, srspEnqueued: 0xffffffff,
        sequence: 8, radioEpoch: "UNKNOWN",
    });
    assert.equal(calls(), 1);
    assert.equal(await owner.b4ReadOnlyDiagnostics(allow), undefined); // 30s cooldown
    assert.equal(calls(), 1);
});

test("D05/D07: malformed or unauthorized counter coverage rejected", async () => {
    const variants = [
        (x) => x.writeUInt32LE(0x11, 12),
        (x) => x.writeUInt32LE(1, 8),
        (x) => x.writeBigUInt64LE(13n, 16),
        (x) => x.writeUInt32LE(3, 24),
        (x) => x.write("FAKE", 0),
        (x) => x.writeUInt8(4, 4),
        (x) => x.writeUInt8(8, 5),
        (x) => x.writeUInt16LE(131, 6),
    ];
    for (const mutate of variants) {
        const data = frame();
        mutate(data);
        const {owner} = fakeOwner(data);
        assert.equal(await owner.b4ReadOnlyDiagnostics(allow), undefined);
    }
    const {owner} = fakeOwner(Buffer.alloc(102));
    assert.equal(await owner.b4ReadOnlyDiagnostics(allow), undefined);
});

test("D17/D22/D23: concurrent probes coalesce, no second serial owner", async () => {
    const {owner} = fakeOwner();
    let resolve;
    let calls = 0;
    owner.znp.requestWithReply = async () => {
        calls++;
        return new Promise(r => {resolve = r;});
    };
    const first = owner.b4ReadOnlyDiagnostics(allow);
    assert.equal(await owner.b4ReadOnlyDiagnostics(allow), undefined);
    assert.equal(calls, 1);
    resolve({payload: {diagnostic: frame()}});
    const finished = await first;
    assert.equal(finished.radioEpoch, "UNKNOWN");
    assert.equal(calls, 1);
    assert.ok(Znp.prototype.request);
    assert.equal(typeof ZStackAdapter.prototype.b4ReadOnlyDiagnostics, "function");
});

test("D22: SRSP timeout never initiates retry or leaks a caller exception", async () => {
    const {owner} = fakeOwner();
    let calls = 0;
    owner.znp.requestWithReply = async () => {
        calls++;
        throw new Error("synthetic MT timeout");
    };
    assert.equal(await owner.b4ReadOnlyDiagnostics(allow), undefined);
    assert.equal(await owner.b4ReadOnlyDiagnostics(allow), undefined);
    assert.equal(calls, 1);
});

test("D17: real ZNP mutex rejects diagnosis while active, even with zero pending waiters", async () => {
    const znp = new Znp("/dev/never-opened-by-test", 115200, false);
    assert.equal(znp.b4CanProbe(), false); // not initialized
    znp.initialized = true; // test-only: simulate established existing owner
    assert.equal(znp.b4CanProbe(), true);
    let release;
    const active = znp.queue.run(() => new Promise(r => {release = r;}));
    assert.equal(znp.queue.count, 0); // no *queued* work, but LOCK IS HELD
    assert.equal(znp.b4CanProbe(), false);
    const {owner, calls} = fakeOwner();
    owner.znp.b4CanProbe = () => znp.b4CanProbe();
    assert.equal(await owner.b4ReadOnlyDiagnostics(allow), undefined);
    assert.equal(calls(), 0);
    release();
    await active;
    assert.equal(znp.b4CanProbe(), true);
    assert.ok(await owner.b4ReadOnlyDiagnostics(allow));
});

test("D01/D03/D04: real Znp.request/Waitress routes ping and SYS F0 over the one writer", async () => {
    const znp = new Znp("/dev/never-opened-by-test", 115200, false);
    znp.initialized = true; // no SerialPort.asyncOpen: source-compiled in-memory test
    const commands = [];
    znp.unpiWriter.writeFrame = (request) => {
        commands.push(request.commandID);
        const body = request.commandID === 1 ? Buffer.from([0x01, 0x00]) : frame();
        queueMicrotask(() => znp.onUnpiParsed(new Frame(Type.SRSP, Subsystem.SYS, request.commandID, body)));
    };
    const [ping, f0] = await Promise.all([
        znp.requestWithReply(Subsystem.SYS, "ping", {}, undefined, 300),
        znp.requestWithReply(Subsystem.SYS, "r4DiagReadOnly", {}, undefined, 300),
    ]);
    assert.deepEqual(commands, [1, 240]);
    assert.equal(ping.payload.capabilities, 1);
    assert.equal(f0.payload.diagnostic.length, 132);
    assert.equal(f0.payload.diagnostic.readUInt32LE(48), 0xffffffff);
    assert.equal(znp.b4CanProbe(), true);
    assert.equal(znp.waitress.waiters.size, 0);
});

test("D22: genuine timed-out F0 waiter is removed and does not leak or retry", async () => {
    const znp = new Znp("/dev/never-opened-by-test", 115200, false);
    znp.initialized = true;
    let writes = 0;
    znp.unpiWriter.writeFrame = () => {writes++;}; // deliberately unresponsive radio
    await assert.rejects(znp.requestWithReply(Subsystem.SYS, "r4DiagReadOnly", {}, undefined, 15));
    assert.equal(writes, 1);
    assert.equal(znp.waitress.waiters.size, 0);
    // Timeout cannot authorize a subsequent transaction-ID-less probe.
    assert.equal(znp.b4CanProbe(), false);
    assert.equal(znp.b4DiagPoisoned, true);
});

test("D14/D16/D19/D30: exact Waitress timeout only, bounded privacy-safe host forensic ring", async () => {
    const znp = new Znp("/dev/not-opened", 115200, false);
    znp.initialized = true; // simulated; no OS serial access
    znp.unpiWriter.writeFrame = () => {}; // force genuine Waitress timeout
    await assert.rejects(znp.requestWithReply(Subsystem.SYS, "ping", {}, undefined, 15));
    assert.equal(znp.b4ReadPassiveForensics().recent_events.length, 0); // opt-in default off
    znp.b4EnablePassiveForensics(true);
    await assert.rejects(znp.requestWithReply(Subsystem.SYS, "ping", {}, undefined, 15));
    let receipt = znp.b4ReadPassiveForensics();
    assert.equal(receipt.recent_events.length, 1);
    assert.deepEqual(Object.keys(receipt.recent_events[0]).sort(), ["at_ms","kind"]);
    assert.equal(receipt.recent_events[0].kind, "SYS_SREQ_TIMEOUT");
    assert.equal(receipt.radio_epoch, "UNKNOWN");
    // A different Error, e.g. UART writer failure, never becomes an SRSP timeout.
    znp.b4RecordHostSreqTimeout(Subsystem.SYS, "ping", 15, new Error("UART detached"));
    assert.equal(znp.b4ReadPassiveForensics().recent_events.length, 1);
    // No unbounded accumulation, no raw packets or device identifiers in output.
    for (let i = 0; i < 300; i++) {
        znp.b4RecordHostSreqTimeout(Subsystem.AF, "dataRequest", 15,
                                  new Error("SRSP - AF - dataRequest after 15ms"));
    }
    receipt = znp.b4ReadPassiveForensics();
    assert.equal(receipt.recent_events.length, 256);
    assert.ok(receipt.dropped >= 45);
    assert.equal(JSON.stringify(receipt).includes("network_key"), false);
    assert.equal(JSON.stringify(receipt).includes("waiter_id"), false);
    assert.equal(JSON.stringify(receipt).includes("/dev/"), false);
    znp.b4EnablePassiveForensics(false);
    assert.equal(znp.b4ReadPassiveForensics().recent_events.length, 0);
    assert.equal(znp.b4ReadPassiveForensics().dropped, 0);
});

test("D24/D30: adapter exposes only explicit sanitized opt-in owner forensics", () => {
    const adapter = Object.create(ZStackAdapter.prototype);
    adapter.znp = new Znp("/dev/not-opened", 115200, false);
    adapter.b4SetPassiveHostForensics(true);
    adapter.znp.b4RecordHostSreqTimeout(Subsystem.ZDO, "permitJoin", 100,
                                     new Error("SRSP - ZDO - permitJoin after 100ms"));
    const view = adapter.b4GetPassiveHostForensics();
    assert.equal(view.schema, "r4-b4-inprocess-host-sreq-v1");
    assert.deepEqual(view.recent_events.map(x=>x.kind), ["ZDO_SREQ_TIMEOUT"]);
    assert.equal(view.radio_epoch, "UNKNOWN");
    adapter.b4SetPassiveHostForensics(false);
    assert.equal(adapter.b4GetPassiveHostForensics().recent_events.length, 0);
    assert.equal(Object.keys(view).some(key=>/pan|ieee|network|serial|payload|key/i.test(key)), false);
});

test("D17/D18: 200 concurrent diagnostic offers coalesce while stock SYS requests keep single-owner order", async () => {
    const {owner} = fakeOwner();
    let diagnostics = 0;
    let resolve;
    owner.znp.requestWithReply = async () => {
        diagnostics++;
        return new Promise(r => {resolve = r;});
    };
    const first = owner.b4ReadOnlyDiagnostics(allow);
    const burst = await Promise.all(Array.from({length: 200}, () => owner.b4ReadOnlyDiagnostics(allow)));
    assert.ok(burst.every(x => x === undefined));
    assert.equal(diagnostics, 1);
    resolve({payload:{diagnostic:frame()}});
    assert.equal((await first).srspEnqueued, 0xffffffff);
    assert.equal(await owner.b4ReadOnlyDiagnostics(allow), undefined);
    assert.equal(diagnostics, 1);

    const znp = new Znp("/dev/never-opened", 115200, false);
    znp.initialized = true;  // mock already-existing owner; no actual port opened
    const issued = [];
    znp.unpiWriter.writeFrame = (request) => {
        issued.push(request.commandID);
        queueMicrotask(() => znp.onUnpiParsed(
            new Frame(Type.SRSP, Subsystem.SYS, request.commandID, Buffer.from([1,0]))
        ));
    };
    const pings = await Promise.all(Array.from({length: 40},
        () => znp.requestWithReply(Subsystem.SYS, "ping", {}, undefined, 300)));
    assert.equal(issued.length, 40);
    assert.ok(issued.every(code => code === 1)); // no extra diagnostic traffic
    assert.ok(pings.every(response => response.payload.capabilities === 1));
    assert.equal(znp.waitress.waiters.size, 0);
});

test("REVIEW-P0: real diagnostic timeout permanently quarantines ambiguous F0; ordinary SYS ping unaffected", async () => {
    const znp = new Znp("/dev/no-serial", 115200, false);
    znp.initialized = true;
    const writes = [];
    znp.unpiWriter.writeFrame = (request) => {
        writes.push(request.commandID);
        if (request.commandID === 1) {
            queueMicrotask(() => znp.onUnpiParsed(
                new Frame(Type.SRSP, Subsystem.SYS, request.commandID, Buffer.from([1, 0]))
            ));
        }
    };
    await assert.rejects(znp.requestWithReply(Subsystem.SYS, "r4DiagReadOnly", {}, undefined, 15));
    assert.equal(znp.b4CanProbe(), false);
    assert.equal(znp.b4DiagPoisoned, true);
    assert.equal(znp.waitress.waiters.size, 0);
    await assert.rejects(znp.requestWithReply(Subsystem.SYS, "r4DiagReadOnly", {}, undefined, 15), /poisoned/);
    assert.deepEqual(writes, [240]); // never transmit second F0
    const ping = await znp.requestWithReply(Subsystem.SYS, "ping", {}, undefined, 200);
    assert.equal(ping.payload.capabilities, 1);
    assert.deepEqual(writes, [240, 1]);
});

test("REVIEW-P0: synchronous F0 write error cleans orphan waiter and latches diagnostic shutdown", async () => {
    const znp = new Znp("/dev/no-serial", 115200, false);
    znp.initialized = true;
    znp.unpiWriter.writeFrame = () => { throw Error("simulated synchronous UART failure"); };
    await assert.rejects(znp.requestWithReply(Subsystem.SYS, "r4DiagReadOnly", {}, undefined, 20),
                         /simulated synchronous UART failure/);
    assert.equal(znp.waitress.waiters.size, 0);
    assert.equal(znp.b4CanProbe(), false);
    await assert.rejects(znp.requestWithReply(Subsystem.SYS, "r4DiagReadOnly", {}, undefined, 20), /poisoned/);
});

test("REVIEW-P0: fail closed on unqualified reserved counters and nonadvancing sample sequence", async () => {
    const dirty = frame();
    dirty.writeUInt32LE(0x77777777, 32 + 4 * 23); // invalid native bit 23
    const first = fakeOwner(dirty);
    assert.equal(await first.owner.b4ReadOnlyDiagnostics(allow), undefined);
    assert.equal(first.owner.znp.poisoned, true);
    assert.equal(first.calls(), 1);
    const good = fakeOwner();
    assert.equal((await good.owner.b4ReadOnlyDiagnostics(allow)).sequence, 8);
    good.owner.b4NextAllowedMs = 0; // simulate an authorized later offer
    assert.equal(await good.owner.b4ReadOnlyDiagnostics(allow), undefined);
    assert.equal(good.owner.znp.poisoned, true);
    assert.equal(good.calls(), 2);
    const nonpositive = frame();
    nonpositive.writeUInt32LE(0, 28);
    const zero = fakeOwner(nonpositive);
    assert.equal(await zero.owner.b4ReadOnlyDiagnostics(allow), undefined);
});

test("REVIEW-P0: delayed unsolicited F0 after timed-out request cannot reopen diagnostics", async () => {
    const znp = new Znp("/dev/no-serial", 115200, false);
    znp.initialized = true;
    const sent = [];
    znp.unpiWriter.writeFrame = (f) => {
        sent.push(f.commandID);
        if (f.commandID === 1) queueMicrotask(() => znp.onUnpiParsed(
            new Frame(Type.SRSP, Subsystem.SYS, 1, Buffer.from([1, 0]))));
    };
    await assert.rejects(znp.requestWithReply(Subsystem.SYS, "r4DiagReadOnly", {}, undefined, 15));
    // Legitimate delayed response from the *previous* transaction. There is
    // no F0 correlation ID, so it cannot authorize a new diagnostic request.
    znp.onUnpiParsed(new Frame(Type.SRSP, Subsystem.SYS, 240, frame()));
    assert.equal(znp.waitress.waiters.size, 0);
    assert.equal(znp.b4CanProbe(), false);
    await assert.rejects(znp.requestWithReply(Subsystem.SYS, "r4DiagReadOnly", {}, undefined, 200), /poisoned/);
    assert.equal((await znp.requestWithReply(Subsystem.SYS, "ping", {}, undefined, 200)).payload.capabilities, 1);
    assert.deepEqual(sent, [240, 1]);
});

test("REVIEW-P1: ZNP mutex idle but unresolved Waitress still forbids F0", () => {
    const znp = new Znp("/dev/not-opened", 115200, false);
    znp.initialized = true;
    assert.equal(znp.queue.count, 0);
    assert.equal(znp.b4CanProbe(), true);
    const waiter = znp.waitress.waitFor(
        {type: Type.SRSP, subsystem: Subsystem.SYS, command: "ping"}, 10_000
    );
    assert.equal(znp.queue.count, 0); // misleading queue-only criterion
    assert.equal(znp.waitress.b4IsIdle(), false);
    assert.equal(znp.b4CanProbe(), false);
    znp.waitress.remove(waiter.ID);
    assert.equal(znp.waitress.b4IsIdle(), true);
    assert.equal(znp.b4CanProbe(), true);
});

test("REVIEW-P0: F0 queued before first timeout cannot escape the mutex after quarantine", async () => {
    const znp = new Znp("/dev/no-serial", 115200, false);
    znp.initialized = true;
    const writes = [];
    znp.unpiWriter.writeFrame = (request) => {
        writes.push(request.commandID);
        if (request.commandID === 1) queueMicrotask(() => znp.onUnpiParsed(
            new Frame(Type.SRSP, Subsystem.SYS, 1, Buffer.from([1, 0]))));
    };
    const first = assert.rejects(
        znp.requestWithReply(Subsystem.SYS, "r4DiagReadOnly", {}, undefined, 12)
    );
    // This call arrives before the timeout and passes the early guard.
    // The decisive check must be run again *inside* AsyncMutex after first
    // timeout, or this F0 would be wrongly transmitted later.
    const second = assert.rejects(
        znp.requestWithReply(Subsystem.SYS, "r4DiagReadOnly", {}, undefined, 100),
        /poisoned inside ZNP mutex/
    );
    await Promise.all([first, second]);
    assert.deepEqual(writes, [240]);
    assert.equal(znp.waitress.waiters.size, 0);
    assert.equal(znp.b4CanProbe(), false);
    const normal = await znp.requestWithReply(Subsystem.SYS, "ping", {}, undefined, 100);
    assert.equal(normal.payload.capabilities, 1);
    assert.deepEqual(writes, [240, 1]);
});

test("REVIEW-P1: direct queued F0 cannot bypass normal outstanding Waitress", async () => {
    const znp = new Znp("/dev/no-serial", 115200, false);
    znp.initialized = true;
    const recorded = [];
    znp.unpiWriter.writeFrame = (request) => { recorded.push(request.commandID); };
    const prior = znp.waitress.waitFor(
        {type: Type.SRSP, subsystem: Subsystem.ZDO, command: "permitJoin"}, 2000
    );
    await assert.rejects(
        znp.requestWithReply(Subsystem.SYS, "r4DiagReadOnly", {}, undefined, 25),
        /owner unavailable or poisoned inside ZNP mutex/
    );
    assert.deepEqual(recorded, []);
    znp.waitress.remove(prior.ID);
});

test("REVIEW-P0: a queued F0 never writes after the existing owner is disconnected", async () => {
    const znp = new Znp("/dev/no-device-opened", 115200, false);
    znp.initialized = true;
    const transmitted = [];
    let releasePing;
    znp.unpiWriter.writeFrame = (frame) => {
        transmitted.push(frame.commandID);
        if (frame.commandID === 1) {
            releasePing = () => znp.onUnpiParsed(
                new Frame(Type.SRSP, Subsystem.SYS, 1, Buffer.from([1, 0]))
            );
        }
    };
    const normal = znp.requestWithReply(Subsystem.SYS, "ping", {}, undefined, 500);
    assert.equal(typeof releasePing, "function"); // mutex occupied by normal ping
    const diagnostic = assert.rejects(
        znp.requestWithReply(Subsystem.SYS, "r4DiagReadOnly", {}, undefined, 500),
        /owner unavailable or poisoned inside ZNP mutex/
    );
    // Simulates the real pinned onPortClose setting initialized=false while
    // the diagnostic request is already in the mutex's pending queue.
    znp.initialized = false;
    releasePing(); // finish preexisting ping; mutex advances to queued F0
    await normal;
    await diagnostic;
    assert.deepEqual(transmitted, [1]); // no diagnostic write to a closed port
    assert.equal(znp.waitress.waiters.size, 0);
    assert.equal(znp.b4CanProbe(), false);
});
