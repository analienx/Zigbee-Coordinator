/* R4-R06 / T7: actual compiled pinned Herdsman owner lifecycle tests.
 * Deterministic microtask handoff and synthetic UNPI only. No radio opened.
 */
"use strict";
const {test} = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const root = process.env.B4_HERDSMAN_ROOT;
if (!root || !path.isAbsolute(root) || !root.startsWith("/tmp/")) {
    throw new Error("real compiled pinned Herdsman in disposable /tmp required");
}
function mod(p) {return require(path.join(root, "dist", ...p.split("/")));}
const {AsyncMutex} = mod("utils/async-mutex.js");
const {Waitress} = mod("utils/waitress.js");
const {Znp} = mod("adapter/z-stack/znp/znp.js");
const {Frame} = mod("adapter/z-stack/unpi/frame.js");
const {Type, Subsystem} = mod("adapter/z-stack/unpi/constants.js");
const nonce = Buffer.from("0102030405060708", "hex");

test("T7 mutex reserves lock across a microtask handoff: no ABA or overtaking", async () => {
    const mutex = new AsyncMutex();
    const order = [];
    let releaseFirst;
    const first = mutex.run(() => new Promise(resolve => {releaseFirst = resolve;}));
    const second = mutex.run(async () => {order.push("second");});
    assert.equal(mutex.isIdle(), false);
    assert.equal(mutex.count, 1);
    releaseFirst();
    // Enqueue THIS callback after first owner's resumed finally, but BEFORE
    // the queued second owner's wakeup microtask. The old mutex lies idle.
    const newcomer = new Promise((resolve, reject) => queueMicrotask(() => {
        try {
            order.push(mutex.isIdle() ? "UNLOCKED_ABA" : "reserved");
            resolve(mutex.run(async () => {order.push("third");}));
        } catch (error) {
            reject(error);
        }
    }));
    await Promise.all([first, second, newcomer]);
    assert.deepEqual(order, ["reserved", "second", "third"]);
    assert.equal(mutex.isIdle(), true);
});

test("T7 mutex reset rejects every queued caller; no orphaned promises", async () => {
    const mutex = new AsyncMutex();
    let releaseFirst;
    const first = mutex.run(() => new Promise(resolve => {releaseFirst = resolve;}));
    let entered = false;
    const queued = mutex.run(async () => {entered = true;});
    const rejected = assert.rejects(queued, /AsyncMutex queue cleared/);
    assert.equal(mutex.count, 1);
    mutex.clear();
    assert.equal(mutex.count, 0);
    releaseFirst();
    await Promise.all([first, rejected]);
    assert.equal(entered, false);
    assert.equal(mutex.isIdle(), true);
    await mutex.run(async () => {entered = true;});
    assert.equal(entered, true);
});

test("T7 tagged Waitress cancellation settles only F2 promise, not ordinary SYS", async () => {
    const waitress = new Waitress(() => false, () => "timeout");
    const f2 = waitress.waitFor({command: "r4DiagReadOnlyV4"}, 2000);
    const normal = waitress.waitFor({command: "ping"}, 2000);
    const settled = assert.rejects(f2.start().promise, /B4 diagnostic owner closed/);
    assert.equal(waitress.b4CancelMatching(m => m.command === "r4DiagReadOnlyV4",
                                         "B4 diagnostic owner closed"), 1);
    await settled;
    assert.equal(waitress.b4Cancel(f2.ID, "again"), false);
    assert.equal(waitress.waiters.size, 1);
    waitress.remove(normal.ID);
    assert.equal(waitress.b4IsIdle(), true);
});

test("T7 F2 synchronous writer exception cancels waiter, poisons only diagnostics", async () => {
    const znp = new Znp("/dev/not-opened", 115200, false);
    znp.initialized = true;
    let writes = 0;
    znp.unpiWriter.writeFrame = () => {
        writes++;
        throw new Error("injected-writer-failure");
    };
    await assert.rejects(
        znp.requestWithReply(Subsystem.SYS, "r4DiagReadOnlyV4", {nonce}, undefined, 200),
        /injected-writer-failure/,
    );
    assert.equal(writes, 1);
    assert.equal(znp.waitress.waiters.size, 0);
    assert.equal(znp.b4DiagPoisoned, true);
    await assert.rejects(
        znp.requestWithReply(Subsystem.SYS, "r4DiagReadOnlyV4", {nonce}, undefined, 200),
        /session poisoned/,
    );
    assert.equal(writes, 1);
    // Existing normal ZNP path stays functional without extra serial owner.
    znp.unpiWriter.writeFrame = frame => {
        writes++;
        assert.equal(frame.commandID, 1);
        queueMicrotask(() => znp.onUnpiParsed(
            new Frame(Type.SRSP, Subsystem.SYS, 1, Buffer.from([1, 0]))));
    };
    await znp.requestWithReply(Subsystem.SYS, "ping", {}, undefined, 200);
    assert.equal(writes, 2);
});

test("T7 F2 SRSP timeout cleans matcher; a late frame cannot reopen F2", async () => {
    const znp = new Znp("/dev/not-opened", 115200, false);
    znp.initialized = true;
    const sent = [];
    znp.unpiWriter.writeFrame = frame => sent.push(frame.commandID);
    await assert.rejects(
        znp.requestWithReply(Subsystem.SYS, "r4DiagReadOnlyV4", {nonce}, undefined, 15),
        /after 15ms/,
    );
    assert.deepEqual(sent, [242]);
    assert.equal(znp.waitress.waiters.size, 0);
    assert.equal(znp.b4DiagPoisoned, true);
    await assert.rejects(
        znp.requestWithReply(Subsystem.SYS, "r4DiagReadOnlyV4", {nonce}, undefined, 15),
        /session poisoned/,
    );
    assert.deepEqual(sent, [242]);
});

test("T7 owner close cancels active F2; queued F2 and normal requests settle", async () => {
    const znp = new Znp("/dev/not-opened", 115200, false);
    znp.initialized = true;
    znp.socketPort = {destroy() {}};
    const sent = [];
    znp.unpiWriter.writeFrame = frame => sent.push(frame.commandID);
    const active = assert.rejects(
        znp.requestWithReply(Subsystem.SYS, "r4DiagReadOnlyV4", {nonce}, undefined, 5000),
        /B4 diagnostic owner closed/,
    );
    const queued = assert.rejects(
        znp.requestWithReply(Subsystem.SYS, "ping", {}, undefined, 5000),
        /AsyncMutex queue cleared/,
    );
    assert.equal(znp.queue.count, 1);
    await znp.close();
    await Promise.all([active, queued]);
    assert.deepEqual(sent, [242]);
    assert.equal(znp.waitress.waiters.size, 0);
    assert.equal(znp.queue.isIdle(), true);
    assert.equal(znp.b4DiagPoisoned, true);
});


test("F1 optional diagnostic admits atomically: never waits in production mutex queue", async () => {
    const mutex = new AsyncMutex();
    let release;
    const owner = mutex.run(() => new Promise(resolve => {release = resolve;}));
    assert.equal(mutex.isIdle(), false);
    let called = 0;
    const optional = mutex.tryRunIfIdle(async () => {called++;});
    assert.equal(optional, undefined);
    assert.equal(mutex.count, 0, "diagnostic must not be queued");
    assert.equal(called, 0);
    release();
    await owner;
    assert.equal(mutex.isIdle(), true);
    const result = mutex.tryRunIfIdle(async () => {called++; return 17;});
    assert.equal(await result, 17);
    assert.equal(called, 1);
});

test("F1 F2 request while AF owner busy: NOT_SUBMITTED and no UART write", async () => {
    const znp = new Znp("/dev/not-opened", 115200, false);
    znp.initialized = true;
    let release;
    let writes = 0;
    znp.unpiWriter.writeFrame = () => {writes++;};
    const owner = znp.queue.run(() => new Promise(resolve => {release = resolve;}));
    const nonce = Buffer.from("0102030405060708", "hex");
    assert.throws(
        () => znp.request(Subsystem.SYS, "r4DiagReadOnlyV4", {nonce}, undefined, 1200),
        /B4 DIAG_NOT_SUBMITTED_BUSY/
    );
    assert.equal(writes, 0);
    assert.equal(znp.queue.count, 0);
    release();
    await owner;
});
