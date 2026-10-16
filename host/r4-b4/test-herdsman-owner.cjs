/* Actual compiled pinned herdsman 10.9.1 classes, simulated input only.
 * Run AFTER host/r4-b4/herdsman_overlay.py and "pnpm run build".
 * No serial/USB/host integration is opened by this test.
 */
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const root = process.argv[2];
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
