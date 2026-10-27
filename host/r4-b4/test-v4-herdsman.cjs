/* B4 v4 actual compiled pinned herdsman Source-only F2 tests.
 * Executed in CI after B4 v3 and v4 overlays, no serial port ever opened.
 */
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const root = process.env.B4_HERDSMAN_ROOT;
if (!root || !path.isAbsolute(root) || !root.startsWith("/tmp/")) {
    throw Error("no disposable compiled herdsman checkout");
}
function mod(p) {return require(path.join(root, "dist", ...p.split("/")));}
const {ZStackAdapter} = mod("adapter/z-stack/adapter/zStackAdapter.js");
const {Znp} = mod("adapter/z-stack/znp/znp.js");
const {ZpiObject} = mod("adapter/z-stack/znp/zpiObject.js");
const {Frame} = mod("adapter/z-stack/unpi/frame.js");
const {Type, Subsystem} = mod("adapter/z-stack/unpi/constants.js");
const {Controller} = mod("controller/controller.js");

function wire(nonce, {caps=0, boot=0n, reset=255, seq=1, minor=1, mask=0x3F}={}) {
    const d = Buffer.alloc(160);
    d.write("R4D4", 0, "ascii");
    d[4] = 4; d.writeUInt16LE(160,6);
    d.writeUInt32LE(caps,8); d.writeUInt32LE(mask,12);
    d.writeBigUInt64LE(boot, 16);
    d.writeUInt32LE(seq,28);
    d.writeUInt32LE(1,32); d.writeUInt32LE(2,36);
    d.writeUInt32LE(2,40); d.writeUInt32LE(3,44);
    d.writeUInt32LE(4,48); d.writeUInt32LE(5,52);
    nonce.copy(d,132);
    d[156] = reset; d[157] = minor; d[158] = reset === 255 ? 0 : 1;
    return d;
}

function ownerWithResponse(chooser) {
    const adapter = Object.create(ZStackAdapter.prototype);
    adapter.queue = {count() {return 0;}};
    adapter.znp = {
        disabled: false,
        requests: 0,
        b4CanProbe() {return !this.disabled;},
        b4CanProbeV4() {return !this.disabled;},
        b4F2NoBlockingWaiters() {return !this.disabled;},
        b4GetPassiveOwnerMetrics() {
            return {initialized:true, mutexIdle:true, mutexQueued:0,
                waitressPending:0, diagnosticQuarantined:this.disabled,
                srsp:{}, scope:"HOST_OWNER_LIFETIME_ONLY"};
        },
        b4F2ReadAdmissionReason() {return null;},
        b4F2AcceptReply() {},
        b4IsDiagPoisoned() {return this.disabled;},
        b4SetProbeGuard(guard) {this.guard = guard;},
        b4SetF2BoundaryAdmission(enabled) {this.boundaryAdmission = enabled;},
        b4PoisonDiagSession() {this.disabled = true;},
        async requestWithReply(sys,cmd,payload,unused,timeout) {
            this.requests++;
            assert.equal(sys, Subsystem.SYS);
            assert.equal(cmd, "r4DiagReadOnlyV4");
            assert.equal(payload.nonce.length, 8);
            assert.equal(timeout,6000);
            return {payload:{diagnostic:chooser(payload.nonce)}};
        }
    };
    adapter.closing = false; adapter.interpanLock = false;
    adapter.b4DiagInFlight = false; adapter.b4NextAllowedMs = 0;
    return adapter;
}
const allowed = {
    enabled:true, hostIdle:true, otaActive:false, stillAllowed:()=>true,
};

test("V4 F2 native MT dictionary request serializes exact 8-byte host nonce", () => {
    const nonce = Buffer.from("0102030405060708","hex");
    const req = ZpiObject.createRequest(Subsystem.SYS,"r4DiagReadOnlyV4",{nonce});
    assert.equal(req.unpiFrame.commandID,242);
    assert.deepEqual(req.unpiFrame.data,nonce);
    const buf = new Frame(Type.SRSP,Subsystem.SYS,242,wire(nonce)).toBuffer();
    const decoded = ZpiObject.fromUnpiFrame(Frame.fromBuffer(160,buf.length-1,buf));
    assert.equal(decoded.payload.diagnostic.length,160);
    assert.deepEqual(decoded.payload.diagnostic.subarray(132,140),nonce);
    const corrupt = Buffer.from(buf);
    corrupt[corrupt.length - 1] ^= 1;
    assert.throws(()=>Frame.fromBuffer(160,corrupt.length-1,corrupt));
    assert.throws(()=>ZpiObject.fromUnpiFrame(
        new Frame(Type.SRSP,Subsystem.SYS,242,Buffer.alloc(159))));
});

test("V4 response nonce matches random request and boot stays unqualified for hardware",async()=>{
    const owner = ownerWithResponse((nonce)=>wire(nonce,{
        caps:1,boot:0x1234567890ABCDEFn,reset:2,seq:4
    }));
    const result = await owner.b4ReadOnlyDiagnosticsV4(allowed);
    assert.equal(result.abi,4);
    assert.equal(result.minor,1);
    assert.equal(result.radioBootId,"efcdab9078563412");
    assert.equal(result.radioEpochHardwareVerified,false);
    assert.equal(result.resetReason,2);
    assert.equal(result.buildImageDigest,null);
    assert.equal(result.uartTxFinishedEvents,5);
    assert.equal(owner.znp.requests,1);
    assert.equal(owner.znp.guard,undefined);
});

test("V4 stale F2 response with wrong nonce quarantines optional requests",async()=>{
    const stale = Buffer.from("0000000000000000","hex");
    const owner = ownerWithResponse(()=>wire(stale));
    const result = await owner.b4ReadOnlyDiagnosticsV4(allowed);
    assert.equal(result,undefined);
    assert.equal(owner.znp.disabled,true);
    assert.equal(owner.znp.guard,undefined);
});

test("V4 source-invalid identity and no boot cap never invent epoch",async()=>{
    const owner = ownerWithResponse((nonce)=>wire(nonce,{caps:0,boot:0n,reset:255}));
    const result = await owner.b4ReadOnlyDiagnosticsV4(allowed);
    assert.equal(result.radioBootId,null);
    assert.equal(result.resetReason,null);
    assert.equal(result.radioEpochHardwareVerified,false);
    const wrong = ownerWithResponse((nonce)=>wire(nonce,{caps:1,boot:0n}));
    assert.equal(await wrong.b4ReadOnlyDiagnosticsV4(allowed),undefined);
    assert.equal(wrong.znp.disabled,true);
});

test("V4 competing branch SYS F2 layout must never parse as this F2 ABI", async()=>{
    // #104's latest F2 candidate is not binary compatible with #105:
    // capability bit1=nonce, 140..155 reset/fingerprint, minor zero.
    // A matching 0xF2 opcode alone must NOT cause cross-decoding.
    const owner = ownerWithResponse((nonce)=>{
        const d=wire(nonce,{caps:3,boot:0x12345678n,reset:255,minor:0});
        d.writeUInt32LE(2,140);
        d.writeUInt32LE(0x12345678,144);
        return d;
    });
    assert.equal(await owner.b4ReadOnlyDiagnosticsV4(allowed),undefined);
    assert.equal(owner.znp.disabled,true);
    assert.equal(owner.znp.requests,1);
});

test("V4 disabled/busy/OTA/replaced predicate all send zero serial requests",async()=>{
    const owner = ownerWithResponse((nonce)=>wire(nonce));
    for(const input of [
        {...allowed,enabled:false},
        {...allowed,hostIdle:false},
        {...allowed,otaActive:true},
        {...allowed,stillAllowed:()=>false},
        {...allowed,stillAllowed:undefined},
    ]) {
        assert.equal(await owner.b4ReadOnlyDiagnosticsV4(input),undefined);
    }
    assert.equal(owner.znp.requests,0);
});

test("V4 F2 uses existing ZNP owner when only unrelated AREQ callback is outstanding", async () => {
    const znp = new Znp("/dev/not-opened", 115200, false);
    znp.initialized = true; // synthetic owner, do not open any serial device
    const callback = znp.waitress.waitFor(
        {type: Type.AREQ, subsystem: Subsystem.AF, command: "dataConfirm"}, 2000
    );
    const transmitted = [];
    znp.unpiWriter.writeFrame = (request) => {
        transmitted.push(request.commandID);
        assert.equal(request.commandID, 242);
        assert.equal(request.data.length, 8);
        queueMicrotask(() => znp.onUnpiParsed(
            new Frame(Type.SRSP, Subsystem.SYS, request.commandID, wire(request.data))
        ));
    };
    const owner = Object.create(ZStackAdapter.prototype);
    owner.znp = znp;
    owner.queue = {count: () => 0};
    owner.interpanLock = false; owner.closing = false;
    owner.b4DiagInFlight = false; owner.b4NextAllowedMs = 0;
    assert.equal(znp.waitress.b4IsIdle(), false);
    assert.equal(znp.b4CanProbeV4(), true);
    assert.equal(znp.b4CanProbe(), false); // F0 remains all-waiter blocked
    const result = await owner.b4ReadOnlyDiagnosticsV4(allowed);
    assert.equal(result?.abi, 4);
    assert.equal(result?.sequence, 1);
    assert.equal(owner.b4GetV4Outcome().kind, "VALID");
    assert.deepEqual(transmitted, [242]);
    assert.equal(znp.waitress.waiters.size, 1); // AREQ callback never discarded
    znp.waitress.remove(callback.ID);
});

test("V4 F2 direct write still rejects a live unrelated SRSP without transmission", async () => {
    const znp = new Znp("/dev/not-opened", 115200, false);
    znp.initialized = true;
    const transmitted = [];
    znp.unpiWriter.writeFrame = (request) => transmitted.push(request.commandID);
    const active = znp.waitress.waitFor(
        {type: Type.SRSP, subsystem: Subsystem.ZDO, command: "permitJoin"}, 3000
    );
    assert.equal(znp.b4CanProbeV4(), false);
    await assert.rejects(
        znp.requestWithReply(Subsystem.SYS, "r4DiagReadOnlyV4",
            {nonce: Buffer.from("0102030405060708", "hex")}, undefined, 200),
        /B4 DIAG_NOT_SUBMITTED_BUSY/
    );
    assert.deepEqual(transmitted, []);
    assert.equal(znp.b4IsDiagPoisoned(), false); // safely not submitted
    znp.waitress.remove(active.ID);
});

test("V4 real compiled Znp mutex vetoes F2 after OTA begins while queued",async()=>{
    const znp = new Znp("/dev/not-opened",115200,false);
    znp.initialized = true;
    const writes = [];
    let release;
    znp.unpiWriter.writeFrame = (frame)=>{
        writes.push(frame.commandID);
        if(frame.commandID===1)release=()=>znp.onUnpiParsed(
            new Frame(Type.SRSP,Subsystem.SYS,1,Buffer.from([1,0])));
    };
    const normal=znp.requestWithReply(Subsystem.SYS,"ping",{},undefined,500);
    assert.equal(typeof release,"function");
    let idle=true;
    znp.b4SetProbeGuard(()=>idle);
    const pending=assert.rejects(
        znp.requestWithReply(Subsystem.SYS,"r4DiagReadOnlyV4",
            {nonce:Buffer.from("0102030405060708","hex")},undefined,500),
        /B4 DIAG_NOT_SUBMITTED_BUSY/
    );
    idle=false; release();
    await normal; await pending;
    assert.deepEqual(writes,[1]);
    assert.equal(znp.waitress.waiters.size,0);
    assert.equal(znp.b4DiagPoisoned,false);
    znp.b4SetProbeGuard(undefined);
});

test("V4 Controller uses original Z-Stack owner only",async()=>{
    const adapter=Object.create(ZStackAdapter.prototype);
    adapter.b4ReadOnlyDiagnosticsV4=async (arg)=>({abi:4,arg});
    const ctrl=Object.create(Controller.prototype);
    ctrl.stopping=false;ctrl.adapterDisconnected=false;ctrl.adapter=adapter;
    const result=await ctrl.b4ReadOnlyDiagnosticsV4FromExistingOwner(allowed);
    assert.equal(result.abi,4);
    ctrl.adapter={};
    assert.equal(await ctrl.b4ReadOnlyDiagnosticsV4FromExistingOwner(allowed),undefined);
    ctrl.adapter=adapter;ctrl.adapterDisconnected=true;
    assert.equal(await ctrl.b4ReadOnlyDiagnosticsV4FromExistingOwner(allowed),undefined);
});

test("F2 v4.2 preserves v4.1 framing and provides exactly 18 native causal stages", async () => {
    const values = Array.from({length:18}, (_, i) => i + 11);
    const owner = ownerWithResponse((nonce) => {
        const frame = wire(nonce, {minor:2, mask:0x00FFFFFF, seq:7});
        for (let i=0; i<18; i++) frame.writeUInt32LE(values[i], 56 + i*4);
        return frame;
    });
    const result = await owner.b4ReadOnlyDiagnosticsV4(allowed);
    assert.equal(result.minor, 2);
    assert.equal(result.validityMask, 0x00FFFFFF);
    assert.equal(result.mtLifecycle.allProduced, 11);
    assert.equal(result.mtLifecycle.allTlRejected, 19);
    assert.equal(result.mtLifecycle.afDataProduced, 20);
    assert.equal(result.mtLifecycle.afDataTlRejected, 28);
    assert.equal(Object.keys(result.mtLifecycle).length, 18);
    assert.equal(owner.znp.requests, 1);
    const oldOwner = ownerWithResponse((nonce)=>wire(nonce,{minor:1,mask:0x3F}));
    assert.equal((await oldOwner.b4ReadOnlyDiagnosticsV4(allowed)).mtLifecycle, null);
});

test("F2 v4.2 quarantines wrong validity, reserved slot, and incompatible minor", async () => {
    for (const mutate of [
        (d) => d.writeUInt32LE(0x2c,12),
        (d) => d.writeUInt32LE(1,128), // slot24 is NOT a valid counter
        (d) => {d[157]=1;}, // v4.1 must not carry v4.2 counters
    ]) {
        const owner=ownerWithResponse((nonce) => {
            const d=wire(nonce,{minor:2,mask:0x00FFFFEC});
            d.writeUInt32LE(12,56);
            mutate(d);
            return d;
        });
        assert.equal(await owner.b4ReadOnlyDiagnosticsV4(allowed), undefined);
        assert.equal(owner.znp.disabled,true);
    }
});
