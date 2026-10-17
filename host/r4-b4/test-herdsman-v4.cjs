/* B4 v4: genuine compiled pinned herdsman classes. No port is opened.
 * Run only after verified v3 and v4 addons on disposable source checkout.
 */
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const root = process.env.B4_HERDSMAN_ROOT;
if (typeof root !== "string" || !root.startsWith("/tmp/")) {
    throw Error("pinned disposable B4 source root required");
}
const mod = p => require(path.join(root, "dist", ...p.split("/")));
const {ZpiObject} = mod("adapter/z-stack/znp/zpiObject.js");
const {Znp} = mod("adapter/z-stack/znp/znp.js");
const {ZStackAdapter} = mod("adapter/z-stack/adapter/zStackAdapter.js");
const {Controller} = mod("controller/controller.js");
const {Frame} = mod("adapter/z-stack/unpi/frame.js");
const {Type,Subsystem} = mod("adapter/z-stack/unpi/constants.js");

function makeResponse(nonce, {epoch=0x1122334455667788n, ready=true, seq=1,
                              fingerprint=0x55ffaa0012345678n,valid=0x3F} = {}) {
    const bytes=Buffer.alloc(160);
    bytes.write("R4D4",0,"ascii");bytes.writeUInt8(4,4);
    bytes.writeUInt16LE(160,6);
    bytes.writeUInt32LE(ready?3:2,8);
    bytes.writeUInt32LE(valid,12);
    if (ready) bytes.writeBigUInt64LE(epoch,16);
    bytes.writeUInt32LE(seq,28);
    bytes.writeUInt32LE(2,32);bytes.writeUInt32LE(4,36);
    bytes.writeUInt32LE(3,40);bytes.writeUInt32LE(5,44);
    bytes.writeUInt32LE(11,48);bytes.writeUInt32LE(7,52);
    nonce.copy(bytes,132);
    bytes.writeUInt32LE(6,140);
    bytes.writeBigUInt64LE(fingerprint,144);
    bytes.writeUInt16LE(ready?1:0,154);
    return bytes;
}
function fakeAdapter(alter = x=>x) {
    const owner = Object.create(ZStackAdapter.prototype);
    owner.queue={count(){return 0;}};
    owner.closing=false;owner.interpanLock=false;
    owner.b4DiagInFlight=false;owner.b4NextAllowedMs=0;
    owner.znp={
        poison:false,
        b4CanProbe(){return !this.poison;},
        b4PoisonDiagSession(){this.poison=true;},
        b4SetProbeGuard(guard){this.guard=guard;},
        async requestWithReply(subsystem,name,payload,id,timeout){
            assert.equal(subsystem,Subsystem.SYS);
            assert.equal(name,"r4DiagReadOnlyV4");
            assert.equal(timeout,1200);
            assert(Buffer.isBuffer(payload.nonce));
            assert.equal(payload.nonce.length,8);
            assert(payload.nonce.some(x=>x!==0));
            return {payload:{diagnostic:alter(makeResponse(payload.nonce))}};
        }
    };
    return owner;
}
const allow={enabled:true,hostIdle:true,otaActive:false,stillAllowed:()=>true};

test("V4: real ZpiObject encodes 8-byte SREQ and decodes 160-byte SRSP",()=>{
    const nonce=Buffer.from("ab1204fe0034ef05","hex");
    const p=ZpiObject.createRequest(Subsystem.SYS,"r4DiagReadOnlyV4",{nonce});
    const req=p.unpiFrame;
    assert.equal(req.commandID,241);
    assert.deepEqual(req.data,nonce);
    const full=new Frame(Type.SRSP,Subsystem.SYS,241,makeResponse(nonce)).toBuffer();
    assert.equal(ZpiObject.fromUnpiFrame(Frame.fromBuffer(160,full.length-1,full)).payload.diagnostic.length,160);
    assert.throws(()=>ZpiObject.fromUnpiFrame(new Frame(Type.SRSP,Subsystem.SYS,241,Buffer.alloc(159))));
});

test("V4: valid nonce echoed, entropy qualified and original six counters decoded",async()=>{
    const owner=fakeAdapter();
    const result=await owner.b4ReadOnlyDiagnosticsV4(allow);
    assert.equal(result.abi,4);
    assert.equal(result.radioEpoch,"1122334455667788");
    assert.equal(result.bootEpochAvailable,true);
    assert.equal(result.sourceFingerprint,"55ffaa0012345678");
    assert.equal(result.resetReason,6);
    assert.equal(result.sequence,1);
    assert.equal(result.srspDepth,2);assert.equal(result.uartTxFinishedEvents,7);
    assert.equal(owner.znp.poison,false);
});
test("V4: failed radio TRNG exposes UNKNOWN rather than guessed boot epoch",async()=>{
    const owner=fakeAdapter(x=>{
        const nonce=x.subarray(132,140);
        return makeResponse(nonce,{ready:false});
    });
    const res=await owner.b4ReadOnlyDiagnosticsV4(allow);
    assert.equal(res.radioEpoch,"UNKNOWN");
    assert.equal(res.bootEpochAvailable,false);
    assert.equal(owner.znp.poison,false);
});
test("V4: late F1 nonce alias poisoned instead of returning a forged sample",async()=>{
    const owner=fakeAdapter(x=>{
        const b=Buffer.from(x);b[132]^=0x01;return b;
    });
    assert.equal(await owner.b4ReadOnlyDiagnosticsV4(allow),undefined);
    assert.equal(owner.znp.poison,true);
});
test("V4: nonzero invalid counter and caps mismatch fail-closed",async()=>{
    for(const change of [
        b=>b.writeUInt32LE(1,32+6*4),
        b=>b.writeUInt32LE(5,8),
        b=>b.writeUInt16LE(0,154),
        b=>b.writeBigUInt64LE(0n,144),
        b=>b.writeUInt32LE(1,156)
    ]) {
        const owner=fakeAdapter(src=>{const b=Buffer.from(src);change(b);return b;});
        assert.equal(await owner.b4ReadOnlyDiagnosticsV4(allow),undefined);
        assert.equal(owner.znp.poison,true);
    }
});
test("V4: guarded Controller only uses its real ZStackAdapter, requires live OTA predicate",async()=>{
    const controller=Object.create(Controller.prototype);
    const adapter=fakeAdapter();
    controller.adapter=adapter;controller.stopping=false;controller.adapterDisconnected=false;
    assert.equal((await controller.b4ReadOnlyDiagnosticsV4FromExistingOwner(allow)).abi,4);
    assert.equal(await controller.b4ReadOnlyDiagnosticsV4FromExistingOwner({...allow,stillAllowed:undefined}),undefined);
    controller.adapter={};
    assert.equal(await controller.b4ReadOnlyDiagnosticsV4FromExistingOwner(allow),undefined);
});
test("V4: manual default OFF, OTA and stale owner never send F1",async()=>{
    for (const input of [
        {...allow,enabled:false},{...allow,otaActive:true},
        {...allow,stillAllowed:()=>false}
    ]) {
        const owner=fakeAdapter();
        assert.equal(await owner.b4ReadOnlyDiagnosticsV4(input),undefined);
        assert.equal(owner.znp.poison,false);
    }
});
test("V4: true pinned ZNP mutex veto prevents F1 after OTA starts while queued",async()=>{
    const znp=new Znp("/dev/never-opened",115200,false);
    znp.initialized=true;
    let otaSafe=true;
    const ids=[];
    let finishPing;
    znp.unpiWriter.writeFrame=packet=>{
        ids.push(packet.commandID);
        if(packet.commandID===1)
            finishPing=()=>znp.onUnpiParsed(new Frame(Type.SRSP,Subsystem.SYS,1,Buffer.from([1,0])));
    };
    const ping=znp.requestWithReply(Subsystem.SYS,"ping",{},undefined,500);
    assert.equal(typeof finishPing,"function");
    znp.b4SetProbeGuard(()=>otaSafe);
    const nonce=Buffer.from("840c0113df184bd7","hex");
    const diagnostic=assert.rejects(
        znp.requestWithReply(Subsystem.SYS,"r4DiagReadOnlyV4",{nonce},undefined,500),
        /B4 F0 runtime admission vetoed/
    );
    otaSafe=false;finishPing();
    await ping;await diagnostic;
    assert.deepEqual(ids,[1]);
    assert.equal(znp.waitress.waiters.size,0);
    assert.equal(znp.b4DiagPoisoned,false);
    znp.b4SetProbeGuard(undefined);
});
