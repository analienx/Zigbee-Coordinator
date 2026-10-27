"use strict";
const {test}=require("node:test"), assert=require("node:assert/strict");
const path=require("node:path"), fs=require("node:fs"), os=require("node:os");
const root=process.env.B4_HERDSMAN_ROOT;
if(!root || !root.startsWith("/tmp/"))throw Error("hosted compiled source required");
const mod=p=>require(path.join(root,"dist",p));
const {AsyncMutex}=mod("utils/async-mutex.js");
const {Znp}=mod("adapter/z-stack/znp/znp.js");
const {ZStackAdapter}=mod("adapter/z-stack/adapter/zStackAdapter.js");
const {Frame}=mod("adapter/z-stack/unpi/frame.js");
const {Type,Subsystem}=mod("adapter/z-stack/unpi/constants.js");
const worker=require("./p7u_diagnostic_worker.cjs");
const allowed={enabled:true,hostIdle:true,otaActive:false,stillAllowed:()=>true,reserveAtBoundary:true};
const flush=async()=>{for(let i=0;i<20;i++)await Promise.resolve();};
function body(nonce,seq=1){
 const d=Buffer.alloc(240);d.write("R4D4");d[4]=4;d.writeUInt16LE(240,6);
 d.writeUInt32LE(0xffffec,12);d.writeUInt32LE(seq,28);nonce.copy(d,132);
 d[156]=255;d[157]=3;d.writeUInt32LE(11,160);d.writeUInt32LE(10,164);
 d.writeUInt32LE(10,168);d.writeUInt32LE(0x24010000,192);d.writeUInt32LE(10,236);
 return d;
}
function setup(){
 const znp=new Znp("/dev/never-opened",115200,false);znp.initialized=true;
 const adapter=Object.create(ZStackAdapter.prototype);
 Object.assign(adapter,{znp,queue:{count:()=>100},closing:false,interpanLock:false,
   b4DiagInFlight:false,b4NextAllowedMs:0});
 const sent=[];znp.unpiWriter.writeFrame=f=>sent.push(f);
 const receive=(d,cmd)=>znp.onUnpiParsed(new Frame(Type.SRSP,Subsystem.SYS,cmd,d));
 const ping=()=>znp.requestWithReply(Subsystem.SYS,"ping",{},undefined,6000);
 return {znp,adapter,sent,receive,ping};
}

test("one F2 slot runs after the active transaction despite a continuously nonempty adapter queue",async()=>{
 const h=setup();const first=h.ping();assert.equal(h.sent.length,1);
 const next=h.ping();const diag=h.adapter.b4ReadOnlyDiagnosticsV4(allowed);
 assert.equal(h.sent.length,1,"F2 cannot interrupt the active SREQ");
 h.receive(Buffer.from([1,0]),1);await first;await flush();
 assert.equal(h.sent.length,2);assert.equal(h.sent[1].commandID,242);
 h.receive(body(h.sent[1].data),242);const result=await diag;
 assert.equal(result.minor,3);assert.equal(result.uartProgress.npiRequests,11);
 assert.equal(result.uartProgress.tickPeriodUs,10);assert.equal(Object.keys(result.mtLifecycle).length,18);
 await flush();assert.equal(h.sent.length,3);assert.equal(h.sent[2].commandID,1);
 h.receive(Buffer.from([1,0]),1);await next;
 assert.equal(h.znp.queue.isIdle(),true);assert.equal(h.znp.waitress.waiters.size,0);
 // The decoded result must survive the real strict durable writer unchanged.
 const parent=fs.mkdtempSync(path.join(os.tmpdir(),"f2-pair-"));
 try {
  const state=worker.open(path.join(parent,"p7u-b4-diagnostics"));
  const row={schema:"p7u-b4-native-sample-v1",kind:"VALID",utc:Date.now(),
   monotonicReceiveNs:"123",hostRunId:"8e2cdca6-17b6-4a4c-a951-a78742ad89e1",
   ownerGeneration:"28ca5f87-b319-4c93-93d3-23d0f46a316d",abi:4,minor:3,
   sequence:result.sequence,validityMask:result.validityMask,
   mtLifecycle:result.mtLifecycle,uartProgress:result.uartProgress};
  worker.commit(state,row);
  assert.equal(worker.open(path.join(parent,"p7u-b4-diagnostics")).records[0].uartProgress.npiRequests,11);
  assert.throws(()=>worker.commit(state,{...row,uartProgress:{...row.uartProgress,rawPayload:"bad"}}),/PROGRESS_SHAPE/);
  assert.throws(()=>worker.commit(state,{...row,uartProgress:null}),/PROGRESS_SHAPE/);
 }finally{fs.rmSync(parent,{recursive:true,force:true});}
});

test("a queued F2 rechecks OTA at the exact write boundary",async()=>{
 const h=setup();let otaAllowed=true;const first=h.ping();
 const diag=h.adapter.b4ReadOnlyDiagnosticsV4({...allowed,stillAllowed:()=>otaAllowed});
 otaAllowed=false;h.receive(Buffer.from([1,0]),1);await first;
 assert.equal(await diag,undefined);assert.equal(h.sent.length,1);
 assert.equal(h.adapter.b4GetV4Outcome().kind,"SKIPPED");
 assert.equal(h.znp.queue.isIdle(),true);
});

test("reservation expiry removes only F2 and leaves the active owner intact",async t=>{
 t.mock.timers.enable({apis:["setTimeout"]});
 const h=setup();const first=h.ping();
 const diag=h.adapter.b4ReadOnlyDiagnosticsV4(allowed);
 t.mock.timers.tick(1001);await flush();
 assert.equal(await diag,undefined);assert.equal(h.sent.length,1);
 assert.equal(h.znp.queue.isIdle(),false);
 h.receive(Buffer.from([1,0]),1);await first;
 assert.equal(h.znp.queue.isIdle(),true);assert.equal(h.znp.waitress.waiters.size,0);
});

test("owner queue clear cancels the pending F2 without running it later",async()=>{
 const mutex=new AsyncMutex();let release;let ran=false;
 const first=mutex.run(()=>new Promise(resolve=>{release=resolve;}));
 const diag=mutex.runF2AtBoundary(async()=>{ran=true;});
 const rejected=assert.rejects(diag,/AsyncMutex queue cleared/);
 mutex.clear();await rejected;release();await first;
 assert.equal(ran,false);assert.equal(mutex.isIdle(),true);
});

test("minor3 cannot be accepted with the old 160-byte frame",async()=>{
 const h=setup();const diag=h.adapter.b4ReadOnlyDiagnosticsV4(allowed);
 const invalid=body(h.sent[0].data).subarray(0,160);invalid.writeUInt16LE(160,6);
 h.receive(invalid,242);assert.equal(await diag,undefined);
 assert.equal(h.znp.b4IsDiagPoisoned(),true);
});
