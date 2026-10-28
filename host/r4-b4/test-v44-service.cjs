"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict");
const path=require("node:path"),fs=require("node:fs"),os=require("node:os");
const root=process.env.B4_HERDSMAN_ROOT;
if(!root || !root.startsWith("/tmp/"))throw Error("hosted compiled source required");
const mod=p=>require(path.join(root,"dist",p));
const {Znp}=mod("adapter/z-stack/znp/znp.js");
const {ZStackAdapter}=mod("adapter/z-stack/adapter/zStackAdapter.js");
const {Frame}=mod("adapter/z-stack/unpi/frame.js");
const {Type,Subsystem}=mod("adapter/z-stack/unpi/constants.js");
const worker=require("./p7u_diagnostic_worker.cjs");
const flush=async()=>{for(let i=0;i<30;i++)await Promise.resolve();};
function setup(){
 const znp=new Znp("/dev/never-opened",115200,false);znp.initialized=true;
 const sent=[];znp.unpiWriter.writeFrame=f=>sent.push(f);
 return {znp,sent,receive:(system,command,payload)=>znp.onUnpiParsed(new Frame(Type.SRSP,system,command,payload))};
}
function waiter(znp,id){return znp.waitFor(Type.AREQ,Subsystem.AF,"dataConfirm",undefined,id,undefined,1000);}
test("failed and timed-out AF requests reclaim their own confirmation without removing another",async t=>{
 t.mock.timers.enable({apis:["setTimeout"]});
 const h=setup();const unrelated=waiter(h.znp,42);
 for(let i=0;i<200;i++){
  const confirmation=waiter(h.znp,i+100);
  const p=h.znp.request(Subsystem.AF,"dataRequest",{dstaddr:1,destendpoint:1,srcendpoint:1,clusterid:6,
   transid:i%255,options:0,radius:30,len:0,data:Buffer.alloc(0)},confirmation.ID,10);
  const rejected=assert.rejects(p,/after 10ms/);t.mock.timers.tick(10);await rejected;
  assert.equal(h.znp.waitress.waiters.size,1);
  assert.equal(h.znp.waitress.waiters.has(unrelated.ID),true);
 }
 h.znp.waitress.remove(unrelated.ID);assert.equal(h.znp.waitress.waiters.size,0);
});
test("writer throw and synchronous admission failure reclaim unstarted confirmation waiters",async()=>{
 const h=setup();let w=waiter(h.znp,1);
 h.znp.unpiWriter.writeFrame=()=>{throw Error("writer failed");};
 await assert.rejects(h.znp.request(Subsystem.SYS,"ping",{},w.ID),/writer failed/);
 assert.equal(h.znp.waitress.waiters.size,0);
 w=waiter(h.znp,2);h.znp.initialized=false;
 assert.throws(()=>h.znp.request(Subsystem.SYS,"ping",{},w.ID),/initialized/);
 assert.equal(h.znp.waitress.waiters.size,0);
});
test("successful SRSP preserves its pending data confirmation until normal completion",async()=>{
 const h=setup(),w=waiter(h.znp,3);
 const p=h.znp.request(Subsystem.SYS,"ping",{},w.ID);h.receive(Subsystem.SYS,1,Buffer.from([1,0]));await p;
 assert.equal(h.znp.waitress.waiters.has(w.ID),true);h.znp.waitress.remove(w.ID);
});
test("standalone confirmation timeout removes itself with no later serial traffic",async t=>{
 t.mock.timers.enable({apis:["setTimeout"]});const h=setup(),w=waiter(h.znp,4);
 const failure=assert.rejects(w.start().promise,/after 1000ms/);t.mock.timers.tick(1000);await failure;
 assert.equal(h.znp.waitress.waiters.size,0);
});
test("ZDO confirmation ownership is released on timeout, writer error and unsupported command",async t=>{
 t.mock.timers.enable({apis:["setTimeout"]});const h=setup();
 const response=()=>h.znp.waitFor(Type.AREQ,Subsystem.ZDO,"mgmtPermitJoinRsp",undefined,undefined,undefined,1000);
 let w=response();const p=h.znp.requestZdo(0x0036,Buffer.from([0,0,1,0]),w.ID);
 const rejected=assert.rejects(p,/after 6000ms/);t.mock.timers.tick(6000);await rejected;
 assert.equal(h.znp.waitress.waiters.size,0);
 h.znp.unpiWriter.writeFrame=()=>{throw Error("ZDO writer failed");};
 w=response();await assert.rejects(h.znp.requestZdo(0x0036,Buffer.from([0,0,1,0]),w.ID),/writer failed/);
 assert.equal(h.znp.waitress.waiters.size,0);
 w=response();await assert.rejects(h.znp.requestZdo(0xffff,Buffer.alloc(0),w.ID),/not supported/);
 assert.equal(h.znp.waitress.waiters.size,0);
});
test("minor4 nonce, congestion and existing progress survive real decode and durable storage",async()=>{
 const h=setup(),adapter=Object.create(ZStackAdapter.prototype);
 Object.assign(adapter,{znp:h.znp,queue:{count:()=>0},closing:false,interpanLock:false,b4DiagInFlight:false,b4NextAllowedMs:0});
 const p=adapter.b4ReadOnlyDiagnosticsV4({enabled:true,hostIdle:true,otaActive:false,stillAllowed:()=>true});
 await flush();assert.equal(h.sent[0].commandID,242);
 const data=Buffer.alloc(248);data.write("R4D4");data[4]=4;data.writeUInt16LE(248,6);
 data.writeUInt32LE(0x1ffffff,12);data.writeUInt32LE(1,28);h.sent[0].data.copy(data,132);
 data[156]=255;data[157]=4;data.writeUInt32LE(10,236);
 data.writeUInt32LE(12,140);data.writeUInt32LE(18,144);data.writeUInt32LE(100,148);data.writeUInt32LE(200,152);
 data.writeUInt32LE(180,128);data.writeUInt32LE(30,240);data.writeUInt32LE(2,244);
 h.receive(Subsystem.SYS,242,data);const result=await p;assert.equal(result.minor,4);
 assert.deepEqual(result.congestion,{srspQueuedBytes:12,asyncQueuedBytes:18,srspBytesHighWater:100,
  asyncBytesHighWater:200,maxSrspQueueAgeTicks:30,maxAsyncQueueAgeTicks:180,maxReadyServiceGapTicks:2});
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),"v44-evidence-"));
 try{
  const history=path.join(dir,"p7u-b4-diagnostics"),state=worker.open(history);
  const row={schema:"p7u-b4-native-sample-v1",kind:"VALID",utc:Date.now(),monotonicReceiveNs:"123",
   hostRunId:"8e2cdca6-17b6-4a4c-a951-a78742ad89e1",ownerGeneration:"28ca5f87-b319-4c93-93d3-23d0f46a316d",
   abi:4,minor:4,sequence:1,validityMask:result.validityMask,mtLifecycle:result.mtLifecycle,
   uartProgress:result.uartProgress,congestion:result.congestion,
   probeLatencyMs:1000,processUptimeMs:100000,sourceAbi:4,imageRuntimeAttested:false,
   srspDepth:result.srspDepth,srspHighWater:result.srspHighWater,asyncDepth:result.asyncDepth,
   asyncHighWater:result.asyncHighWater,srspEnqueued:result.srspEnqueued,
   uartTxFinishedEvents:result.uartTxFinishedEvents,
   radioEpochTag:"b4b58f156dce221ea30f64ac",radioEpochHardwareVerified:false,
   resetReason:null,hostPackage:"Zigbee2MQTT 2.14.0 / zigbee-herdsman 10.9.1",
   hostEvidence:adapter.b4GetNoWireEvidence()};
  worker.commit(state,row);assert.deepEqual(worker.open(history).records[0].congestion,result.congestion);
  assert.throws(()=>worker.commit(state,{...row,congestion:null}),/CONGESTION/);
  assert.throws(()=>worker.commit(state,{...row,congestion:{...result.congestion,asyncQueuedBytes:201}}),/CONGESTION/);
  assert.throws(()=>worker.commit(state,{...row,congestion:{...result.congestion,payload:1}}),/CONGESTION/);
  const saturated=structuredClone(row);
  for(const k of Object.keys(saturated.mtLifecycle))saturated.mtLifecycle[k]=0xffffffff;
  for(const k of ["npiRequests","mtEntered","mtReturned","uartWriteAccepted","uartRxBytes","npiWakes"])
   saturated.uartProgress[k]=0xffffffff;
  for(const k of Object.keys(saturated.congestion))saturated.congestion[k]=0xffffffff;
  for(const stats of Object.values(saturated.hostEvidence.srsp))
   Object.assign(stats,{ok:Number.MAX_SAFE_INTEGER,timeout:Number.MAX_SAFE_INTEGER,maxLatencyMs:3600000,lastLatencyMs:3600000});
  for(const k of Object.keys(saturated.hostEvidence.wire))
   if(k!=="measurement")saturated.hostEvidence.wire[k]=Number.MAX_SAFE_INTEGER;
  worker.commit(state,saturated);
  assert.equal(worker.open(history).records.length,2);
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
