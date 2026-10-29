"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict");
const path=require("node:path"),fs=require("node:fs"),os=require("node:os"),{randomUUID}=require("node:crypto");
const {spawnSync}=require("node:child_process");
const root=process.env.B4_HERDSMAN_ROOT;
if(!root?.startsWith("/tmp/"))throw Error("Actual pinned compiled owner required");
const mod=p=>require(path.join(root,"dist",p));
const {ZStackAdapter}=mod("adapter/z-stack/adapter/zStackAdapter.js"),{Znp}=mod("adapter/z-stack/znp/znp.js");
const {Frame}=mod("adapter/z-stack/unpi/frame.js"),{Type,Subsystem}=mod("adapter/z-stack/unpi/constants.js");
const worker=require("./p7u_diagnostic_worker.cjs");
function page(n,nonce,fault=true){
 const b=Buffer.alloc(n===3?160:248);b.write("R4D6");b[4]=6;b[5]=n;b[6]=b.length;nonce.copy(b,8);
 b.writeUInt32LE(17,24);b.writeUInt32LE(201000,28);
 const put=(i,v)=>b.writeUInt32LE(v,32+4*i);
 if(n===3){put(0,1);put(1,10);put(2,8);put(3,201000);put(14,fault?1:0);put(15,fault?1:0);
  put(16,200000);put(17,800000);put(18,200000);put(19,6000000);put(20,25000);put(29,fault?1:0);
 }else{
  [1,7,0x2401,100,200100,200000,200000,1,7,0,0,0,10,20,19,30,1,1,5,5,1,1].forEach((v,i)=>put(i,v));
  b.writeUInt32LE(100,120);b.writeUInt16LE(0x2401,124);b[126]=3;
 }
 return b;
}
function owner(choose=page){
 const znp=new Znp("/dev/never-opened",115200,false);znp.initialized=true;const frames=[];
 znp.unpiWriter.writeFrame=f=>{frames.push(f);queueMicrotask(()=>znp.onUnpiParsed(new Frame(Type.SRSP,Subsystem.SYS,242,choose(f.data[0],f.data.subarray(1)))));};
 const a=Object.create(ZStackAdapter.prototype);Object.assign(a,{znp,queue:{count:()=>0},closing:false,
  interpanLock:false,b4DiagInFlight:false,b4NextAllowedMs:0});return {a,znp,frames};
}
const allowed={enabled:true,hostIdle:true,otaActive:false,stillAllowed:()=>true};
test("V6 exact-nonce summary/fault uses the existing owner and strict redaction",async()=>{
 const {a,znp,frames}=owner();const v=await a.b4ReadOwnedStageV6(allowed);
 assert.equal(v.abi,6);assert.equal(v.fault.stageId,7);assert.equal(v.fault.operation,"dataRequest");
 assert.equal(v.fault.events[0].operation,"dataRequest");assert.equal(v.radioBootId,null);
 assert.deepEqual(frames.map(f=>f.data[0]),[3,4]);assert.equal(znp.waitress.waiters.size,0);
 assert.equal(a.b4DiagInFlight,false);assert.equal(znp.b4IsDiagPoisoned(),false);
 const {radioBootId,...stageV6}=v;
 const record={schema:"p7u-b4-native-sample-v1",kind:"STAGE",utc:Date.now(),monotonicReceiveNs:"12345",
  hostRunId:randomUUID(),ownerGeneration:randomUUID(),processUptimeMs:1234,probeLatencyMs:2,
  stageV6,radioEpochTag:null,radioEpochHardwareVerified:false,hostEvidence:null};
 worker.sameRecord(record);
 const base=fs.mkdtempSync(path.join(os.tmpdir(),"v6-journal-")),r=path.join(base,"p7u-b4-diagnostics");fs.mkdirSync(r,{mode:0o700});
 const s=worker.open(r);worker.commit(s,record);assert.equal(worker.open(r).manifest.sequence,1);
 for(const change of [x=>x.stageV6.raw="secret",x=>x.stageV6.fault.device="secret",x=>x.stageV6.fault.events[0].key="secret",
  x=>x.stageV6.fault.stageId=0,x=>x.stageV6.fault.ageTicks=1,x=>x.stageV6.counters.selectedFaultStage=2]){
  const bad=structuredClone(record);change(bad);assert.throws(()=>worker.sameRecord(bad));
 }
 if(process.env.B4_V6_FIXTURE)fs.writeFileSync(process.env.B4_V6_FIXTURE,JSON.stringify(record));
});
test("V6 no overdue observation requires only one summary request",async()=>{
 const {a,frames}=owner((n,nonce)=>page(n,nonce,false));const v=await a.b4ReadOwnedStageV6(allowed);
 assert.equal(v.fault,null);assert.deepEqual(frames.map(f=>f.data[0]),[3]);
});
test("V6 rejects cross-snapshot, wrong stage, age and dirty frozen tail",async()=>{
 for(const kind of ["sequence","stage","age","tail"]){
  const {a,znp}=owner((n,nonce)=>{const b=page(n,nonce);if(n===4){
   if(kind==="sequence")b.writeUInt32LE(18,24);if(kind==="stage")b.writeUInt32LE(2,32);
   if(kind==="age")b.writeUInt32LE(1,52);if(kind==="tail")b[247]=1;
  }return b;});
  const v=await a.b4ReadOwnedStageV6(allowed);assert.equal(v.kind,"FAILED");assert.equal(znp.b4IsDiagPoisoned(),true);
 }
});
test("V6 production/OTA/disabled admission sends no diagnostic",async()=>{
 const {a,znp,frames}=owner();
 for(const x of [{...allowed,enabled:false},{...allowed,otaActive:true},{...allowed,stillAllowed:()=>false}])
  assert.equal(await a.b4ReadOwnedStageV6(x),undefined);
 const w=znp.waitress.waitFor({type:Type.SRSP,subsystem:Subsystem.AF,command:"dataRequest"},6000);
 assert.equal(await a.b4ReadOwnedStageV6(allowed),undefined);znp.waitress.remove(w.ID);assert.equal(frames.length,0);
});
test("V6 uses normal slots, retains busy demand and bounds V4/V5 service",async()=>{
 const r=spawnSync("python",["-c","import json,sys;sys.path.insert(0,'host/r4-b4');import b4_v6_stage_overlay as v;from b4_v5_live_collector_overlay import SAMPLE;print(json.dumps(v.STAGE_SAMPLE+SAMPLE.replace('this.#b4V5V4SlotsRemaining = 4;','this.#b4V6Turn=true;this.#b4V5V4SlotsRemaining = 4;')))"],{encoding:"utf8"});
 assert.equal(r.status,0,r.stderr);const body=JSON.parse(r.stdout);
 const T=new Function("process",`return class {#b4Operational=true;#b4EpochKey=Buffer.alloc(32,1);#b4V6Turn=true;#b4V5V4SlotsRemaining=0;#b4V5YieldToV4=false;
  zigbee={zhController:{b4NoWireOwnerSnapshotFromExistingOwner:()=>null}};calls=[];outcomes=[undefined,{kind:'FAILED',reason:'V6_REPLY_TIMEOUT',submissionState:'SENT_OR_UNCERTAIN'}];
  b4ProbeReadOnlyOwnedStageV6(){this.calls.push(6);return this.outcomes.shift();}
  b4ProbeReadOnlyHangFlightV5(){this.calls.push(5);return {kind:'FAILED',reason:'V5_REPLY_TIMEOUT',submissionState:'SENT_OR_UNCERTAIN'};}
  #b4Persist(x){} async sample(){const probeStarted=performance.now();${body}this.calls.push(4);}}`)
  ({env:{P7U_B4_STAGE_V6:"1",P7U_B4_FLIGHT_V5:"1"},hrtime:process.hrtime});
 const c=new T();for(let i=0;i<8;i++)await c.sample();assert.deepEqual(c.calls,[6,4,6,4,4,4,4,5]);
});
