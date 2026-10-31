/* V7 real compiled herdsman B1 sampler: same Znp mutex, one SREQ at a time; NO serial open. */
"use strict";
const test=require("node:test");
const assert=require("node:assert/strict");
const fs=require("node:fs");
const os=require("node:os");
const path=require("node:path");
const root=process.env.B4_HERDSMAN_ROOT;
if(!root || !path.isAbsolute(root) || !root.startsWith("/tmp/"))throw Error("pinned checkout required");
const mod=p=>require(path.join(root,"dist",...p.split("/")));
const {ZStackAdapter}=mod("adapter/z-stack/adapter/zStackAdapter.js");
const {Znp}=mod("adapter/z-stack/znp/znp.js");
const {Frame}=mod("adapter/z-stack/unpi/frame.js");
const {Subsystem,Type}=mod("adapter/z-stack/unpi/constants.js");
const TAGS=["B1E2","B1E3","B1E4","B1E5","B1E6"];

function page(tag,length=248){
 const b=Buffer.alloc(length);b.write(tag,0,"ascii");b[4]=1;b[5]=length&255;return b;
}
function link(reply=(p)=>page(TAGS[p])){
 const journal=path.join(fs.mkdtempSync(path.join(os.tmpdir(),"p7u-v7-")),"b1.jsonl");
 process.env.P7U_B1_SAMPLER_JOURNAL=journal;
 const znp=new Znp("/dev/never-opened",115200,false);
 znp.initialized=true; // synthetic active owner, DO NOT open a port
 const frames=[];
 znp.unpiWriter.writeFrame=frame=>{
  frames.push(frame);
  if(frame.subsystem===Subsystem.SYS && frame.commandID===0xf1)
   queueMicrotask(()=>znp.onUnpiParsed(new Frame(Type.SRSP,Subsystem.SYS,0xf1,reply(frame.data[7]))));
 };
 const owner=Object.create(ZStackAdapter.prototype);
 owner.znp=znp;owner.closing=false;owner.p7uB1InFlight=false;owner.p7uB1Slot=0;
 const lines=()=>fs.existsSync(journal)?fs.readFileSync(journal,"utf8").trim().split("\n").map(JSON.parse):[];
 return {znp,owner,frames,lines};
}

test("V7 slot reads B1E2+B1E6 every time and B1E3+B1E5 every 10th, journaled raw",async()=>{
 const {owner,frames,lines}=link();
 const first=await owner.p7uB1Sample();
 assert.equal(first.outcome,"SAMPLED");
 assert.deepEqual(frames.map(f=>f.data[7]),[0,4,1,3]);
 for(const f of frames)assert.deepEqual([...f.data.subarray(0,7)],[0x42,0x31,0x51,0x31,1,8,4]);
 const second=await owner.p7uB1Sample();
 assert.deepEqual(frames.slice(4).map(f=>f.data[7]),[0,4]);
 assert.equal(second.B1E2.slice(0,8),Buffer.from("B1E2").toString("hex"));
 const rows=lines();
 assert.equal(rows.length,2);assert.ok(rows[0].B1E3 && rows[0].B1E5 && rows[1].B1E6);
});

test("V7 never puts a second SREQ in flight: it waits behind production on the same mutex",async()=>{
 const {owner,znp,frames}=link();
 const ping=znp.request(Subsystem.SYS,"ping",{capabilities:1},undefined,2000);
 await new Promise(r=>setImmediate(r));
 const sampling=owner.p7uB1Sample();
 await new Promise(r=>setTimeout(r,30));
 assert.equal(frames.length,1,"sampler must not write while the production SREQ is outstanding");
 assert.equal(frames[0].commandID,1);
 znp.onUnpiParsed(new Frame(Type.SRSP,Subsystem.SYS,1,Buffer.from([0x79,0x01])));
 await ping;
 const record=await sampling;
 assert.equal(record.outcome,"SAMPLED");
 assert.deepEqual(frames.slice(1).map(f=>f.data[7]),[0,4,1,3]);
});

test("V7 overlap and closing are journaled, never reported as zero samples",async()=>{
 const {owner,frames,lines}=link();
 owner.p7uB1InFlight=true;
 assert.equal((await owner.p7uB1Sample()).outcome,"OVERLAP_PREVIOUS_SLOT_STILL_WAITING");
 owner.p7uB1InFlight=false;owner.closing=true;
 assert.equal((await owner.p7uB1Sample()).outcome,"ADAPTER_CLOSING");
 assert.equal(frames.length,0);
 assert.deepEqual(lines().map(r=>r.outcome),["OVERLAP_PREVIOUS_SLOT_STILL_WAITING","ADAPTER_CLOSING"]);
});

test("V7 wrong page shape is an error field, never accepted data",async()=>{
 const {owner}=link(p=>page(p===4?"B1E2":TAGS[p]));
 const record=await owner.p7uB1Sample();
 assert.equal(record.B1E6,undefined);assert.equal(record.B1E6_error,"B1_PAGE_SHAPE");
 assert.ok(record.B1E2);
});

test("V7 is default OFF and keeps a 30 s floor",()=>{
 const owner=Object.create(ZStackAdapter.prototype);
 delete process.env.P7U_B1_SAMPLER;owner.p7uB1Start();assert.equal(owner.p7uB1Timer,undefined);
 process.env.P7U_B1_SAMPLER="1";process.env.P7U_B1_SAMPLER_MS="5";
 owner.p7uB1Start();assert.ok(owner.p7uB1Timer);
 assert.equal(owner.p7uB1Timer._idleTimeout,30000);
 clearInterval(owner.p7uB1Timer);delete process.env.P7U_B1_SAMPLER;delete process.env.P7U_B1_SAMPLER_MS;
});

test("V7 F1 codec accepts exactly 24 or 248 bytes only",()=>{
 const {ZpiObject}=mod("adapter/z-stack/znp/zpiObject.js");
 assert.equal(ZpiObject.fromUnpiFrame(new Frame(Type.SRSP,Subsystem.SYS,241,page("B1E6"))).payload.snapshot.length,248);
 for(const length of [0,23,25,100,247,249])
  assert.throws(()=>ZpiObject.fromUnpiFrame(new Frame(Type.SRSP,Subsystem.SYS,241,Buffer.alloc(length))));
});
