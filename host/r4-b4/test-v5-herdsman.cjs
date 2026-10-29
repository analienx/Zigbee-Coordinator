/* V5 real compiled herdsman single-owner 9-byte F2 test; NO serial open. */
"use strict";
const test=require("node:test");
const assert=require("node:assert/strict");
const path=require("node:path");
const root=process.env.B4_HERDSMAN_ROOT;
if(!root || !path.isAbsolute(root) || !root.startsWith("/tmp/"))throw Error("pinned checkout required");
const mod=p=>require(path.join(root,"dist",...p.split("/")));
const {ZStackAdapter}=mod("adapter/z-stack/adapter/zStackAdapter.js");
const {Znp}=mod("adapter/z-stack/znp/znp.js");
const {Frame}=mod("adapter/z-stack/unpi/frame.js");
const {Subsystem,Type}=mod("adapter/z-stack/unpi/constants.js");

function pages(page,nonce){
 const b=Buffer.alloc(160);
 b.write("R4D5",0,"ascii");b[4]=5;b[5]=page;b[6]=160;
 nonce.copy(b,8);
 for(let i=0;i<8;i++)b[16+i]=i+1;
 b.writeUInt32LE(17,24);b.writeUInt32LE(250,28);
 if(page===1){
   b.writeUInt32LE(4,32);b.writeUInt32LE(100,36);
   b.writeUInt32LE(2,40);b.writeUInt32LE(200,44);
   b.writeUInt32LE(2,48);b.writeUInt32LE(210,52);
   b.writeUInt32LE(1,56);b.writeUInt32LE(7,60);
   b.writeUInt32LE(1,64);b.writeUInt32LE(0,72);
   b.writeUInt32LE(3,104);b.writeUInt32LE(1,108);b.writeUInt32LE(10,112);
 }else{
   b.writeUInt32LE(240,32);b.writeUInt16LE(0x6400,36);b[38]=4;
 }
 return b;
}
function adapterWithLink(chooser=pages) {
 const znp=new Znp("/dev/never-opened",115200,false);
 znp.initialized=true; // Synthetic active owner, DO NOT open a port.
 const frames=[];
 znp.unpiWriter.writeFrame=frame=>{
   frames.push(frame);
   const page=frame.data[0],nonce=frame.data.subarray(1);
   queueMicrotask(()=>znp.onUnpiParsed(new Frame(
       Type.SRSP,Subsystem.SYS,0xf2,chooser(page,nonce))));
 };
 const owner=Object.create(ZStackAdapter.prototype);
 owner.znp=znp;owner.queue={count:()=>0};
 owner.closing=false;owner.interpanLock=false;
 owner.b4DiagInFlight=false;owner.b4NextAllowedMs=0;
 return {znp,owner,frames};
}
const allowed={enabled:true,hostIdle:true,otaActive:false,stillAllowed:()=>true};

test("V5 production traffic winning admission between pages defers without poison or timeout forgiveness",async()=>{
 const {owner,znp,frames}=adapterWithLink();
 const original=znp.b4ReadV5Page.bind(znp);let blocker;
 znp.b4F2ConsecutiveTimeouts=1;znp.b4F2NextAllowedMs=0;znp.b4F2ProgressAtTimeout=-1;znp.b4F2OwnerProgress=0;
 znp.b4ReadV5Page=async(page,nonce)=>{
  const result=await original(page,nonce);
  if(page===1)blocker=znp.waitress.waitFor({type:Type.SRSP,subsystem:Subsystem.AF,command:"dataRequest"},6000);
  return result;
 };
 const out=await owner.b4ReadHangFlightV5(allowed);
 assert.equal(out.reason,"V5_PARTIAL_PAIR_OWNER_BUSY");assert.equal(frames.length,1);
 assert.equal(znp.b4IsDiagPoisoned(),false);assert.equal(znp.b4F2ConsecutiveTimeouts,1);
 znp.waitress.remove(blocker.ID);assert.equal(znp.waitress.waiters.size,0);
});
test("V5 both pages use same one owner, 9-byte F2, no second serial",async()=>{
 const {owner,frames,znp}=adapterWithLink();
 znp.b4F2ConsecutiveTimeouts=1;
 znp.b4F2NextAllowedMs=0;
 znp.b4F2ProgressAtTimeout=-1;
 znp.b4F2OwnerProgress=0;
 const out=await owner.b4ReadHangFlightV5(allowed);
 assert.equal(znp.b4F2ConsecutiveTimeouts,0);
 assert.equal(out?.abi,5);
 assert.equal(out?.pageSequence,17);
 assert.equal(out?.radioBootId,"0102030405060708");
 assert.equal(out?.counters.reserveExhausted,1);
 assert.equal(out?.eventCount,1);
 assert.equal(out?.events[0].stage,4);
 assert.equal(out?.events[0].subsystem,"AF");
 assert.deepEqual(frames.map(f=>f.commandID),[242,242]);
 assert.deepEqual(frames.map(f=>f.data.length),[9,9]);
 assert.equal(frames[0].data[0],1);
 assert.equal(frames[1].data[0],2);
 assert.deepEqual(frames[0].data.subarray(1),frames[1].data.subarray(1));
 assert.equal(znp.waitress.waiters.size,0);
 assert.equal(znp.b4IsDiagPoisoned(),false);
 assert.equal(owner.b4DiagInFlight,false);
});
test("V5 successful partial page must not erase prior timeout count",async()=>{
 const {znp}=adapterWithLink();
 // Prior timed-out probe; cooldown elapsed and normal owner progress advanced.
 znp.b4F2ConsecutiveTimeouts=1;
 znp.b4F2NextAllowedMs=0;
 znp.b4F2ProgressAtTimeout=-1;
 znp.b4F2OwnerProgress=0;
 const nonce=Buffer.from("0102030405060708","hex");
 const page1=await znp.b4ReadV5Page(1,nonce);
 assert.equal(page1[5],1);
 assert.equal(znp.b4F2ConsecutiveTimeouts,1);
 const page2=await znp.b4ReadV5Page(2,nonce);
 assert.equal(page2[5],2);
 // Only the complete, validated adapter may acknowledge success.
 assert.equal(znp.b4F2ConsecutiveTimeouts,1);
});
test("V5 bad page nonce or epoch quarantines, never exports stale evidence",async()=>{
 for(const kind of ["nonce","epoch","page"]){
   const {owner,znp}=adapterWithLink((page,nonce)=>{
     const b=pages(page,nonce);
     if(page===2&&kind==="nonce")b[8]^=0xff;
     if(page===2&&kind==="epoch")b.writeUInt32LE(18,24);
     if(page===2&&kind==="page")b[5]=255;
     return b;
   });
   const outcome=await owner.b4ReadHangFlightV5(allowed);
   assert.equal(outcome?.kind,"FAILED");
   assert.equal(outcome?.submissionState,"SENT_OR_UNCERTAIN");
   if(kind==="nonce"){
     assert.equal(outcome?.reason,"V5_REPLY_TIMEOUT");
     assert.equal(znp.b4IsDiagPoisoned(),false);
     assert.equal(znp.b4F2ReadAdmissionReason(),"F2_TIMEOUT_COOLDOWN");
   }else{
     assert.equal(outcome?.reason,"V5_INVALID_OR_UNCERTAIN");
     assert.equal(znp.b4IsDiagPoisoned(),true);
   }
 }
});
test("V5 disabled/OTA/live SRSP veto without sending any diagnostic",async()=>{
 const {owner,frames,znp}=adapterWithLink();
 for(const input of [
   {...allowed,enabled:false},{...allowed,hostIdle:false},
   {...allowed,otaActive:true},{...allowed,stillAllowed:()=>false}
 ])assert.equal(await owner.b4ReadHangFlightV5(input),undefined);
 const srsp=znp.waitress.waitFor({type:Type.SRSP,subsystem:Subsystem.ZDO,command:"permitJoin"},3000);
 assert.equal(await owner.b4ReadHangFlightV5(allowed),undefined);
 assert.equal(frames.length,0);
 znp.waitress.remove(srsp.ID);
});
test("V5 corrupt boot validity, future tick, and forged anomaly are quarantined",async()=>{
 for(const bad of ["boot","tick","anomaly","dirty"]){
   const {owner,znp}=adapterWithLink((page,nonce)=>{
     const b=pages(page,nonce);
     if(page===1&&bad==="boot")b.writeUInt32LE(2,104);
     if(page===2&&bad==="tick")b.writeUInt32LE(251,32);
     if(page===1&&bad==="anomaly"){
       b.writeUInt32LE(7,104);b[158]=3;b[159]=1;
     }
     if(page===1&&bad==="dirty")b[152]=1;
     return b;
   });
   const outcome=await owner.b4ReadHangFlightV5(allowed);
   assert.equal(outcome?.kind,"FAILED");
   assert.equal(outcome?.submissionState,"SENT_OR_UNCERTAIN");
   assert.equal(znp.b4IsDiagPoisoned(),true);
 }
});
test("V5 first frozen anomaly is preserved and sanitized",async()=>{
 const {owner}=adapterWithLink((page,nonce)=>{
   const b=pages(page,nonce);
   if(page===1){
     b.writeUInt32LE(7,104);
     b.writeUInt32LE(220,144);b.writeUInt16LE(0x6422,148);b[150]=6;
     b.writeUInt32LE(221,152);b.writeUInt16LE(0x6422,156);b[158]=8;b[159]=1;
   }
   return b;
 });
 const out=await owner.b4ReadHangFlightV5(allowed);
 assert.equal(out?.preAnomaly?.stage,6);
 assert.equal(out?.firstAnomaly?.stage,8);
 assert.equal(out?.firstAnomaly?.subsystem,"AF");
});
test("V5 impossible reserve counts rejected by actual-owner parser",async()=>{
 for(const kind of ["active","release"]){
   const {owner,znp}=adapterWithLink((page,nonce)=>{
     const b=pages(page,nonce);
     if(page===1&&kind==="active")b.writeUInt32LE(8,72);
     if(page===1&&kind==="release")b.writeUInt32LE(8,68);
     return b;
   });
   const out=await owner.b4ReadHangFlightV5(allowed);
   assert.equal(out?.kind,"FAILED");
   assert.equal(out?.submissionState,"SENT_OR_UNCERTAIN");
   assert.equal(znp.b4IsDiagPoisoned(),true);
 }
});
test("V5 page1 already submitted before guard revocation is FAILED",async()=>{
 let still=true;
 const {owner,frames,znp}=adapterWithLink((page,nonce)=>{
   const b=pages(page,nonce);
   if(page===1)still=false;
   return b;
 });
 const out=await owner.b4ReadHangFlightV5({...allowed,stillAllowed:()=>still});
 assert.equal(out?.kind,"FAILED");
 assert.equal(out?.reason,"V5_PARTIAL_PAIR_OWNER_REVOKED");
 assert.equal(out?.submissionState,"SENT_OR_UNCERTAIN");
 assert.equal(frames.length,1);
 assert.equal(znp.b4IsDiagPoisoned(),false);
});
test("V5 missing SRSP counts as V4 cooldown and never claims no wire",{timeout:12000},async()=>{
 const {owner,frames,znp}=adapterWithLink();
 znp.unpiWriter.writeFrame=frame=>{frames.push(frame);};
 const out=await owner.b4ReadHangFlightV5(allowed);
 assert.equal(out?.kind,"FAILED");
 assert.equal(out?.reason,"V5_REPLY_TIMEOUT");
 assert.equal(out?.submissionState,"SENT_OR_UNCERTAIN");
 assert.equal(frames.length,1);
 assert.equal(znp.b4IsDiagPoisoned(),false);
 assert.equal(znp.b4F2ReadAdmissionReason(),"F2_TIMEOUT_COOLDOWN");
});
test("V5 legacy V4 SYS F2 request remains buffer8",()=>{
 const {ZpiObject}=mod("adapter/z-stack/znp/zpiObject.js");
 const n=Buffer.from("0102030405060708","hex");
 const frame=ZpiObject.createRequest(Subsystem.SYS,"r4DiagReadOnlyV4",{nonce:n}).unpiFrame;
 assert.equal(frame.data.length,8);
 assert.equal(frame.commandID,242);
});
