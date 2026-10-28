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
test("V5 both pages use same one owner, 9-byte F2, no second serial",async()=>{
 const {owner,frames,znp}=adapterWithLink();
 const out=await owner.b4ReadHangFlightV5(allowed);
 assert.equal(out?.abi,5);
 assert.equal(out?.pageSequence,17);
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
test("V5 bad page nonce or epoch quarantines, never exports stale evidence",async()=>{
 for(const kind of ["nonce","epoch","page"]){
   const {owner,znp}=adapterWithLink((page,nonce)=>{
     const b=pages(page,nonce);
     if(page===2&&kind==="nonce")b[8]^=0xff;
     if(page===2&&kind==="epoch")b.writeUInt32LE(18,24);
     if(page===2&&kind==="page")b[5]=255;
     return b;
   });
   assert.equal(await owner.b4ReadHangFlightV5(allowed),undefined);
   assert.equal(znp.b4IsDiagPoisoned(),true);
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
test("V5 legacy V4 SYS F2 request remains buffer8",()=>{
 const {ZpiObject}=mod("adapter/z-stack/znp/zpiObject.js");
 const n=Buffer.from("0102030405060708","hex");
 const frame=ZpiObject.createRequest(Subsystem.SYS,"r4DiagReadOnlyV4",{nonce:n}).unpiFrame;
 assert.equal(frame.data.length,8);
 assert.equal(frame.commandID,242);
});
