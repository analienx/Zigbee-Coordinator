"use strict";
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const {spawnSync} = require("node:child_process");
const probe = require("./p7u_preservation_probe.cjs");
const root = process.env.B4_HERDSMAN_ROOT;
assert.ok(root?.startsWith("/tmp/"));
const {Znp} = require(path.join(root,"dist/adapter/z-stack/znp/znp.js"));
const {Frame} = require(path.join(root,"dist/adapter/z-stack/unpi/frame.js"));
const {Type,Subsystem} = require(path.join(root,"dist/adapter/z-stack/unpi/constants.js"));
const QUERY = Buffer.from([0x42,0x31,0x51,0x31,1,8,0,0]);
function response() {
    const b=Buffer.alloc(24);b.write("B1S1");b[4]=1;b[5]=24;b[6]=2;b[7]=0x21;b[8]=0xe6;b[9]=7;b[10]=0x21;b[11]=4;Buffer.from("323949a9","hex").copy(b,12);return b;
}
async function owner() {
    const z=new Znp(probe.PORT,115200,false);
    z.open=async()=>{z.initialized=true;};
    await z.p7uOpenPreservationOnly();return z;
}
test("same compiled owner admits only one exact F1 and no ping/reset/NV/ZDO/startup",async()=>{
    const z=await owner();const writes=[];
    z.unpiWriter.writeFrame=f=>{writes.push(f.commandID);queueMicrotask(()=>z.onUnpiParsed(new Frame(Type.SRSP,Subsystem.SYS,241,response())));};
    for(const [sub,cmd,payload] of [[1,"ping",{}],[1,"resetReq",{type:1}],[1,"osalNvWrite",{}],[5,"startupFromApp",{startdelay:100}],
        [1,"p7uRetainedStatus",{query:Buffer.alloc(8)}],[1,"p7uRetainedStatus",{query:Buffer.from([0x42,0x31,0x51,0x31,1,8,1,0])}]]) {
        assert.throws(()=>z.request(sub,cmd,payload,undefined,15),/ONLY_ONE_FIXED_F1/);
    }
    assert.throws(()=>z.requestZdo(0x0036,Buffer.alloc(0)),/ZDO_DISABLED/);
    const r=await z.requestWithReply(1,"p7uRetainedStatus",{query:QUERY},undefined,15);
    assert.equal(probe.decode(r.payload.snapshot).stage,2);
    assert.deepEqual(writes,[241]);
    assert.throws(()=>z.request(1,"p7uRetainedStatus",{query:QUERY},undefined,15),/ONLY_ONE_FIXED_F1/);
    await assert.rejects(z.p7uOpenPreservationOnly(),/OWNER_NOT_FRESH_OR_PINNED/);
});
test("genuine F1 timeout consumes the only read and never falls back",async()=>{
    const z=await owner();const writes=[];z.unpiWriter.writeFrame=f=>writes.push(f.commandID);
    await assert.rejects(z.requestWithReply(1,"p7uRetainedStatus",{query:QUERY},undefined,15),/after 15ms/);
    assert.throws(()=>z.request(1,"p7uRetainedStatus",{query:QUERY},undefined,15),/ONLY_ONE_FIXED_F1/);
    assert.deepEqual(writes,[241]);
});
test("transport refuses socket, different USB device, baud or flow control",async()=>{
    for(const args of [["tcp://192.168.50.59:6638",115200,false],["/dev/ttyFAKE",115200,false],[probe.PORT,9600,false],[probe.PORT,115200,true]]) {
        const z=new Znp(...args);let opened=false;z.open=async()=>{opened=true;};
        await assert.rejects(z.p7uOpenPreservationOnly(),/NOT_FRESH_OR_PINNED/);assert.equal(opened,false);
    }
});
test("actual skipBootloader branch clears inherited HUPCL on its owned PTY descriptor, with no UART write",()=>{
    const js=`const {Znp}=require(process.env.B4_HERDSMAN_ROOT+'/dist/adapter/z-stack/znp/znp.js');
    const z=new Znp('${probe.PORT}',115200,false);let writes=0;z.unpiWriter.writeBuffer=()=>{writes++;};z.unpiWriter.writeFrame=()=>{writes++;};
    z.open=async()=>{z.path=process.env.P7U_TEST_PTY;await z.openSerialPort();};
    z.p7uOpenPreservationOnly().then(async r=>{if(writes!==0||r.hupclDisabled!==true)process.exit(2);await z.close();}).catch(()=>process.exit(3));`;
    const py=`import os,pty,termios,subprocess,sys
master,slave=pty.openpty()
a=termios.tcgetattr(slave);a[2]|=termios.HUPCL;termios.tcsetattr(slave,termios.TCSANOW,a)
env=dict(os.environ,P7U_TEST_PTY=os.ttyname(slave))
p=subprocess.run([sys.argv[1],'-e',sys.argv[2]],env=env,pass_fds=(slave,),capture_output=True,text=True,timeout=10)
assert p.returncode==0,p.stderr
assert termios.tcgetattr(slave)[2]&termios.HUPCL==0
os.close(slave);os.close(master)
`;
    const p=spawnSync("python",["-c",py,process.execPath,js],{encoding:"utf8"});assert.equal(p.status,0,p.stderr||p.stdout);
});
function fixture() {
    const root=fs.mkdtempSync(path.join(os.tmpdir(),"p7u-preserve-"));fs.chmodSync(root,0o700);
    const source="a".repeat(40);
    const plan={schema:"p7u-preservation-f1-plan-v1",source_sha:source,operation_id:probe.OPERATION,command:"SYS_F1_B1Q1_OP0_ONCE",
        serial_by_id:probe.PORT,image_id:"sha256:"+"b".repeat(64),database_sha256:"c".repeat(64),backup_sha256:"d".repeat(64),
        history_sha256:{old:"e".repeat(64)},original_container_id:"f".repeat(64),prior_result_sha256:{previous:"1".repeat(64)}};
    const raw=JSON.stringify(plan)+"\n";const pin=crypto.createHash("sha256").update(raw).digest("hex");
    fs.writeFileSync(path.join(root,"plan.json"),raw);fs.writeFileSync(path.join(root,"plan.sha256"),pin+"\n");
    fs.writeFileSync(path.join(root,"authority.intent.json"),JSON.stringify({schema:"p7u-preservation-authority-v1",operation_id:probe.OPERATION,source_sha:source,plan_sha256:pin,utc_ms:Date.now()}));
    return {root,source,cleanup:()=>fs.rmSync(root,{recursive:true,force:true})};
}
function fake(reply=response()) {
    let initialized=false;const calls=[];
    return {calls,p7uOpenPreservationOnly:async()=>{calls.push("open");initialized=true;return{hupclDisabled:true};},
        requestWithReply:async(sub,cmd,payload,id,timeout)=>{calls.push(cmd);assert.equal(sub,1);assert.deepEqual(payload.query,QUERY);assert.equal(timeout,2000);
            if(reply instanceof Error)throw reply;return{payload:{snapshot:reply}};},close:async()=>{calls.push("close");initialized=false;},isInitialized:()=>initialized};
}
test("program writes intent before open, captures held F1 honestly, closes, and refuses replay",async()=>{
    const x=fixture();const z=fake();
    try {
        const out=await probe.run({...x,factory:()=>{assert.ok(fs.existsSync(path.join(x.root,"probe.attempt.json")));return z;},checkData:false,hardDeadline:false});
        assert.equal(out.status,"F1_OBSERVED");assert.equal(out.observed.stage,2);assert.equal(out.observed.network_recovery_verified,false);
        assert.equal(out.serial_closed,true);assert.deepEqual(z.calls,["open","p7uRetainedStatus","close"]);
        await assert.rejects(probe.run({...x,factory:()=>{throw Error("must not construct");},checkData:false,hardDeadline:false}),/EEXIST/);
    } finally{x.cleanup();}
});
test("unknown or malformed response is preserved without retry or fabricated state",async()=>{
    for(const reply of [new Error("SRSP - SYS - p7uRetainedStatus after 2000ms"),Buffer.alloc(24),Buffer.alloc(25)]) {
        const x=fixture();const z=fake(reply);
        try {const r=await probe.run({...x,factory:()=>z,checkData:false,hardDeadline:false});assert.equal(r.status,"PROBE_FAILED_STATE_UNKNOWN");assert.equal(r.observed,undefined);assert.equal(r.serial_closed,true);assert.equal(z.calls.filter(v=>v==="p7uRetainedStatus").length,1);}
        finally{x.cleanup();}
    }
});
test("wrong source, stale authority, changed plan or symlink fail before transport construction",async()=>{
    for(const mode of ["source","stale","tamper","symlink"]) {
        const x=fixture();let constructed=false;
        try {
            if(mode==="source")x.source="f".repeat(40);
            if(mode==="stale") {const p=path.join(x.root,"authority.intent.json");const d=JSON.parse(fs.readFileSync(p));d.utc_ms-=90001;fs.writeFileSync(p,JSON.stringify(d));}
            if(mode==="tamper")fs.appendFileSync(path.join(x.root,"plan.json")," ");
            if(mode==="symlink") {fs.renameSync(path.join(x.root,"plan.json"),path.join(x.root,"other"));fs.symlinkSync("other",path.join(x.root,"plan.json"));}
            await assert.rejects(probe.run({...x,factory:()=>{constructed=true;return fake();},checkData:false,hardDeadline:false}));
            assert.equal(constructed,false);
        }finally{x.cleanup();}
    }
});
