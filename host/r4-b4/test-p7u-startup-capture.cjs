"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict");
const path=require("node:path"),{performance}=require("node:perf_hooks");
const root=process.env.B4_HERDSMAN_ROOT;
if(!root || !root.startsWith("/tmp/"))throw Error("Actual compiled pinned owner required");
const mod=p=>require(path.join(root,"dist",p));
const {Znp}=mod("adapter/z-stack/znp/znp.js");
const {Frame}=mod("adapter/z-stack/unpi/frame.js");
const {Type,Subsystem}=mod("adapter/z-stack/unpi/constants.js");
const {ZnpAdapterManager}=mod("adapter/z-stack/adapter/manager.js");
const {logger}=mod("utils/logger.js");
async function flush(){for(let i=0;i<20;i++)await Promise.resolve();}

test("the existing owner captures a startup warning before open completes without extra requests",async t=>{
    const old=process.env.P7U_B4_STARTUP_CAPTURE;
    process.env.P7U_B4_STARTUP_CAPTURE="1";
    t.after(()=>{if(old===undefined)delete process.env.P7U_B4_STARTUP_CAPTURE;else process.env.P7U_B4_STARTUP_CAPTURE=old;});
    let now=100000;t.mock.method(performance,"now",()=>now);t.mock.timers.enable({apis:["setTimeout"]});
    const lines=[];t.mock.method(logger,"info",message=>lines.push(String(message)));
    const znp=new Znp("/dev/never-opened",115200,false),sent=[];
    znp.initialized=true;znp.unpiWriter.writeFrame=f=>sent.push(f);
    znp.openSerialPort=()=>znp.requestWithReply(Subsystem.SYS,"ping",{},undefined,6000).then(()=>undefined);
    const opened=znp.open();await flush();
    znp.unpiParser.write(Buffer.from([0xfe,32,0x41]));
    now+=4000;t.mock.timers.tick(4000);await flush();
    assert.equal(sent.length,1);
    const warning=lines.find(s=>s.startsWith("P7U_STARTUP_WARNING "));
    assert.ok(warning,"warning is emitted during startup, before an operational worker exists");
    const captured=JSON.parse(warning.substring("P7U_STARTUP_WARNING ".length));
    assert.equal(captured.operation.operation,"ping");assert.equal(captured.trigger,"PENDING_SLOW");
    assert.equal(captured.ingressTiming.lastParsedMonoMs,null);
    znp.onUnpiParsed(new Frame(Type.SRSP,Subsystem.SYS,1,Buffer.from([1,0])));
    await opened;
    assert.ok(lines.some(s=>s.includes('"phase":"OWNER_OPENED"')));
    assert.equal(sent.length,1);assert.ok(!warning.includes("/dev/") && !warning.includes("payload"));
});

test("startup capture is opt-in and observer errors cannot fail startup",async t=>{
    const old=process.env.P7U_B4_STARTUP_CAPTURE;delete process.env.P7U_B4_STARTUP_CAPTURE;
    t.after(()=>{if(old===undefined)delete process.env.P7U_B4_STARTUP_CAPTURE;else process.env.P7U_B4_STARTUP_CAPTURE=old;});
    let logs=0;t.mock.method(logger,"info",()=>{logs++;throw Error("sink failure");});
    const znp=new Znp("/dev/never-opened",115200,false);znp.openSerialPort=async()=>{};
    await znp.open();assert.equal(logs,0);
    process.env.P7U_B4_STARTUP_CAPTURE="1";await znp.open();assert.ok(logs>0);
});

test("the real retained manager records the state-change wait without a second startup",async t=>{
    const old=process.env.P7U_B4_STARTUP_CAPTURE;process.env.P7U_B4_STARTUP_CAPTURE="1";
    t.after(()=>{if(old===undefined)delete process.env.P7U_B4_STARTUP_CAPTURE;else process.env.P7U_B4_STARTUP_CAPTURE=old;});
    let now=100000;t.mock.method(performance,"now",()=>now);t.mock.timers.enable({apis:["setTimeout"]});
    const phases=[],requests=[];let finish;
    const stateReady=new Promise(resolve=>{finish=resolve;});
    const znp={requestWithReply:async()=>({payload:{devicestate:0}}),
        waitFor:()=>({start:()=>({promise:stateReady})}),
        request:async(...args)=>{requests.push(args);},b4StartupTrace:phase=>phases.push(phase)};
    const manager=new ZnpAdapterManager({},znp,{});
    manager.p7uRetainedNetworkValidated=true;manager.p7uRequireRetainedR4Status=async()=>{};
    const pending=manager.beginStartup();await flush();
    assert.deepEqual(phases,["ZDO_START_OFFERED","ZDO_START_ACK"]);
    now+=4000;t.mock.timers.tick(4000);await flush();
    assert.deepEqual(phases,["ZDO_START_OFFERED","ZDO_START_ACK","STATE_CHANGE_PENDING"]);
    finish();await pending;
    assert.deepEqual(phases,["ZDO_START_OFFERED","ZDO_START_ACK","STATE_CHANGE_PENDING","STATE9_READY"]);
    assert.equal(requests.length,1);assert.equal(requests[0][1],"startupFromApp");
});

test("startup remains successful when optional trace callbacks throw",async ()=>{
    const znp={requestWithReply:async()=>({payload:{devicestate:0}}),
        waitFor:()=>({start:()=>({promise:Promise.resolve()})}),request:async()=>{},
        b4StartupTrace:()=>{throw Error("evidence unavailable");}};
    const manager=new ZnpAdapterManager({},znp,{});
    manager.p7uRetainedNetworkValidated=true;manager.p7uRequireRetainedR4Status=async()=>{};
    await manager.beginStartup();
});

test("state-change metadata includes only the parsed state, no frame payload",t=>{
    const old=process.env.P7U_B4_STARTUP_CAPTURE;process.env.P7U_B4_STARTUP_CAPTURE="1";
    t.after(()=>{if(old===undefined)delete process.env.P7U_B4_STARTUP_CAPTURE;else process.env.P7U_B4_STARTUP_CAPTURE=old;});
    const lines=[];t.mock.method(logger,"info",message=>lines.push(String(message)));
    const znp=new Znp("/dev/never-opened",115200,false);znp.b4StartStartupCapture();
    znp.onUnpiParsed(new Frame(Type.AREQ,Subsystem.ZDO,192,Buffer.from([9])));
    const line=lines.find(s=>s.includes('"phase":"STATE_CHANGE_IND"'));
    assert.ok(line);const row=JSON.parse(line.substring("P7U_STARTUP_TRACE ".length));
    assert.equal(row.networkState,9);assert.ok(!Object.hasOwn(row,"payload"));
});
