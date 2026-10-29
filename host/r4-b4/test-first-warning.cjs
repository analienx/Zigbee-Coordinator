"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict");
const {performance}=require("node:perf_hooks");
const path=require("node:path"),fs=require("node:fs"),os=require("node:os");
const {randomUUID}=require("node:crypto");
const root=process.env.B4_HERDSMAN_ROOT;
if(!root || !root.startsWith("/tmp/"))throw Error("Actual compiled pinned owner required");
const mod=p=>require(path.join(root,"dist",p));
const {Znp}=mod("adapter/z-stack/znp/znp.js");
const {Frame}=mod("adapter/z-stack/unpi/frame.js");
const {Type,Subsystem}=mod("adapter/z-stack/unpi/constants.js");
const worker=require("./p7u_diagnostic_worker.cjs");
async function flush(){for(let i=0;i<15;i++)await Promise.resolve();}
function setup(t){
    let now=100000;t.mock.method(performance,"now",()=>now);t.mock.timers.enable({apis:["setTimeout"]});
    const znp=new Znp("/dev/never-opened",115200,false);znp.initialized=true;
    const sent=[],snapshots=[];znp.unpiWriter.writeFrame=f=>sent.push(f);
    znp.b4SetFirstWarningSink(s=>snapshots.push(s));
    const ping=(timeout=6000)=>znp.requestWithReply(Subsystem.SYS,"ping",{},undefined,timeout);
    const receive=(data=Buffer.from([1,0]),id=1)=>znp.onUnpiParsed(new Frame(Type.SRSP,Subsystem.SYS,id,data));
    const advance=async ms=>{now+=ms;t.mock.timers.tick(ms);await flush();};
    return {znp,sent,snapshots,ping,receive,advance,moveClock:ms=>now+=ms};
}
test("first slow pending operation freezes host state without another wire request",async t=>{
    const h=setup(t);const pending=h.ping();
    h.znp.unpiParser.write(Buffer.from([0xfe,32,0x41])); // Raw bytes, incomplete UNPI frame.
    await h.advance(4000);
    assert.equal(h.sent.length,1);assert.equal(h.snapshots.length,1);
    const snap=structuredClone(h.snapshots[0]);
    assert.equal(snap.trigger,"PENDING_SLOW");assert.equal(snap.operation.operation,"ping");
    assert.equal(snap.operation.elapsedMs,4000);assert.equal(snap.operation.timeoutMs,6000);
    assert.equal(snap.recentOperations.at(-1).phase,"OFFERED");
    assert.equal(snap.ingressTiming.lastRxMonoMs,100000);
    assert.equal(snap.ingressTiming.lastParsedMonoMs,null);
    assert.equal(snap.scope,"HOST_WARNING_NOT_RADIO_FAULT_PROOF");
    h.receive();await pending;
    for(let i=0;i<20;i++){const p=h.ping();h.receive();await p;}
    assert.equal(h.snapshots.length,1);assert.deepEqual(h.snapshots[0],snap);
    assert.ok(h.znp.b4OperationHistory.length<=16);
    assert.equal(h.znp.b4PendingWarning,undefined);
});
test("late event-loop acknowledgement records SLOW_ACK rather than a fabricated radio fault",async t=>{
    const h=setup(t);const p=h.ping();h.moveClock(4200);h.receive();await p;
    assert.equal(h.snapshots[0].trigger,"SLOW_ACK");
    assert.equal(h.snapshots[0].operation.elapsedMs,4200);
    assert.equal(h.snapshots[0].operation.timerLatenessMs,null);
    assert.equal(h.znp.b4WarningTimer,undefined);
});
test("first timeout retains original error and consumes no diagnostic transaction",async t=>{
    const h=setup(t);const p=h.ping(200);const rejected=assert.rejects(p,/SRSP - SYS - ping after 200ms/);
    await h.advance(200);await rejected;
    assert.equal(h.snapshots.length,1);assert.equal(h.snapshots[0].trigger,"SRSP_TIMEOUT");
    assert.equal(h.sent.length,1);assert.equal(h.znp.b4IsDiagPoisoned(),false);
});
test("an evidence sink failure cannot reject a successful production SRSP",async t=>{
    const h=setup(t);h.znp.b4SetFirstWarningSink(()=>{throw Error("IPC failure");});
    const p=h.ping();await h.advance(4000);h.receive();await p;
    assert.equal(h.znp.b4PendingWarning,undefined);assert.equal(h.znp.b4IsDiagPoisoned(),false);
});
test("F2 diagnostics do not manufacture production first-warning events",async t=>{
    const h=setup(t),nonce=Buffer.from("0102030405060708","hex");
    const p=h.znp.requestWithReply(Subsystem.SYS,"r4DiagReadOnlyV4",{nonce},undefined,6000);
    await h.advance(4000);assert.equal(h.snapshots.length,0);
    const body=Buffer.alloc(160);body.write("R4D4");nonce.copy(body,132);h.receive(body,242);await p;
    assert.equal(h.snapshots.length,0);
});
test("first-warning journal survives reopen and rejects arbitrary identifiers/payload fields",async t=>{
    const h=setup(t);const p=h.ping();await h.advance(4000);h.receive();await p;
    const row={schema:"p7u-b4-native-sample-v1",kind:"FIRST_WARNING",utc:Date.now(),
        monotonicReceiveNs:process.hrtime.bigint().toString(),hostRunId:randomUUID(),ownerGeneration:randomUUID(),
        processUptimeMs:100000,firstWarning:{...h.snapshots[0],lastFlight:null},hostEvidence:null};
    if(process.env.B4_FIRST_WARNING_FIXTURE){
        assert.ok(process.env.B4_FIRST_WARNING_FIXTURE.startsWith('/tmp/'));
        fs.writeFileSync(process.env.B4_FIRST_WARNING_FIXTURE,JSON.stringify(row));
    }
    const temp=fs.mkdtempSync(path.join(os.tmpdir(),"p7u-first-warning-"));
    try{
        const dir=path.join(temp,"history"),store=worker.open(dir);worker.commit(store,row);
        assert.deepEqual(worker.open(dir).records.at(-1).firstWarning,row.firstWarning);
        for(const bad of [
            {...row.firstWarning,rawPayload:"secret"},
            {...row.firstWarning,operation:{...row.firstWarning.operation,operation:"device-secret"}},
            {...row.firstWarning,lastFlight:{record:{kind:"FIRST_WARNING"}}},
        ])assert.throws(()=>worker.commit(store,{...row,firstWarning:bad}),/FIRST_WARNING/);
    }finally{fs.rmSync(temp,{recursive:true,force:true});}
});

test("the actual collector caches only ACKed flights and queues no radio read at warning time",()=>{
    const {spawnSync}=require('node:child_process');
    const p=spawnSync('python',['-c',
        "import sys,runpy,json;sys.path.insert(0,'host/r4-b4');m=runpy.run_path('host/r4-b4/b4_first_warning_overlay.py');print(json.dumps({k:m[k] for k in ('WARNING_SINK','FLIGHT_ACK','FLIGHT_TRACK')}))"],{encoding:'utf8'});
    assert.equal(p.status,0,p.stderr);const blocks=JSON.parse(p.stdout);
    const sink=blocks.WARNING_SINK.split('                        this.zigbee.zhController?.b4SetHostTimeoutSinkFromExistingOwner(')[0];
    const Type=new Function(`return class {
        #b4Operational=true;#b4WorkerReady=true;#b4LastWarningFlight=null;
        #b4PendingWarningFlights=new Map();#b4PendingIds=new Set();
        #b4V5V4SlotsRemaining=4;#b4V5YieldToV4=true;
        rows=[];callback=null;
        zigbee={zhController:{b4NoWireOwnerSnapshotFromExistingOwner:()=>null,
            b4SetFirstWarningSinkFromExistingOwner:cb=>{this.callback=cb;}}};
        #b4Persist(row){this.rows.push(row);}
        install(){${sink}}
        track(record){const sample=record,id=1;${blocks.FLIGHT_TRACK.split('            this.#b4Worker.postMessage')[0]}}
        ack(message){${blocks.FLIGHT_ACK}}
        due(){return this.#b4V5V4SlotsRemaining===0 && !this.#b4V5YieldToV4;}
    }`)();
    const c=new Type();c.install();const record={kind:'FLIGHT',sentinel:1};c.track(record);
    c.callback({trigger:'PENDING_SLOW'});assert.equal(c.rows[0].firstWarning.lastFlight,null);
    assert.equal(c.due(),true);
    record.sentinel=999;
    const receipt={sequence:42,sha256:'a'.repeat(64),committedBytes:1000};c.ack({id:1,receipt});
    c.callback({trigger:'PENDING_SLOW'});
    assert.equal(c.rows[1].firstWarning.lastFlight.record.sentinel,1);
    assert.deepEqual(c.rows[1].firstWarning.lastFlight.receipt,receipt);
    assert.equal(c.rows[1].kind,'FIRST_WARNING');
});
