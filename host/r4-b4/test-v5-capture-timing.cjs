"use strict";
// Execute the actual emitted collector body; no serial, broker or live owner.
const {test}=require("node:test");
const assert=require("node:assert/strict");
const {spawnSync}=require("node:child_process");
const {createHmac}=require("node:crypto");
const fixture=spawnSync("python",["-c",
    "import runpy,json;print(json.dumps(runpy.run_path('host/r4-b4/b4_v5_live_collector_overlay.py')['SAMPLE']))"],{encoding:"utf8"});
assert.equal(fixture.status,0,fixture.stderr);
const body=JSON.parse(fixture.stdout);
const factory=new Function("process","createHmac",`return class {
    #b4Operational=true; #b4EpochKey=Buffer.alloc(32,1);
    #b4V5V4SlotsRemaining=0; #b4V5YieldToV4=false;
    zigbee={zhController:{b4NoWireOwnerSnapshotFromExistingOwner:()=>({passive:true})}};
    outcomes=[]; calls=[]; records=[];
    b4ProbeReadOnlyHangFlightV5(){this.calls.push(5);return this.outcomes.shift();}
    #b4Persist(row){this.records.push(row);}
    stop(){this.#b4Operational=false;}
    async sample(){const probeStarted=performance.now();${body}this.calls.push(4);}
}`);
const good=()=>({abi:5,pageSequence:1,radioBootId:null,counters:{},events:[]});
function collector(enabled=true){
    const Type=factory({env:{P7U_B4_FLIGHT_V5:enabled?"1":"0"},hrtime:process.hrtime},createHmac);
    return new Type();
}
test("first normal opportunity is V5; successful pairs preserve four V4 slots",async()=>{
    const c=collector();c.outcomes=[good(),good()];
    for(let i=0;i<6;i++)await c.sample();
    assert.deepEqual(c.calls,[5,4,4,4,4,5]);
    assert.deepEqual(c.records.map(x=>x.kind),["FLIGHT","FLIGHT"]);
    assert.equal(c.records[0].radioEpochTag,null);
    assert.equal("radioBootId" in c.records[0].flightV5,false);
});
test("busy skips retain capture demand while preserving V4 bounded admission",async()=>{
    const c=collector();c.outcomes=[undefined,undefined,good()];
    for(let i=0;i<5;i++)await c.sample();
    assert.deepEqual(c.calls,[5,4,5,4,5]);
    assert.deepEqual(c.records.map(x=>x.kind),["SKIPPED","SKIPPED","FLIGHT"]);
    assert.equal(c.records[0].submissionState,"NONE");
});
test("submitted failure remains FAILED and does not create a fast retry loop",async()=>{
    const c=collector();c.outcomes=[{kind:"FAILED",reason:"V5_REPLY_TIMEOUT",submissionState:"SENT_OR_UNCERTAIN"},good()];
    for(let i=0;i<6;i++)await c.sample();
    assert.deepEqual(c.calls,[5,4,4,4,4,5]);
    assert.equal(c.records[0].kind,"FAILED");
    assert.equal(c.records[0].submissionState,"SENT_OR_UNCERTAIN");
});
test("a known page-two busy refusal retains demand and yields one V4 slot",async()=>{
    const c=collector();c.outcomes=[{kind:"FAILED",reason:"V5_PARTIAL_PAIR_OWNER_BUSY",submissionState:"SENT_OR_UNCERTAIN"},good()];
    for(let i=0;i<3;i++)await c.sample();
    assert.deepEqual(c.calls,[5,4,5]);assert.equal(c.records[0].submissionState,"SENT_OR_UNCERTAIN");
});
test("disabled V5 preserves V4 slots; stopping prevents committing a flight",async()=>{
    const c=collector(false);for(let i=0;i<6;i++)await c.sample();
    assert.deepEqual(c.calls,[4,4,4,4,4,4]);assert.equal(c.records.length,0);
    const stopped=collector();stopped.b4ProbeReadOnlyHangFlightV5=()=>{stopped.stop();return good();};
    await stopped.sample();assert.equal(stopped.records.length,0);
});
