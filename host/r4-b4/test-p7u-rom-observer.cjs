"use strict";
const {test}=require("node:test");
const assert=require("node:assert/strict");
const {EventEmitter}=require("node:events");
const fs=require("node:fs");const os=require("node:os");const path=require("node:path");const crypto=require("node:crypto");
const {spawnSync}=require("node:child_process");
const {FixedRomObserver,run}=require("./p7u_rom_observer.cjs");
const {PORT,OPERATION}=require("./p7u_preservation_probe.cjs");
function packet(b){return Buffer.from([b.length+2,b.reduce((a,v)=>a+v,0)&255,...b]);}
class Port extends EventEmitter {
    constructor(fault){super();this.sent=[];this.port={fd:12};this.isOpen=false;this.fault=fault;}
    async asyncOpen(){this.isOpen=true;}
    async asyncClose(){this.isOpen=false;this.emit("close");}
    write(b,cb){
        this.sent.push(Buffer.from(b));cb();
        if(b.equals(Buffer.from([0,0xcc])))return;
        if(this.fault==="silent")return;
        if(this.fault==="noise"){queueMicrotask(()=>this.emit("data",Buffer.alloc(129)));return;}
        if(this.fault==="nack"){queueMicrotask(()=>this.emit("data",Buffer.from([0,0x33])));return;}
        const op=b[2];const answer=op===0x23?packet([0x40]):op===0x28?packet([0,0,0x32,2]):Buffer.alloc(0);
        if(this.fault==="checksum"&&op===0x28)answer[1]^=1;
        if(this.fault==="length"&&op===0x28)answer[0]=255;
        const raw=Buffer.concat([Buffer.from([0,0xcc]),answer]);
        queueMicrotask(()=>{for(const byte of raw)this.emit("data",Buffer.from([byte]));});
    }
    drain(cb){cb();}
}
test("one typed observation sends only ROM ping/status/chip/status and data ACKs; no sync/reset/write opcode",async()=>{
    const p=new Port();const o=new FixedRomObserver(p);const r=await o.observeOnce();
    assert.equal(r.rom_protocol_observed,true);assert.equal(r.chip_id,0x3202);assert.equal(r.physical_board_attested,false);
    assert.deepEqual(p.sent.map(b=>b.toString("hex")),["032020","032323","00cc","032828","00cc","032323","00cc"]);
    await assert.rejects(o.observeOnce(),/CONSUMED/);assert.equal(p.sent.length,7);
    assert.equal(o.command,undefined);assert.equal(o.reset,undefined);
});
test("timeout/noise/nack/length/checksum consume observation without fallback or reset",async()=>{
    for(const fault of ["silent","noise","nack","length","checksum"]){
        const p=new Port(fault);const o=new FixedRomObserver(p);
        await assert.rejects(o.observeOnce(),/ROM_/);const count=p.sent.length;
        await assert.rejects(o.observeOnce(),/CONSUMED/);assert.equal(p.sent.length,count);
        for(const b of p.sent)assert.ok(b.equals(Buffer.from([0,0xcc]))||[0x20,0x23,0x28].includes(b[2]));
    }
});
function fixture(){
    const root=fs.mkdtempSync(path.join(os.tmpdir(),"p7u-rom-"));fs.chmodSync(root,0o700);const source="a".repeat(40);
    const plan={schema:"p7u-rom-observe-plan-v1",source_sha:source,operation_id:OPERATION,command:"TI_ROM_PING_CHIPID_NO_ENTRY_OR_RESET",
        serial_by_id:PORT,image_id:"sha256:"+"b".repeat(64),database_sha256:"c".repeat(64),backup_sha256:"d".repeat(64),
        history_sha256:{f1:"e".repeat(64)},original_container_id:"f".repeat(64),prior_result_sha256:{prior:"1".repeat(64)}};
    const raw=JSON.stringify(plan)+"\n";const pin=crypto.createHash("sha256").update(raw).digest("hex");
    fs.writeFileSync(path.join(root,"plan.json"),raw);fs.writeFileSync(path.join(root,"plan.sha256"),pin+"\n");
    fs.writeFileSync(path.join(root,"authority.intent.json"),JSON.stringify({schema:"p7u-preservation-authority-v1",operation_id:OPERATION,source_sha:source,plan_sha256:pin,utc_ms:Date.now()}));
    return{root,source,cleanup:()=>fs.rmSync(root,{recursive:true,force:true})};
}
const fakeStty=(bin,args)=>{assert.equal(bin,"/bin/stty");assert.ok(["--help","-hupcl","-a"].includes(args[0]));return Buffer.from("-hupcl;");};
test("durable intent precedes port construction; valid result, close and replay refusal",async()=>{
    const x=fixture();const p=new Port();
    try{
        const opts={...x,checkData:false,hardDeadline:false,stty:fakeStty,factory:()=>{assert.ok(fs.existsSync(path.join(x.root,"probe.attempt.json")));return p;}};
        const r=await run(opts);assert.equal(r.status,"ROM_PROTOCOL_OBSERVED");assert.equal(r.serial_closed,true);
        assert.equal(r.resets_requested,0);assert.equal(r.bootloader_entry_requested,false);assert.equal(p.isOpen,false);
        await assert.rejects(run(opts),/EEXIST/);
    }finally{x.cleanup();}
});
test("unknown result remains unknown and closes; failed HUPCL check emits zero bytes",async()=>{
    for(const badFlags of [false,true]){
        const x=fixture();const p=new Port("nack");
        try{const r=await run({...x,checkData:false,hardDeadline:false,factory:()=>p,
            stty:badFlags?()=>Buffer.from("hupcl;"):fakeStty});
            assert.equal(r.status,"ROM_STATE_UNKNOWN");assert.equal(r.observed,undefined);assert.equal(r.serial_closed,true);
            assert.equal(p.sent.length,badFlags?0:1);
        }finally{x.cleanup();}
    }
});
test("wrong protocol plan or stale authority rejected before opening",async()=>{
    for(const fault of ["protocol","stale"]){const x=fixture();try{
        if(fault==="protocol"){
            const file=path.join(x.root,"plan.json");const p=JSON.parse(fs.readFileSync(file));p.command="SYS_F1_B1Q1_OP0_ONCE";
            const raw=JSON.stringify(p)+"\n";fs.writeFileSync(file,raw);fs.writeFileSync(path.join(x.root,"plan.sha256"),crypto.createHash("sha256").update(raw).digest("hex"));
        }else{const file=path.join(x.root,"authority.intent.json");const a=JSON.parse(fs.readFileSync(file));a.utc_ms-=100000;fs.writeFileSync(file,JSON.stringify(a));}
        await assert.rejects(run({...x,checkData:false,factory:()=>{throw Error("must not open");}}),/P7U_PRESERVATION_/);
    }finally{x.cleanup();}}
});
test("real compiled SerialPort binding on PTY sends exact nonmutating transcript and leaves HUPCL clear",()=>{
    const x=fixture();try{
        const js=`const {SerialPort}=require(process.env.B4_HERDSMAN_ROOT+'/dist/adapter/serialPort.js');
const {run}=require(${JSON.stringify(path.resolve(__dirname,"p7u_rom_observer.cjs"))});
run({root:${JSON.stringify(x.root)},source:${JSON.stringify(x.source)},checkData:false,
factory:()=>new SerialPort({path:process.env.P7U_TEST_PTY,baudRate:115200,rtscts:false,hupcl:false,autoOpen:false})})
.then(r=>process.exit(r.status==='ROM_PROTOCOL_OBSERVED'&&r.serial_closed&&r.hupcl_disabled?0:2)).catch(()=>process.exit(3));`;
        const py=`import os,pty,termios,subprocess,sys,select,time
master,slave=pty.openpty();a=termios.tcgetattr(slave);a[2]|=termios.HUPCL;termios.tcsetattr(slave,termios.TCSANOW,a)
p=subprocess.Popen([sys.argv[1],'-e',sys.argv[2]],env=dict(os.environ,P7U_TEST_PTY=os.ttyname(slave)),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
expected=[bytes.fromhex(v) for v in ['032020','032323','00cc','032828','00cc','032323','00cc']]
pending=b'';i=0;deadline=time.monotonic()+10
while i<len(expected) and time.monotonic()<deadline:
 if not select.select([master],[],[],.1)[0]:continue
 pending+=os.read(master,128)
 while i<len(expected) and len(pending)>=len(expected[i]):
  frame=expected[i];assert pending[:len(frame)]==frame,(i,pending.hex());pending=pending[len(frame):];i+=1
  if frame==bytes.fromhex('032020'):os.write(master,bytes.fromhex('00cc'))
  if frame==bytes.fromhex('032323'):os.write(master,bytes.fromhex('00cc034040'))
  if frame==bytes.fromhex('032828'):os.write(master,bytes.fromhex('00cc063400003202'))
out,err=p.communicate(timeout=12)
assert p.returncode==0,(out,err)
assert i==len(expected) and not pending,i
assert not select.select([master],[],[],.1)[0]
assert termios.tcgetattr(slave)[2]&termios.HUPCL==0
os.close(slave);os.close(master)
`;
        const p=spawnSync("python",["-c",py,process.execPath,js],{encoding:"utf8",timeout:25000});assert.equal(p.status,0,p.stderr||p.stdout);
    }finally{x.cleanup();}
});
