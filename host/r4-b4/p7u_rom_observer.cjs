"use strict";
/** One fixed ROM-protocol observation. No BSL entry, sync pulse, reset, NV,
 * network startup, HTTP or caller-supplied opcode. A timeout consumes the run.
 * PING/GET_STATUS/GET_CHIP_ID framing matches pinned SMLIGHT command.py
 * SHA256 9fb42418ffa2301be52bfa2fe1208fb465138c2cc4cf432a767df2f6860ee25a.
 */
const fs = require("node:fs");
const path = require("node:path");
const {execFileSync} = require("node:child_process");
const {admission,unique,PORT,OPERATION} = require("./p7u_preservation_probe.cjs");
const ROOT = "/share/p7u-lifecycle/private/rom-observe";
const ACK = Buffer.from([0,0xcc]);
class FixedRomObserver {
    #port; #buffer=Buffer.alloc(0); #waiter; #fault; #consumed=false;
    constructor(port) {
        this.#port=port;
        port.on("data", data => {
            if(this.#buffer.length+data.length>128){this.#fault=Error("ROM_NOISE_LIMIT");this.#wake();return;}
            this.#buffer=Buffer.concat([this.#buffer,data]);this.#wake();
        });
        port.on("error",()=>{this.#fault=Error("ROM_TRANSPORT_ERROR");this.#wake();});
        port.on("close",()=>{this.#fault=Error("ROM_TRANSPORT_CLOSED");this.#wake();});
    }
    #wake(){if(this.#waiter){const w=this.#waiter;this.#waiter=undefined;w();}}
    async #read(n) {
        const deadline=Date.now()+1500;
        while(this.#buffer.length<n) {
            if(this.#fault)throw this.#fault;
            const left=deadline-Date.now();if(left<=0)throw Error("ROM_READ_TIMEOUT");
            await new Promise(resolve=>{let timer;const done=()=>{clearTimeout(timer);if(this.#waiter===done)this.#waiter=undefined;resolve();};this.#waiter=done;timer=setTimeout(done,left);});
        }
        if(this.#fault)throw this.#fault;
        const b=this.#buffer.subarray(0,n);this.#buffer=this.#buffer.subarray(n);return b;
    }
    async #write(data) {
        if(this.#fault)throw this.#fault;
        await new Promise((resolve,reject)=>this.#port.write(data,e=>e?reject(Error("ROM_WRITE_ERROR")):resolve()));
        await new Promise((resolve,reject)=>this.#port.drain(e=>e?reject(Error("ROM_DRAIN_ERROR")):resolve()));
    }
    async #command(op, length) {
        // Private, no arbitrary payload/address/length or mutation API exists.
        if(![0x20,0x23,0x28].includes(op))throw Error("ROM_OPCODE_DENIED");
        await this.#write(Buffer.from([3,op,op]));
        if(!(await this.#read(2)).equals(ACK))throw Error("ROM_ACK_UNQUALIFIED");
        if(length===0)return undefined;
        const h=await this.#read(2);
        if(h[0]!==length+2)throw Error("ROM_RESPONSE_LENGTH");
        const b=await this.#read(length);
        if((b.reduce((a,v)=>a+v,0)&255)!==h[1])throw Error("ROM_RESPONSE_CHECKSUM");
        await this.#write(ACK);return b;
    }
    async #status(){const b=await this.#command(0x23,1);if(b[0]!==0x40)throw Error("ROM_STATUS_UNQUALIFIED");}
    async observeOnce() {
        if(this.#consumed)throw Error("ROM_OBSERVATION_CONSUMED");
        this.#consumed=true;
        await this.#command(0x20,0);await this.#status();
        const chip=await this.#command(0x28,4);await this.#status();
        if(this.#buffer.length!==0)throw Error("ROM_UNEXPECTED_TRAILING_BYTES");
        const id=(chip[2]<<8)|chip[3];if(id===0||id===0xffff)throw Error("ROM_CHIP_ID_UNQUALIFIED");
        return {rom_protocol_observed:true,chip_id:id,physical_board_attested:false,network_recovery_verified:false};
    }
}
function makePort() {
    const {SerialPort}=require("/app/node_modules/.pnpm/zigbee-herdsman@10.9.1/node_modules/zigbee-herdsman/dist/adapter/serialPort.js");
    return new SerialPort({path:PORT,baudRate:115200,rtscts:false,hupcl:false,autoOpen:false});
}
async function run({root=ROOT,source,factory=makePort,checkData=true,stty=execFileSync,hardDeadline=true}={}) {
    source=source??fs.readFileSync(path.join(__dirname,"P7U_SOURCE_SHA.txt"),"utf8").trim();
    const {pin}=admission(root,source,checkData,"rom-observe");
    if(process.platform!=="linux")throw Error("ROM_LINUX_ONLY");
    stty("/bin/stty",["--help"],{timeout:2000,stdio:"ignore"});
    const common={schema:"p7u-rom-observe-result-v1",source_sha:source,operation_id:OPERATION,plan_sha256:pin,
        only_command:"TI_ROM_PING_CHIPID_NO_ENTRY_OR_RESET",resets_requested:0,nv_writes_requested:0,
        bootloader_entry_requested:false,explicit_modem_line_toggles:0,normal_network_startup:false};
    unique(path.join(root,"probe.attempt.json"),{...common,utc_ms:Date.now()});
    let port,result={...common,status:"ROM_STATE_UNKNOWN",serial_closed:false,utc_ms:Date.now()};
    const timer=hardDeadline?setTimeout(()=>{try{unique(path.join(root,"probe.result.json"),{...result,status:"DEADLINE_STATE_UNKNOWN"});}finally{process.exit(3);}},12000):null;
    try {
        port=factory();const observer=new FixedRomObserver(port);
        await port.asyncOpen();
        const fd=port.port?.fd;if(!Number.isSafeInteger(fd)||fd<0)throw Error("ROM_FD_UNAVAILABLE");
        stty("/bin/stty",["-hupcl"],{timeout:2000,stdio:[fd,"ignore","pipe"]});
        const flags=stty("/bin/stty",["-a"],{timeout:2000,stdio:[fd,"pipe","pipe"]}).toString();
        if(!/(?:^|\s)-hupcl(?:[;\s]|$)/.test(flags))throw Error("ROM_HUPCL_UNQUALIFIED");
        result.hupcl_disabled=true;
        result.observed=await observer.observeOnce();result.status="ROM_PROTOCOL_OBSERVED";
    }catch(error){result.error_class=error instanceof Error&&/^ROM_[A-Z_]+$/.test(error.message)?error.message:"ROM_TRANSPORT_ERROR";}
    finally {
        try{if(port?.isOpen)await port.asyncClose();result.serial_closed=!port?.isOpen;}
        catch{result.status="CLOSE_UNCONFIRMED_STATE_UNKNOWN";result.serial_closed=false;}
        clearTimeout(timer);
    }
    result.utc_ms=Date.now();unique(path.join(root,"probe.result.json"),result);return result;
}
if(require.main===module)run().then(r=>{console.log(JSON.stringify(r));process.exitCode=r.serial_closed&&r.status==="ROM_PROTOCOL_OBSERVED"?0:2;})
    .catch(()=>{console.error(JSON.stringify({status:"HOLD_NO_REPLAY"}));process.exitCode=3;});
module.exports={FixedRomObserver,run,ROOT};
