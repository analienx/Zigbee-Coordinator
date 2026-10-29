"""Freeze first host warning without radio I/O; apply after V5 host overlays."""
import argparse,hashlib,json,subprocess
from pathlib import Path
from b4_v5_herdsman_overlay import once

ZNP=r'''
    private b4WarningSink: ((snapshot:Record<string,unknown>)=>void)|undefined;
    private b4WarningFrozen=false;
    private b4WarningOrdinal=0;
    private b4WarningTimer:ReturnType<typeof setTimeout>|undefined;
    private b4PendingWarning:{id:number;subsystem:string;operation:string;started:number;budget:number;warning:number}|undefined;
    private readonly b4OperationHistory:Array<Record<string,unknown>>=[];

    public b4SetFirstWarningSink(sink:((snapshot:Record<string,unknown>)=>void)|undefined):void {
        this.b4WarningSink=sink;
        this.b4EnablePassiveForensics(typeof sink==="function" || typeof this.b4HostTimeoutSink==="function");
        if(!sink && this.b4WarningTimer){clearTimeout(this.b4WarningTimer);this.b4WarningTimer=undefined;}
    }
    private b4OperationClass(name:string):string {
        // Canonical protocol operation names only; never payload/device text.
        return ["ping","version","register","dataRequest","dataRequestExt","dataRequestSrcRtg",
            "startupFromApp","nodeDescReq","activeEpReq","simpleDescReq","mgmtLqiReq","mgmtRtgReq",
            "mgmtBindReq","mgmtNwkUpdateReq","permitJoin","getDeviceInfo","getExtAddr","setTxPower"].includes(name)?name:"OTHER";
    }
    private b4WarningHistory(phase:"OFFERED"|"ACK"|"TIMEOUT"|"ERROR",op:NonNullable<Znp["b4PendingWarning"]>):void {
        const wire=this.unpiParser.b4NoWireIngress();
        const row={atMonoMs:Math.floor(performance.now()),operationId:op.id,subsystem:op.subsystem,
            operation:op.operation,phase,rxRawBytes:wire.rxRawBytes,parsedFrames:wire.unpiParsedFrames,
            parseErrors:wire.unpiParseErrors,bufferedBytes:wire.unpiBufferedBytes,
            queueDepth:this.queue.count,waiterMapEntries:this.waitress.b4PendingCount()};
        if(this.b4OperationHistory.length>=16)this.b4OperationHistory.shift();
        this.b4OperationHistory.push(row);
    }
    private b4BeginWarningOperation(subsystem:Subsystem,name:string,budget:number):number|undefined {
        if(!this.b4HostForensicsEnabled || !this.b4WarningSink)return undefined;
        const key=this.b4PassiveSrspKey(subsystem);
        if(key===null || !Number.isFinite(budget) || budget<=0)return undefined;
        if(this.b4WarningTimer)clearTimeout(this.b4WarningTimer);
        const op={id:++this.b4WarningOrdinal,subsystem:key,operation:this.b4OperationClass(name),
            started:Math.floor(performance.now()),budget:Math.floor(budget),
            warning:Math.min(4000,Math.max(250,Math.floor(budget*2/3)))};
        this.b4PendingWarning=op;this.b4WarningHistory("OFFERED",op);
        if(!this.b4WarningFrozen && op.warning<op.budget){
            this.b4WarningTimer=setTimeout(()=>{
                if(this.b4PendingWarning?.id===op.id)this.b4FreezeFirstWarning("PENDING_SLOW",op);
            },op.warning);
            this.b4WarningTimer.unref();
        }
        return op.id;
    }
    private b4FreezeFirstWarning(trigger:"PENDING_SLOW"|"SLOW_ACK"|"SRSP_TIMEOUT",op:NonNullable<Znp["b4PendingWarning"]>):void {
        if(this.b4WarningFrozen || !this.b4WarningSink)return;
        const now=Math.floor(performance.now()),elapsed=Math.max(0,now-op.started);
        const snapshot={schema:"p7u-host-first-warning-v1",trigger,capturedMonoMs:now,
            operation:{operationId:op.id,subsystem:op.subsystem,operation:op.operation,startedMonoMs:op.started,
                timeoutMs:op.budget,warningAfterMs:op.warning,elapsedMs:elapsed,
                timerLatenessMs:trigger==="PENDING_SLOW"?Math.max(0,elapsed-op.warning):null},
            ingressTiming:this.unpiParser.b4IngressTiming(),
            recentOperations:this.b4OperationHistory.map(row=>({...row})),
            scope:"HOST_WARNING_NOT_RADIO_FAULT_PROOF"};
        this.b4WarningFrozen=true; // Consume before optional IPC; never replay.
        try{this.b4WarningSink(snapshot);}catch{/* Evidence failure cannot alter production outcome. */}
    }
    private b4EndWarningOperation(id:number|undefined,phase:"ACK"|"TIMEOUT"|"ERROR"):void {
        const op=this.b4PendingWarning;if(id===undefined || op?.id!==id)return;
        if(this.b4WarningTimer){clearTimeout(this.b4WarningTimer);this.b4WarningTimer=undefined;}
        this.b4WarningHistory(phase,op);
        if(phase==="TIMEOUT")this.b4FreezeFirstWarning("SRSP_TIMEOUT",op);
        else if(phase==="ACK" && performance.now()-op.started>=op.warning)this.b4FreezeFirstWarning("SLOW_ACK",op);
        this.b4PendingWarning=undefined;
    }

'''

# Optional observation must never throw into a normal response or timer path.
for _name in ('b4WarningHistory','b4BeginWarningOperation','b4FreezeFirstWarning','b4EndWarningOperation'):
    _a=ZNP.index('    private '+_name+'(')
    _open=ZNP.index(' {',_a)+1
    _end=ZNP.index('\n    }',_open)
    _cleanup=('if(this.b4WarningTimer)clearTimeout(this.b4WarningTimer);this.b4WarningTimer=undefined;'
              'this.b4PendingWarning=undefined;return undefined;') if _name=='b4BeginWarningOperation' else ''
    ZNP=ZNP[:_open+1]+'\n        try {'+ZNP[_open+1:_end]+'\n        } catch {'+_cleanup+'}\n'+ZNP[_end:]

WARNING_SINK=r'''                        this.zigbee.zhController?.b4SetFirstWarningSinkFromExistingOwner((snapshot)=>{
                            if(!this.#b4Operational || !this.#b4WorkerReady)return;
                            const last=this.#b4LastWarningFlight;
                            const lastFlight=last?{record:structuredClone(last.record),receipt:{...last.receipt},
                                ageMs:Math.max(0,Math.floor(performance.now()-last.mono)),
                                ageBasis:"HOST_MONOTONIC_SINCE_SAMPLE_ENQUEUE"}:null;
                            const hostEvidence=this.zigbee.zhController?.b4NoWireOwnerSnapshotFromExistingOwner()??null;
                            // Only mark the next existing sampling opportunity due; no query here.
                            this.#b4V5V4SlotsRemaining=0;this.#b4V5YieldToV4=false;
                            this.#b4Persist({schema:"p7u-b4-native-sample-v1",kind:"FIRST_WARNING",utc:Date.now(),
                                monotonicReceiveNs:process.hrtime.bigint().toString(),
                                firstWarning:{...snapshot,lastFlight},hostEvidence});
                        });
                        this.zigbee.zhController?.b4SetHostTimeoutSinkFromExistingOwner('''

FLIGHT_ACK=r'''                const flight=this.#b4PendingWarningFlights.get(message.id);
                this.#b4PendingWarningFlights.delete(message.id);
                if(flight && message.receipt && /^[a-f0-9]{64}$/.test(message.receipt.sha256) &&
                    Number.isSafeInteger(message.receipt.sequence) && message.receipt.sequence>0 &&
                    Number.isSafeInteger(message.receipt.committedBytes) && message.receipt.committedBytes>0)
                    this.#b4LastWarningFlight={...flight,receipt:{...message.receipt}};
                this.#b4PendingIds.delete(message.id);'''

FLIGHT_TRACK=r'''            if(sample.kind==="FLIGHT")this.#b4PendingWarningFlights.set(id,{record:structuredClone(record),mono:performance.now()});
            this.#b4Worker.postMessage({type: "append", id, record});'''

def checked(root,pin):
    root=Path(root).resolve()
    if not str(root).startswith('/tmp/') or subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip()!=pin:
        raise ValueError('FIRST_WARNING_UNTRUSTED_CHECKOUT')
    return root

def herdsman(root):
    root=checked(root,'0968f979d558874b17396c96b66382d4236bbdcd');files={}
    p='src/adapter/z-stack/znp/znp.ts';s=(root/p).read_text()
    s=once(s,'    public b4GetPassiveOwnerMetrics() {',ZNP+'    public b4GetPassiveOwnerMetrics() {','WARNING_STATE')
    s=once(s,'        this.b4EnablePassiveForensics(typeof sink === "function");',
        '        this.b4EnablePassiveForensics(typeof sink === "function" || typeof this.b4WarningSink === "function");','WARNING_ENABLE_EITHER_SINK')
    s=once(s,'                const b4NormalAckStart = performance.now();',
        '                const b4NormalAckStart = performance.now();\n                const b4WarningOperation = isB4Diag ? undefined : this.b4BeginWarningOperation(object.subsystem, object.command.name, timeout || t);','WARNING_BEGIN_NORMAL')
    s=once(s,'                        this.b4PassiveNoteAck(object.subsystem, performance.now() - b4NormalAckStart);',
        '                        this.b4PassiveNoteAck(object.subsystem, performance.now() - b4NormalAckStart);\n                        this.b4EndWarningOperation(b4WarningOperation,"ACK");','WARNING_ACK_NORMAL')
    s=once(s,'                    this.b4RecordHostSreqTimeout(object.subsystem, object.command.name, timeout || t, error);',
        '''                    const b4IsTimeout=error instanceof Error && error.message===this.waitressTimeoutFormatter({type:Type.SRSP,subsystem:object.subsystem,command:object.command.name},timeout || t);
                    this.b4EndWarningOperation(b4WarningOperation,b4IsTimeout?"TIMEOUT":"ERROR");
                    this.b4RecordHostSreqTimeout(object.subsystem, object.command.name, timeout || t, error);''','WARNING_ERROR_NORMAL')
    s=once(s,'            const b4ZdoAckStart = performance.now();',
        '            const b4ZdoAckStart = performance.now();\n            const b4ZdoWarningOperation=this.b4BeginWarningOperation(Subsystem.ZDO,cmd.name,timeouts.SREQ);','WARNING_BEGIN_ZDO')
    s=once(s,'                this.b4PassiveNoteAck(Subsystem.ZDO, performance.now() - b4ZdoAckStart);',
        '                this.b4PassiveNoteAck(Subsystem.ZDO, performance.now() - b4ZdoAckStart);\n                this.b4EndWarningOperation(b4ZdoWarningOperation,"ACK");','WARNING_ACK_ZDO')
    s=once(s,'                this.b4RecordHostSreqTimeout(Subsystem.ZDO, cmd.name, timeouts.SREQ, error);',
        '''                const b4IsTimeout=error instanceof Error && error.message===this.waitressTimeoutFormatter({type:Type.SRSP,subsystem:Subsystem.ZDO,command:cmd.name},timeouts.SREQ);
                this.b4EndWarningOperation(b4ZdoWarningOperation,b4IsTimeout?"TIMEOUT":"ERROR");
                this.b4RecordHostSreqTimeout(Subsystem.ZDO, cmd.name, timeouts.SREQ, error);''','WARNING_ERROR_ZDO')
    s=once(s,'        logger.info("closing", NS);','        this.b4SetFirstWarningSink(undefined);\n        this.b4PendingWarning=undefined;\n        logger.info("closing", NS);','WARNING_CLOSE')
    files[p]=s
    p='src/adapter/z-stack/unpi/parser.ts';s=(root/p).read_text()
    s=once(s,'    public b4NoWireIngress() {',
        '''    private b4LastRxMonoMs:number|null=null;
    private b4LastParsedMonoMs:number|null=null;
    public b4IngressTiming(){return {lastRxMonoMs:this.b4LastRxMonoMs,lastParsedMonoMs:this.b4LastParsedMonoMs};}
    public b4NoWireIngress() {''','WARNING_PARSER_TIMING')
    s=once(s,'        this.b4RxBytes = Math.min(Number.MAX_SAFE_INTEGER, this.b4RxBytes + chunk.length);',
        '        if(chunk.length>0)this.b4LastRxMonoMs=Math.floor(performance.now());\n        this.b4RxBytes = Math.min(Number.MAX_SAFE_INTEGER, this.b4RxBytes + chunk.length);','WARNING_RX_TIME')
    s=once(s,'                    this.b4UnpiParsed = Math.min(Number.MAX_SAFE_INTEGER, this.b4UnpiParsed + 1);',
        '                    this.b4LastParsedMonoMs=Math.floor(performance.now());\n                    this.b4UnpiParsed = Math.min(Number.MAX_SAFE_INTEGER, this.b4UnpiParsed + 1);','WARNING_PARSED_TIME')
    files[p]=s
    for p,anchor,method in (
        ('src/adapter/z-stack/adapter/zStackAdapter.ts','    public b4SetHostTimeoutSink(',
         '''    public b4SetFirstWarningSink(sink:Parameters<Znp["b4SetFirstWarningSink"]>[0]):void {this.znp.b4SetFirstWarningSink(sink);}\n'''),
        ('src/controller/controller.ts','    public b4SetHostTimeoutSinkFromExistingOwner(',
         '''    public b4SetFirstWarningSinkFromExistingOwner(sink:Parameters<ZStackAdapter["b4SetFirstWarningSink"]>[0]):void {
        if(this.adapter instanceof ZStackAdapter)this.adapter.b4SetFirstWarningSink(sink);
    }\n''')):
        s=(root/p).read_text();files[p]=once(s,anchor,method+anchor,'WARNING_PROXY')
    return root,files

def z2m(root):
    root=checked(root,'62b02e2aa1997c574223b80c196677b63a25f4a7');p='lib/controller.ts';s=(root/p).read_text()
    s=once(s,'    #b4V5YieldToV4 = false;',
        '''    #b4V5YieldToV4 = false;
    #b4LastWarningFlight:{record:Record<string,unknown>;receipt:{sequence:number;sha256:string;committedBytes:number};mono:number}|null=null;
    readonly #b4PendingWarningFlights=new Map<number,{record:Record<string,unknown>;mono:number}>();''','WARNING_FLIGHT_CACHE')
    s=once(s,'worker.on("message", (message: {type?: string; id?: number; reason?: string}) => {',
        'worker.on("message", (message: {type?: string; id?: number; reason?: string; receipt?:{sequence:number;sha256:string;committedBytes:number}}) => {','WARNING_ACK_TYPE')
    s=once(s,'                        this.zigbee.zhController?.b4SetHostTimeoutSinkFromExistingOwner(',
        WARNING_SINK,'WARNING_FREEZE_SINK')
    s=once(s,'                this.#b4PendingIds.delete(message.id);',
        FLIGHT_ACK,'WARNING_COMMITTED_FLIGHT')
    s=once(s,'            this.#b4PendingIds.size >= 4)',
        '            this.#b4PendingIds.size >= (sample.kind === "FIRST_WARNING" ? 4 : 3))','WARNING_RESERVED_IPC_SLOT')
    s=once(s,'            this.#b4Worker.postMessage({type: "append", id, record});',
        FLIGHT_TRACK,'WARNING_QUEUE_FLIGHT')
    cleanup='            this.#b4PendingIds.delete(id);\n            this.#b4PendingNativeValidUtc.delete(id);'
    if s.count(cleanup)!=2:raise ValueError('WARNING_ACK_TIMEOUT_AND_SEND_FAILURE_CLEANUP_DRIFT')
    s=s.replace(cleanup,'            this.#b4PendingWarningFlights.delete(id);\n'+cleanup)
    s=once(s,'        this.zigbee.zhController?.b4SetHostTimeoutSinkFromExistingOwner(undefined);',
        '        this.zigbee.zhController?.b4SetFirstWarningSinkFromExistingOwner(undefined);\n        this.zigbee.zhController?.b4SetHostTimeoutSinkFromExistingOwner(undefined);','WARNING_SHUTDOWN')
    return root,{p:s}

if __name__=='__main__':
    ap=argparse.ArgumentParser();g=ap.add_mutually_exclusive_group(required=True)
    g.add_argument('--herdsman');g.add_argument('--z2m');ap.add_argument('--receipt',required=True)
    args=ap.parse_args();root,files=herdsman(args.herdsman) if args.herdsman else z2m(args.z2m)
    for p,s in files.items():(root/p).write_text(s,encoding='utf-8',newline='')
    Path(args.receipt).write_text(json.dumps({'schema':'p7u-host-first-warning-source-v1','radio_requests':0,
        'warning_is_radio_fault_proof':False,'history_events':16,'reserved_worker_slots':1,
        'files_sha256':{p:hashlib.sha256(s.encode()).hexdigest() for p,s in files.items()}},sort_keys=True)+'\n')
