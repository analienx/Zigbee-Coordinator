"""Paired V6 stage evidence through the existing diagnostic owner and safe slots."""
import argparse,hashlib,json
from pathlib import Path
from b4_first_warning_overlay import checked
from b4_v5_herdsman_overlay import ZNP_METHOD,ADAPTER_METHOD,once
from b4_v5_live_collector_overlay import Z2M_METHOD

ZNP=ZNP_METHOD.replace('b4ReadV5Page(page: 1 | 2','b4ReadV6Page(page: 3 | 4 | 5 | 6 | 7 | 8')
ZNP=ZNP.replace('(page !== 1 && page !== 2)','(page < 3 || page > 8)')
ZNP=ZNP.replace('data.length !== 160','data.length !== (page===3?160:248)').replace('"R4D5"','"R4D6"')
ZNP=ZNP.replace('data[4] !== 5','data[4] !== 6').replace('data.readUInt16LE(6) !== 160','data.readUInt16LE(6) !== data.length')
ZNP=ZNP.replace('V5_','V6_').replace('V5_REPLY_TIMEOUT','V6_REPLY_TIMEOUT')

PARSER=r'''
    private b4V6Command(command:number):{subsystem:string;operation:string} {
        const sub=(command>>8)&31,id=command&255;
        return {subsystem:sub===4?"AF":sub===1?"SYS":sub===5?"ZDO":"OTHER",
            operation:sub===4 && id>=1 && id<=3?["dataRequest","dataRequestExt","dataRequestSrcRtg"][id-1]:
                sub===4 && id===0?"register":sub===1 && id===1?"ping":sub===1 && id===2?"version":"OTHER"};
    }
    private b4ParseV6(a:Buffer,b:Buffer|undefined) {
        const fields=["monitorFlags","tickPeriodUs","monitorChecks","lastCheckTick","maxCheckGapTicks",
            "npiWakes","npiLastTick","stackDispatchEntered","stackLastEnteredTick","stackDispatchExited",
            "stackLastExitedTick","stackActiveService","uartComplete","uartLastCompleteTick","faultMask",
            "firstObservedStage","mtFastBudgetTicks","mtOtherBudgetTicks","srspQueueBudgetTicks",
            "asyncQueueBudgetTicks","uartBudgetTicks","mtStageId","","mtSinceTick","txStageId","","txSinceTick",
            "srspQueuedBytes","asyncQueuedBytes","selectedFaultStage","ingressTrackingOverflow"];
        const counters:Record<string,number>={};
        fields.forEach((name,i)=>{if(name)counters[name]=a.readUInt32LE(32+4*i);});
        if(counters.monitorFlags>7 || !(counters.monitorFlags&1) || counters.tickPeriodUs<1 ||
            counters.tickPeriodUs>100000 || counters.faultMask>31 || counters.firstObservedStage>5 ||
            counters.selectedFaultStage>5 || a.readUInt32LE(24)===0 || !a.subarray(156).equals(Buffer.alloc(4)) ||
            Boolean(counters.monitorFlags&2)!==a.subarray(16,24).some(v=>v!==0) ||
            Boolean(counters.faultMask)!==Boolean(counters.selectedFaultStage) ||
            Boolean(counters.faultMask)!==Boolean(counters.firstObservedStage) ||
            (counters.firstObservedStage && !(counters.faultMask&(1<<(counters.firstObservedStage-1)))) ||
            a.readUInt32LE(120)>65535 || a.readUInt32LE(132)>65535 ||
            (counters.selectedFaultStage && !(counters.faultMask&(1<<(counters.selectedFaultStage-1)))))
            throw Error("B4 V6_INVALID_SUMMARY");
        let fault:Record<string,unknown>|null=null;
        if(b){
            if(!a.subarray(8,32).equals(b.subarray(8,32)) || b[5]!==3+counters.selectedFaultStage)
                throw Error("B4 V6_CROSS_PAGE_MISMATCH");
            const names=["stage","stageId","","enteredTick","observedTick","ageTicks","budgetTicks","pendingFlags",
                "mtStageId","txStageId","srspQueuedBytes","asyncQueuedBytes","npiWakes","stackDispatchEntered",
                "stackDispatchExited","uartComplete","eventCount","eventTotal","srspProducedAtMtEnter",
                "srspProducedAtObservation","stackActiveService","observationFlags"];
            const values:Record<string,number>={};names.forEach((name,i)=>{if(name)values[name]=b.readUInt32LE(32+4*i);});
            if(values.stage!==counters.selectedFaultStage || !values.stageId || !values.budgetTicks || b.readUInt32LE(40)>65535 ||
                values.ageTicks<values.budgetTicks || values.ageTicks>=0x80000000 ||
                ((values.observedTick-values.enteredTick)>>>0)!==values.ageTicks ||
                values.eventCount>16 || values.eventCount!==Math.min(values.eventTotal,16) ||
                values.pendingFlags>63 || values.observationFlags!==values.pendingFlags ||
                !b.subarray(120+8*values.eventCount).equals(Buffer.alloc(128-8*values.eventCount)))
                throw Error("B4 V6_INVALID_FAULT");
            const events:Array<Record<string,number|string>>=[];
            for(let i=0;i<values.eventCount;i++){
                const off=120+8*i,stage=b[off+6],result=b[off+7];
                if(stage<1 || stage>9 || (stage===8 && result===0))throw Error("B4 V6_INVALID_HISTORY");
                events.push({tick:b.readUInt32LE(off),stage,result,...this.b4V6Command(b.readUInt16LE(off+4))});
            }
            fault={...values,...this.b4V6Command(b.readUInt32LE(40)),events};
        } else if(counters.selectedFaultStage)throw Error("B4 V6_MISSING_FAULT");
        return {abi:6 as const,source:"RADIO_READ_ONLY" as const,scope:"OVERDUE_OBSERVATION_NOT_PERMANENT_FAULT" as const,
            ownerScope:"INGRESS_MT_SHARED_FRAME_LOCAL_QUEUE_TX" as const,pageSequence:a.readUInt32LE(24),
            nativeTick:a.readUInt32LE(28),counters,mtOperation:this.b4V6Command(a.readUInt32LE(120)),
            txOperation:this.b4V6Command(a.readUInt32LE(132)),fault,
            radioBootId:(counters.monitorFlags&2)?a.subarray(16,24).toString("hex"):null};
    }
'''
# Reuse the reviewed one-owner admission, timeout/cooldown and finally guard.
gate=ADAPTER_METHOD[ADAPTER_METHOD.index('        if (input?.enabled'):ADAPTER_METHOD.index('            const a = await')]
tail=ADAPTER_METHOD[ADAPTER_METHOD.index('        } catch (error)'):]
tail=tail.replace('V5_','V6_')
ADAPTER=PARSER+r'''
    public async b4ReadOwnedStageV6(input:{enabled:boolean;hostIdle:boolean;otaActive:boolean;stillAllowed:()=>boolean}) {
'''+gate+r'''
            const a=await this.znp.b4ReadV6Page(3,nonce);
            const selected=a.readUInt32LE(148);
            if(selected>5)throw Error("B4 V6_INVALID_SELECTION");
            if(!input.stillAllowed() || this.closing || this.interpanLock)
                return {kind:"FAILED" as const,reason:"V6_PARTIAL_PAIR_OWNER_REVOKED" as const,submissionState:"SENT_OR_UNCERTAIN" as const};
            const b=selected?await this.znp.b4ReadV6Page((selected+3) as 4|5|6|7|8,nonce):undefined;
            const decoded=this.b4ParseV6(a,b);
            this.znp.b4F2AcceptReply();return decoded;
'''+tail

def herdsman(root):
 root=checked(root,'0968f979d558874b17396c96b66382d4236bbdcd');out={}
 for rel in ('src/adapter/z-stack/znp/znp.ts','src/adapter/z-stack/adapter/zStackAdapter.ts','src/controller/controller.ts'):
  s=(root/rel).read_text()
  if rel.endswith('/znp.ts'):
   s=once(s,'    public async b4ReadV5Page(page:',ZNP+'    public async b4ReadV5Page(page:','V6_ZNP')
   s=once(s,'                   zpiObject.payload.diagnostic.length === 160 &&\n                   zpiObject.payload.diagnostic.subarray(0,4).toString("ascii") === "R4D5" &&\n                   zpiObject.payload.diagnostic[4] === 5 &&',
    '''                   ((zpiObject.payload.diagnostic.length === 160 &&
                     zpiObject.payload.diagnostic.subarray(0,4).toString("ascii") === "R4D5" &&
                     zpiObject.payload.diagnostic[4] === 5 && matcher.b4F2Nonce[0]<=2) ||
                    (zpiObject.payload.diagnostic.length === (matcher.b4F2Nonce[0]===3?160:248) &&
                     zpiObject.payload.diagnostic.subarray(0,4).toString("ascii") === "R4D6" &&
                     zpiObject.payload.diagnostic[4] === 6 && matcher.b4F2Nonce[0]>=3 && matcher.b4F2Nonce[0]<=8)) &&''','V6_MATCHER')
  elif rel.endswith('/zStackAdapter.ts'):
   s=once(s,'    public async b4ReadHangFlightV5(input:',ADAPTER+'    public async b4ReadHangFlightV5(input:','V6_ADAPTER')
  else:
   sig='    public async b4ReadHangFlightV5FromExistingOwner(input:'
   proxy='''    public async b4ReadOwnedStageV6FromExistingOwner(input:{enabled:boolean;hostIdle:boolean;otaActive:boolean;stillAllowed:()=>boolean}) {
        if(this.stopping || this.adapterDisconnected || typeof input?.stillAllowed!=="function" ||
            !(this.adapter instanceof ZStackAdapter))return undefined;
        return await this.adapter.b4ReadOwnedStageV6(input);
    }
'''
   s=once(s,sig,proxy+sig,'V6_PROXY')
  (root/rel).write_text(s,encoding='utf-8',newline='');out[rel]=hashlib.sha256(s.encode()).hexdigest()
 return {'schema':'p7u-v6-existing-owner-v1','modified_sha256':out,'new_serial_owner':False}

STAGE_SAMPLE=r'''
            if(process.env.P7U_B4_STAGE_V6==="1" && process.env.P7U_B4_FLIGHT_V5==="1" &&
                this.#b4V6Turn && this.#b4V5V4SlotsRemaining===0 && !this.#b4V5YieldToV4){
                const stage=await this.b4ProbeReadOnlyOwnedStageV6(true);
                if(!this.#b4Operational)return;
                const utc=Date.now(),probeLatencyMs=Math.max(0,Math.round(performance.now()-probeStarted));
                const hostEvidence=this.zigbee.zhController?.b4NoWireOwnerSnapshotFromExistingOwner()??null;
                if(stage && "abi" in stage && stage.abi===6){
                    const {radioBootId,...stageV6}=stage;
                    const radioEpochTag=radioBootId===null?null:createHmac("sha256",this.#b4EpochKey)
                        .update(radioBootId,"utf8").digest("hex").slice(0,24);
                    this.#b4Persist({schema:"p7u-b4-native-sample-v1",kind:"STAGE",utc,
                        monotonicReceiveNs:process.hrtime.bigint().toString(),probeLatencyMs,stageV6,
                        radioEpochTag,radioEpochHardwareVerified:false,hostEvidence});
                    this.#b4V6Turn=false;this.#b4V5V4SlotsRemaining=4;
                }else if(stage && "kind" in stage && stage.kind==="FAILED"){
                    this.#b4Persist({schema:"p7u-b4-native-sample-v1",kind:"FAILED",utc,
                        monotonicReceiveNs:process.hrtime.bigint().toString(),probeLatencyMs,
                        reason:stage.reason,failureClass:stage.reason,submissionState:stage.submissionState,
                        sourceAbi:6,imageRuntimeAttested:false,timingQuality:"HOST_TIMING_UNCERTAIN",hostEvidence});
                    this.#b4V6Turn=false;this.#b4V5V4SlotsRemaining=4;
                }else{
                    this.#b4Persist({schema:"p7u-b4-native-sample-v1",kind:"SKIPPED",utc,
                        monotonicReceiveNs:process.hrtime.bigint().toString(),reason:"HOST_OR_OTA_ADMISSION_SKIPPED",
                        submissionState:"NONE",sourceAbi:6});
                    this.#b4V5YieldToV4=true;
                }
                return;
            }
'''
def z2m(root):
 root=checked(root,'62b02e2aa1997c574223b80c196677b63a25f4a7');p=root/'lib/controller.ts';s=p.read_text()
 method=Z2M_METHOD.replace('b4ProbeReadOnlyHangFlightV5','b4ProbeReadOnlyOwnedStageV6').replace('b4ReadHangFlightV5FromExistingOwner','b4ReadOwnedStageV6FromExistingOwner')
 s=once(s,'    #b4V5V4SlotsRemaining = 0;','    #b4V6Turn = true;\n'+method+'    #b4V5V4SlotsRemaining = 0;','V6_Z2M_STATE')
 s=once(s,'                            this.#b4V5V4SlotsRemaining=0;this.#b4V5YieldToV4=false;',
  '                            this.#b4V6Turn=true;this.#b4V5V4SlotsRemaining=0;this.#b4V5YieldToV4=false;','V6_WARNING_DUE')
 if s.count('this.#b4V5V4SlotsRemaining = 4;')!=2:raise ValueError('V6_V5_TURN_ANCHOR')
 s=s.replace('this.#b4V5V4SlotsRemaining = 4;','this.#b4V6Turn=true;this.#b4V5V4SlotsRemaining = 4;')
 s=once(s,'            if (process.env.P7U_B4_FLIGHT_V5 === "1" &&',STAGE_SAMPLE+'            if (process.env.P7U_B4_FLIGHT_V5 === "1" &&','V6_SAME_SAMPLING_SLOT')
 p.write_text(s,encoding='utf-8',newline='')
 return {'schema':'p7u-v6-safe-slot-collector-v1','default_enabled':False,'extra_timer':False,'maximum_pages_per_slot':2,'sha256':hashlib.sha256(s.encode()).hexdigest()}

if __name__=='__main__':
 p=argparse.ArgumentParser();g=p.add_mutually_exclusive_group(required=True);g.add_argument('--herdsman',type=Path);g.add_argument('--z2m',type=Path);p.add_argument('--receipt',type=Path,required=True)
 a=p.parse_args();r=herdsman(a.herdsman) if a.herdsman else z2m(a.z2m);a.receipt.write_text(json.dumps(r,indent=2)+'\n')
