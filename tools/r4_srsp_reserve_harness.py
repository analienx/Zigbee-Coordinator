#!/usr/bin/env python3
"""Execute real composed TI MT producer and NPI TX code under heap exhaustion.

This is a source-bound, sanitized C fixture. No radio, NV, USB, ESP or
physical boot is exercised. Mutants must be rejected by executable assertions.
"""
import hashlib
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from r4_uart_tx_liveness import extract
from r4_srsp_service import TASK, SYS
from r4_srsp_service_harness import PREFIX

CLIENT = "source/ti/zstack/npi/npi_client_mt.c"
FRAME = "source/ti/zstack/npi/npi_frame_mt.c"

MAIN = r"""
static void make_message(unsigned srsp, unsigned id, unsigned len){
    uint8_t data[250]={0};
    memcpy(data,&now_us,4);data[4]=id;data[5]=id>>8;
    assert(len<=250);
    MT_BuildAndSendZToolResponse(srsp?0x64u:0x44u,srsp?1u:0x81u,len,data);
}
static void drain(void){
    tokens=0;
    if(!setjmp(done))NPITask_process();
}
static void complete(void){
    assert(busy);now_us=uart_due;virtual_complete_write();
}
int main(void){
    Queue_construct(&aq,NULL);Queue_construct(&rq,NULL);
    Queue_construct(&B4_V44_SrspQueueStruct,NULL);
    B4_V44_SrspQueue=Queue_handle(&B4_V44_SrspQueueStruct);
    flood_left=0;
    /* Queue full-size unsolicted traffic before freezing all OSAL allocations. */
    for(unsigned i=1;i<=18;++i)make_message(0,i,200);
    while(mail_out<mail_in)NPITask_processStackMsg(OsalPort_msgReceive(1));
    unsigned live_before=live_alloc;
    allocation_fail=1;
    /* Real producer must bypass every heap allocation, including framing. */
    uint8_t afStatus=0u;
    MT_BuildAndSendZToolResponse(0x64u,0x00u,1u,&afStatus);
    assert(B4_V45_ReserveUsed==1 && B4_NpiSrspDepth==1 && live_alloc==live_before);
    assert(B4_AllRspNpiReceived && B4_AllRspFramedQueued);
    assert(B4_AfRspNpiReceived==1 && B4_AfRspFramedQueued==1);
    uint8_t *frame=B4_V45_Slots[0].frame;unsigned fcs=0;
    assert(frame[0]==0xfe && frame[1]==1 && frame[2]==0x64 && frame[3]==0);
    for(unsigned i=1;i<5;++i)fcs^=frame[i];
    assert(frame[5]==fcs);
    NPITask_ProcessTXQ();assert(srsp_sent==1 && busy);
    assert(B4_V45_Slots[0].used==0 && live_alloc==live_before);
    for(unsigned i=0;i<B4_V45_FRAME_BYTES;++i)assert(frame[i]==0u);
    complete();assert(completed_srsp==1);
    /* Three simultaneous reserved responses with a *completely dead* heap. */
    for(unsigned i=2;i<=4;++i)make_message(1,i,20);
    assert(B4_V45_ReserveUsed==4 && B4_NpiSrspDepth==3);
    assert(B4_V45_Slots[0].used && B4_V45_Slots[1].used && B4_V45_Slots[2].used);
    make_message(1,5,1);
    assert(B4_V45_ReserveExhausted==1 && B4_AllRspAllocFailed>=1);
    assert(B4_NpiSrspDepth==3 && live_alloc==live_before);
    /* When all reserve slots are full, use legacy dynamic overflow
     * if memory is available: do not shed the fourth response. */
    allocation_fail=0;
    make_message(1,5,20);
    while(mail_out<mail_in)NPITask_processStackMsg(OsalPort_msgReceive(1));
    assert(B4_NpiSrspDepth==4 && B4_V45_ReserveExhausted==2);
    drain();
    assert(!live_alloc && !busy && B4_NpiSrspDepth==0 && B4_NpiAsyncDepth==0);
    assert(srsp_sent==5 && completed_srsp==5 && areq_sent==18);
    for(unsigned i=0;i<B4_V45_POOL_SLOTS;++i)assert(!B4_V45_Slots[i].used);
    /* Physical HOLD is sticky: a reserve is allowed but never UART-submitted. */
    held=1;allocation_fail=1;
    make_message(1,6,250);
    assert(B4_NpiSrspDepth==1 && B4_V45_ReserveUsed==5);
    NPITask_ProcessTXQ();assert(!busy && srsp_sent==5);
    held=0;
    NPITask_ProcessTXQ();assert(busy && srsp_sent==6);
    complete();assert(completed_srsp==6);
    /* Slot release before callback is sound because TL already copied frame. */
    make_message(1,7,4);
    NPITask_ProcessTXQ();assert(busy && srsp_sent==7);
    make_message(1,8,4);
    assert(B4_NpiSrspDepth==1 && B4_V45_ReserveUsed==7);
    complete();NPITask_ProcessTXQ();assert(busy && srsp_sent==8);
    complete();
    allocation_fail=0;
    assert(!live_alloc && !B4_NpiSrspDepth && !B4_NpiAsyncDepth);
    for(unsigned i=0;i<B4_V45_POOL_SLOTS;++i)assert(!B4_V45_Slots[i].used);
    assert(!B4_V45_ReleaseFault && completed_srsp==8);
    printf("V45_ACTUAL_C_PASS reserved=%u overflow=%u max_completion_us=%u live=%u\n",
           (unsigned)B4_V45_ReserveUsed,(unsigned)B4_V45_ReserveExhausted,
           max_srsp_us,live_alloc);
    return 0;
}
"""

def exercise(sdk):
    sdk = Path(sdk)
    task=(sdk/TASK).read_text()
    client=(sdk/CLIENT).read_text()
    frame=(sdk/FRAME).read_text()
    record=task[task.index("typedef struct NPI_QueueRec_t"):task.index("} NPI_QueueRec;")+len("} NPI_QueueRec;")]
    globals_=task[task.index("#define B4_V44_SRSP_BURST"):task.index("static uint8_t B4_V44_ReadyTracked")]
    globals_+="static uint8_t B4_V44_ReadyTracked, B4_V44_SrspRun;\n"
    counters=sorted(set(re.findall(r"volatile uint32_t (B4_(?:AllRsp|AfDataRsp|AfRsp|Npi)[A-Za-z]+)",task+client)))
    counter_src="\n".join("static volatile uint32_t "+name+";" for name in counters if name!="B4_NpiUartTxFinishedCallback")
    # Extract literal v4.5 slots/functions as compiled into the true TI task.
    start=task.index("/* B4_V45_STATIC_SRSP_RESERVE.")
    end=task.index("/* Enqueue between the check and pend",start)
    reserve=task[start:end]
    names=["static uint8_t B4_V44_TxReadyLocked(void)",
           "static void B4_V44_NoteReadyLocked(void)",
           "static void B4_V44_Enqueue(NPI_QueueRec *recPtr)"]
    remaining=["static void B4_V44_Pend(void)",
               "void B4_V44_Snapshot(uint8_t *payload)",
               "static void B4_AfNpiTick(volatile uint32_t *p)",
               "void NPITask_sendToHost(uint8_t *pMsg)",
               "static void NPITask_processStackMsg(uint8_t *pMsg)",
               "static void NPITask_ProcessTXQ(void)",
               "static void NPITask_transportTxDoneCallBack(int size)",
               "static void NPITask_process(void)"]
    # The inherited v4.4 UART model only accepted larger synthetic frames.
    # A genuine AF_REGISTER SRSP has one payload byte => 6 framed bytes.
    prefix=PREFIX.replace(
        "assert(!cs_depth && !busy && !held && n>=9 && n<=255);",
        "assert(!cs_depth && !busy && !held && n>=6 && n<=255);")
    prefix=prefix.replace(
        "uint32_t stamp,id;memcpy(&stamp,p+4,4);id=p[8]|((uint32_t)p[9]<<8);",
        "uint32_t stamp=now_us,id=((p[2]&0xe0)==0x60 ? last_srsp_id:last_areq_id)+1u;"
        "if(n>=10){memcpy(&stamp,p+4,4);id=p[8]|((uint32_t)p[9]<<8);}")
    if prefix == PREFIX or "n>=9 && n<=255" in prefix:
        raise RuntimeError("V45_SHORT_SRSP_UART_FIXTURE_DRIFT")
    source=prefix+record+"\n"+globals_+counter_src+"\n"
    source+="extern uint8_t B4_V45_SendReservedSrsp(uint8_t,uint8_t,uint8_t,const uint8_t *);\n"
    source+=extract(client,"static void B4_AfRspTick(volatile uint32_t *p)")+"\n"
    source+=extract(client,"void MT_BuildAndSendZToolResponse(uint8_t cmdType, uint8_t cmdId,\n                                  uint8_t dataLen, uint8_t *pData)")+"\n"
    source+=extract(frame,"uint8_t npiframe_calcMTFCS(uint8_t *msg_ptr, uint8_t len)")+"\n"
    source+=extract(frame,"NPIMSG_msg_t *NPIFrame_frameMsg(uint8_t *pIncomingMsg)")+"\n"
    source+="\n".join(extract(task,n) for n in names)+"\n"+reserve+"\n"
    source+="\n".join(extract(task,n) for n in remaining)+"\n"
    source+=MAIN
    cc=shutil.which("cc") or shutil.which("gcc")
    if not cc:raise RuntimeError("V45_COMPILER_REQUIRED")
    def run(label,text,should_pass):
        with tempfile.TemporaryDirectory(prefix="v45-c-") as td:
            p=Path(td)
            (p/"test.c").write_text(text)
            build=subprocess.run([cc,"-std=c11","-O1","-g","-fsanitize=address,undefined",
                "-fno-omit-frame-pointer","-Wall","-Wextra","-Wno-unused-function",
                str(p/"test.c"),"-o",str(p/"test")],capture_output=True,text=True,timeout=30)
            if build.returncode:raise RuntimeError("V45_COMPILE_"+label+"\n"+build.stderr[-5000:])
            proc=subprocess.run([str(p/"test")],capture_output=True,text=True,timeout=30)
            if (proc.returncode==0)!=should_pass:
                raise RuntimeError("V45_ASSERT_"+label+"\n"+proc.stdout[-1500:]+proc.stderr[-5000:])
            return proc.stdout.strip()
    result=run("reserved_saturated_heap",source,True)
    mutants={
        "reservation_disabled":("if (allSrsp && B4_V45_SendReservedSrsp", "if (0 && B4_V45_SendReservedSrsp"),
        "leak_reserved_slot":("B4_V45_Slots[i].used = 0u;", "B4_V45_Slots[i].used = 1u;"),
        "single_slot":("#define B4_V45_POOL_SLOTS 3u","#define B4_V45_POOL_SLOTS 1u"),
        "free_static_as_heap":("if (!B4_V45_ReleaseReserved(recPtr))","if (1)"),
    }
    for label,(old,new) in mutants.items():
        if source.count(old)!=1:raise RuntimeError("V45_MUTANT_ANCHOR_"+label)
        run(label,source.replace(old,new,1),False)
    return {"schema":"p7u-v45-actual-composite-reserved-srsp-v1",
      "status":"PASS","actual_compiled_ti_producer":True,
      "no_heap_srsp_produced_and_completed":True,
      "source_sha256":hashlib.sha256(source.encode()).hexdigest(),
      "result":result,"negative_mutants":list(mutants),
      "physical_radio_nv_or_bridge_exercised":False}
