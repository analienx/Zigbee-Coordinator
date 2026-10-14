#!/usr/bin/env python3
"""HOSTED ONLY: genuine pinned Queue/UART/TL/task/frame bodies with fault vectors.

Platform Hwi/DMA/Clock/Semaphore/heap are deterministic injection boundaries.
Neither a policy-only test nor hardware/driver-interrupt qualification.
"""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
import test_transport as boundary

ROOT = Path(__file__).resolve().parents[2]
G7 = ROOT / "firmware/slzb-06p7/ti832/g7"
sys.path.insert(0, str(G7))
import g7_task_overlay as overlay
import g6_overlay as g6
import diag_overlay as diag

TASK_COMMON = r'''
#include <stdlib.h>
#include <setjmp.h>
#include "p7_g6.h"
#define NPITASK_TX_READY_EVENT 0x10u
#define NPITASK_TRANSPORT_TX_DONE_EVENT 0x04u
#define NPITASK_MRDY_EVENT 0x80u
#define NPITASK_TRANSPORT_RX_EVENT 2u
#define NPITASK_FRAME_RX_EVENT 8u
#define BIOS_WAIT_FOREVER 0xffffffffu
#define NONE 0
#define ECHO 1
#define INTERCEPT 2
#define MT_SOF 0xfeu
#define MTRPC_POS_LEN 0
#define MTRPC_FRAME_HDR_SZ 3
typedef struct Queue_Elem { struct Queue_Elem *next,*prev; } Queue_Elem;
typedef Queue_Elem Queue_Object; typedef Queue_Object Queue_Struct;
typedef Queue_Object *Queue_Handle; typedef struct {int dummy;} Queue_Params;
static Queue_Struct rx_queue_struct;
static Queue_Handle npiRxQueue;
typedef enum { NPIMSG_Type_ASYNC=1, NPIMSG_Type_SYNCRSP=2 } NPIMSG_Type;
typedef struct { uint8_t *pBuf; uint16_t pBufSize; NPIMSG_Type msgType; } NPIMSG_msg_t;
typedef struct { Queue_Elem _elem; NPIMSG_msg_t *npiMsg; } NPI_QueueRec;
typedef struct { uint32_t period; bool startFlag; uintptr_t arg; } ClockP_Params;
typedef struct { void (*cb)(uintptr_t); uintptr_t arg; uint32_t timeout,due; bool active; } ClockP_Struct;
typedef ClockP_Struct *ClockP_Handle;
static uint32_t tick,period=1000;
static int timer_fail,posts,pend_calls,rx_passes;
static void *live[128]; static unsigned blocks,alloc_calls,fail_at;
static uint32_t npiServiceTaskEvents;
static uint16_t TX_DONE_ISR_EVENT_FLAG,MRDY_ISR_EVENT_FLAG,TRANSPORT_RX_ISR_EVENT_FLAG;
static int npiSemHandle,npiServiceTaskId,incomingTXReroute;
static void (*incomingTXEventAppCBFunc)(uint8_t *);
static jmp_buf task_exit;
volatile uint8_t p7_g6_rx_resync;
uint32_t p7_g6_now(void) { return tick; }
uint32_t p7_g6_period_us(void) { return period; }
void p7_g6_record(uint16_t k,uint16_t a) {(void)k;(void)a;}
static void *alloc(size_t n) {
    if (++alloc_calls==fail_at) return NULL;
    void *p=calloc(1,n); assert(p && blocks<128); live[blocks++]=p;return p;
}
static void release(void *p) {
    if(!p)return;
    unsigned i;for(i=0;i<blocks&&live[i]!=p;i++);
    assert(i<blocks);free(p);live[i]=live[--blocks];
}
#define OsalPort_malloc alloc
#define OsalPort_msgAllocate alloc
#define OsalPort_free release
#define OsalPort_msgDeallocate release
static void Semaphore_post(int s){(void)s;posts++;}
static void Semaphore_pend(int s,uint32_t t){(void)s;(void)t;if(pend_calls++)longjmp(task_exit,1);}
static uint8_t *OsalPort_msgReceive(int t){(void)t;return NULL;}
static void NPIFrame_collectFrameData(void){rx_passes++;}
static int NPIRxBuf_GetRxBufCount(void){return 0;}
static void NPITask_processRXQ(void){rx_passes++;}
static void p7_g6_discard_ring(void){}
static void p7_g6_reset_parser(void){}
static void ClockP_Params_init(ClockP_Params *p){memset(p,0,sizeof(*p));}
static ClockP_Handle ClockP_construct(ClockP_Struct *s,void(*cb)(uintptr_t),uint32_t t,ClockP_Params*p){
    if(timer_fail)return NULL;
    s->cb=cb;s->arg=p->arg;s->timeout=t;s->active=p->startFlag;return s;
}
static void ClockP_stop(ClockP_Handle s){s->active=false;}
static void ClockP_setTimeout(ClockP_Handle s,uint32_t t){assert(!s->active&&t);s->timeout=t;}
static void ClockP_start(ClockP_Handle s){s->due=tick+s->timeout;s->active=true;}
'''

TEST = r'''
static int inline_completion;
static void complete(void) {
    object.writeInUse=false;
    NPITLUART_writeCallBack(uartHandle,npiTxBuf,TransportTxLen,NULL,UART2_STATUS_SUCCESS);
}
static void completion_hook(void){if(inline_completion)complete();}
static void task_once(void){pend_calls=0;if(!setjmp(task_exit))NPITask_process();}
static void advance(uint32_t now) {
    tick=now;
    if(p7_g7_clock->active && (uint32_t)(tick-p7_g7_clock->due)<0x80000000u){
        p7_g7_clock->active=false;p7_g7_clock->cb(0);task_once();
    }
}
static void setup(void){
    assert(!blocks);reset();memset(p7_g7_lanes,0,sizeof(p7_g7_lanes));
    memset((void*)&p7_g7_counters,0,sizeof(p7_g7_counters));
    p7_g7_burst=p7_g7_fault=p7_g7_busy_seen=p7_g7_isr_event=0;
    tick=0;period=1000;timer_fail=posts=rx_passes=inline_completion=0;
    alloc_calls=fail_at=0;npiServiceTaskEvents=0;
    TX_DONE_ISR_EVENT_FLAG=MRDY_ISR_EVENT_FLAG=TRANSPORT_RX_ISR_EVENT_FLAG=0;
    incomingTXEventAppCBFunc=NULL;incomingTXReroute=NONE;
    p7_g7_init();npiTransmitCB=NPITL_transmissionCallBack;taskTxCB=completed;
    npiRxQueue=Queue_construct(&rx_queue_struct,NULL);
}
static uint8_t *raw(uint8_t cmd,uint8_t seq,uint8_t len){
    uint8_t*p=alloc((size_t)len+3);p[0]=len;p[1]=cmd;p[2]=seq;
    for(unsigned i=0;i<len;i++)p[i+3]=(uint8_t)i;
    return p;
}
static void drain(void){
    object.writeInUse=false;
    while(p7_g7_lanes[0].count||p7_g7_lanes[1].count){
        if(npiTxActive)complete();
        task_once();
        if(npiTxActive)complete();
    }
    if(npiTxActive)complete();
    task_once();assert(!blocks&&!npiTxActive);
}
static void intercept(uint8_t*p){release(p);}
static void echo(uint8_t*p){assert(p&&blocks);}
int main(void){
    setup();object.writeInUse=true;NPITask_sendToHost(raw(0x61,1,0));task_once();
    assert(blocks==3 && p7_g7_lanes[0].head && dma_calls==0 && driver_calls==1);
    assert(p7_g7_clock->due==6);
    for(uint32_t t=1;t<6;t++){tick=t;task_once();assert(driver_calls==1&&p7_g7_clock->due==6);}
    advance(6);assert(driver_calls==2&&blocks==3&&p7_g7_clock->due==12);
    advance(12);assert(driver_calls==3&&blocks==0&&p7_g7_counters.dropped==1);
    assert(p7_g7_counters.rejected==3&&!p7_g7_clock->active);
    setup();object.writeInUse=true;NPITask_sendToHost(raw(0x61,1,0));task_once();
    object.writeInUse=false;advance(6);assert(dma_calls==1&&blocks==0);complete();task_once();
    assert(dma_calls==1&&!p7_g7_clock->active);
    setup();NPITask_sendToHost(raw(0x61,1,0));task_once();assert(npiTxActive&&!blocks);
    uint8_t copy[NPI_TL_BUF_SIZE];memcpy(copy,npiTxBuf,sizeof(copy));
    for(unsigned i=0;i<8;i++)NPITask_sendToHost(raw(0x41,(uint8_t)i,0));
    NPITask_sendToHost(raw(0x41,99,0));assert(blocks==24&&p7_g7_counters.full==1);
    for(uint32_t t=1;t<50;t++){tick=t;task_once();assert(dma_calls==1&&!memcmp(copy,npiTxBuf,sizeof(copy)));}
    advance(50);assert(p7_g7_fault&&p7_g7_counters.transport_fault==1&&!blocks&&npiTxActive);
    complete();NPITask_sendToHost(raw(0x61,2,0));task_once();
    assert(dma_calls==1&&!blocks&&p7_g7_fault);
    npiServiceTaskEvents|=NPITASK_TRANSPORT_RX_EVENT;task_once();assert(rx_passes==1);
    setup();for(unsigned i=0;i<8;i++)NPITask_sendToHost(raw(0x61,(uint8_t)i,0));
    for(unsigned i=0;i<2;i++)NPITask_processStackMsg(raw(0x41,(uint8_t)(20+i),0));
    uint8_t order[10];for(unsigned i=0;i<10;i++){
        task_once();assert(npiTxActive);order[i]=npiTxBuf[3];complete();
    }
    assert(order[0]==0&&order[1]==1&&order[2]==2&&order[3]==3&&order[4]==20);
    assert(order[5]==4&&order[6]==5&&order[7]==6&&order[8]==7&&order[9]==21);
    assert(!blocks&&p7_g7_counters.submitted[0]==8&&p7_g7_counters.submitted[1]==2);
    setup();object.writeInUse=true;NPITask_sendToHost(raw(0x61,1,0));task_once();
    NPITask_sendToHost(raw(0x41,2,0));object.writeInUse=false;task_once();
    assert(npiTxBuf[3]==2&&npiTxActive&&driver_calls==2);complete();tick=6;task_once();
    assert(npiTxBuf[3]==1&&dma_calls==2);complete();drain();
    for(int mode=0;mode<4;mode++){
        setup();if(mode==0)late_status=UART2_STATUS_ECANCELLED;
        if(mode==1)late_status=UART2_STATUS_ETIMEOUT;
        if(mode==2)unknown_status=UART2_STATUS_EFAIL;
        if(mode==3)unknown_status=7;
        NPITask_sendToHost(raw(0x61,3,0));task_once();
        assert(!blocks&&dma_calls==1&&p7_g7_counters.ambiguous==1);
        tick=10;task_once();assert(dma_calls==1);complete();task_once();assert(dma_calls==1);
    }
    setup();inline_completion=1;NPITask_sendToHost(raw(0x61,1,0));task_once();
    assert(!blocks&&dma_calls==1&&!npiTxActive);task_once();assert(dma_calls==1);
    setup();tick=0xfffffffdu;object.writeInUse=true;NPITask_sendToHost(raw(0x61,1,0));task_once();
    assert(p7_g7_clock->due==3);object.writeInUse=false;advance(3);assert(dma_calls==1);complete();drain();
    setup();period=10000;object.writeInUse=true;NPITask_sendToHost(raw(0x61,1,0));task_once();
    assert(p7_g7_clock->due==2);object.writeInUse=false;advance(2);assert(dma_calls==1);complete();drain();
    for(unsigned n=1;n<=3;n++){
        setup();uint8_t *input=raw(0x61,1,0);fail_at=alloc_calls+n;
        NPITask_sendToHost(input);assert(!blocks);assert(!dma_calls);
    }
    setup();NPITask_sendToHost(raw(0x21,1,0));assert(!blocks&&p7_g7_counters.invalid==1);
    NPIMSG_msg_t *m=alloc(sizeof(*m));m->msgType=NPIMSG_Type_ASYNC;m->pBufSize=5;
    m->pBuf=alloc(5);m->pBuf[0]=0xfe;m->pBuf[2]=0x61;m->pBuf[4]=0;
    p7_g7_enqueue(m);assert(!blocks&&p7_g7_counters.invalid==2);
    NPITask_sendToHost(raw(0x61,1,250));task_once();assert(npiTxBufLen==255&&dma_calls==1);complete();drain();
    setup();incomingTXEventAppCBFunc=intercept;incomingTXReroute=INTERCEPT;
    NPITask_processStackMsg(raw(0x61,1,0));assert(!blocks&&!p7_g7_lanes[0].count);
    incomingTXEventAppCBFunc=echo;incomingTXReroute=ECHO;
    NPITask_processStackMsg(raw(0x61,1,0));drain();
    setup();timer_fail=1;p7_g7_init();NPITask_sendToHost(raw(0x61,1,0));task_once();
    assert(!blocks&&p7_g7_fault&&p7_g7_counters.timer_fault==1&&!dma_calls);
    setup();period=0;p7_g7_init();NPITask_sendToHost(raw(0x61,1,0));task_once();assert(!blocks&&p7_g7_fault);
    puts("PASS actual Queue/frame/Task/UART/TL composition: ownership, timed rejection, no uncertain retry, bounded saturation/fault, FIFO and 4-SRSP fairness, RX progress, wrap/coarse ticks, allocation/timer failures");
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "npi_config.h").write_text("/* Platform compile context; pinned geometry independently checked by test_transport. */\n")
    paths = {p[0] for p in diag.PATCHES} | {g6.RX, g6.TL, g6.SYS, g6.CLIENT}
    original = {p: (args.sdk / p).read_text() for p in paths}
    g5, _ = diag.apply_patches(original)
    g6_source = g6.patch(g5)
    post = overlay.patch(g6_source)
    # Double apply must fail before a single source write.
    try: overlay.patch(post)
    except ValueError: pass
    else: raise AssertionError("G7_DOUBLE_APPLY_ACCEPTED")
    header = (args.sdk / "source/ti/drivers/UART2.h").read_text()
    import re
    constants = "\n".join(re.findall(r"^#define UART2_STATUS_\w+ .+$", header, re.M))
    driver_blob = (args.sdk / "source/ti/drivers/UART2.c").read_text()
    driver = driver_blob.replace("int_fast16_t __attribute__((weak))\n", "int_fast16_t ")
    bodies = "\n".join(g6.function(driver, n) for n in ("UART2_write", "UART2_writeTimeout", "UART2_writeTimeoutBlocking"))
    queue_blob = (args.sdk / "kernel/tirtos7/packages/ti/sysbios/knl/Queue.c").read_text()
    queues = "\n".join(g6.function(queue_blob, n) for n in
                       ("Queue_Instance_init", "Queue_construct", "Queue_empty", "Queue_enqueue", "Queue_dequeue"))
    common = boundary.COMMON.replace("static int NPITL_checkNpiBusy(void) { return npiTxActive; }", "")
    common = common.replace("uint16 NPITL_writeTL(uint8 *,uint16);", "uint16 NPITL_writeTL(uint8 *,uint16);\nstatic void completion_hook(void);")
    adapter = boundary.ADAPTER.replace("return unknown_status ? unknown_status : result;", "completion_hook();return unknown_status ? unknown_status : result;")
    adapter = adapter.replace("static void completed(uint16 len) { assert(len);tx_callbacks++; }",
                              "static void completed(uint16 len) { assert(len);tx_callbacks++;NPITask_transportTxDoneCallBack(len); }")
    extra = 'static void (*npiTransmitCB)(uint16,uint16);\nstatic void NPITask_transportTxDoneCallBack(int);\n'
    callbacks = g6.function(post[g6.UART], "NPITLUART_writeCallBack")
    frame = g6.function(post[g6.FRAME], "npiframe_calcMTFCS") + "\n" + g6.function(post[g6.FRAME], "NPIFrame_frameMsg")
    task = "\n".join(g6.function(post[g6.TASK], n) for n in
                    ("NPITask_sendToHost", "NPITask_processStackMsg", "NPITask_transportTxDoneCallBack", "NPITask_process"))
    prefix = constants + "\n" + common + TASK_COMMON + queues + "\n" + bodies + extra + adapter
    transport = "\n".join(g6.function(post[g6.TL], n) for n in ("NPITL_checkNpiBusy",)) + "\n"
    transport += "\n".join(g6.function(post[p], n) for p, n in
                           ((g6.UART, "NPITLUART_writeTransport"), (g6.TL, "NPITL_writeTL"),
                            (g6.UART, "p7_g7_uart_outcome"), (g6.TL, "p7_g7_tl_outcome"),
                            (g6.TL, "NPITL_transmissionCallBack")))
    c = args.out / "task-post.c"
    c.write_text(prefix + transport + callbacks + frame + '\n#include "p7_g7_task.inc"\n' + task + TEST)
    binary = args.out / "task-post"
    flags = ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
             "-Wno-unused-variable", "-Wno-unused-parameter", "-DNPI_TL_BUF_SIZE=270",
             "-I", str(args.out), "-I", str(G7), "-I", str(G7.parent / "g6"), "-I", str(G7.parent / "g5")]
    subprocess.run(flags + [str(c), str(G7 / "p7_tx_policy.c"), "-o", str(binary)], check=True)
    result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
    (args.out / "task-post.log").write_text(result.stdout + result.stderr)
    assert result.returncode == 0, result.stderr
    print(result.stdout, end="")
    # Genuine predecessor loses its three owned blocks on a proven rejection.
    pre = args.out / "task-pre.c"
    pre.write_text(prefix.replace("completion_hook();", "") + transport + frame +
                   "\nstatic Queue_Handle npiTxQueue;\n" + g6.function(g6_source[g6.TASK], "NPITask_ProcessTXQ") +
                   r'''
static void NPITask_transportTxDoneCallBack(int s){(void)s;}
static void completion_hook(void){}
int main(void){reset();Queue_Struct q;npiTxQueue=Queue_construct(&q,NULL);
NPIMSG_msg_t*m=alloc(sizeof(*m));m->pBuf=alloc(5);m->pBufSize=5;
NPI_QueueRec*r=alloc(sizeof(*r));r->npiMsg=m;Queue_enqueue(npiTxQueue,&r->_elem);
object.writeInUse=true;NPITask_ProcessTXQ();assert(dma_calls==0&&driver_calls==1);
assert(blocks==3);return 0;}
''')
    pre_binary = args.out / "task-pre"
    subprocess.run(flags + [str(pre), "-o", str(pre_binary)], check=True)
    pre_result = subprocess.run([str(pre_binary)], capture_output=True, text=True, timeout=10)
    (args.out / "task-pre.log").write_text(pre_result.stdout + pre_result.stderr)
    assert pre_result.returncode != 0 and "Assertion `blocks==3' failed" in pre_result.stderr, pre_result.stderr
    (args.out / "task-source-evidence.json").write_text(json.dumps({
        "qualification": "G7_HOST_SOURCE_REGRESSIONS_ONLY_NOT_FLASHABLE",
        "runtime_qualified": False, "hardware_qualified": False, "flash_authorized": False,
        "pre_ownership_control": pre_result.returncode, "post": result.returncode,
        "queue_sha256": hashlib.sha256(queue_blob.encode()).hexdigest(),
        "driver_sha256": hashlib.sha256(driver_blob.encode()).hexdigest(),
        "patched_sha256": {p: hashlib.sha256(post[p].encode()).hexdigest() for p in (g6.TASK, g6.TL, g6.UART)}}, indent=2) + "\n")


if __name__ == "__main__": main()
