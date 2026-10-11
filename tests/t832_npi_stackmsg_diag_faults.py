#!/usr/bin/env python3
"""Compile actual patched TI stack-to-host and read-only diagnostics.

Tests ownership across SRSP/AREQ split, allocation failures, interception,
queue fallback, counter snapshots and versioned wire serialization.
No hardware/radio or network traffic.
"""
from pathlib import Path
import argparse
import subprocess
import tempfile
from t832_npi_ownership_faults import function

PREFIX = r"""
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t uint8;
typedef uint16_t uint16;
typedef int NPIMSG_Type;
#define NPIMSG_Type_ASYNC 1
#define MTRPC_CMD_TYPE_MASK 0xE0
#define MTRPC_CMD_SRSP 0x60
#define NPI_UNPI_CMD0_INDEX 2u
#define NPI_SRSP_BURST_LIMIT 4u
#define NPITASK_TX_READY_EVENT 0x10
#define MT_SRSP_SYS 0x61
#define BSEED_MT_SYS_NPI_DIAG 0xF0
#define CHECK(expr) do {if(!(expr)){fprintf(stderr,"CHECK %d %s\n", __LINE__,#expr);exit(6);}} while(0)
typedef struct {void *prev, *next;} Queue_Elem;
typedef struct {uint8_t *pBuf; uint16 pBufSize; int msgType;} NPIMSG_msg_t;
typedef struct {Queue_Elem _elem; NPIMSG_msg_t *npiMsg; uint8_t rejectCount;} NPI_QueueRec;
typedef void *Queue_Handle;
static void *npiTxQueue=(void *)1,*npiSrspTxQueue=(void *)2;
static NPI_QueueRec *areq,*srsp;
static volatile uint32_t npiSrspQueueDepth,npiSrspQueueHighWater,npiSrspQueueFallback,npiAsyncQueueDepth,npiAsyncQueueHighWater;
static volatile uint32_t npiSrspEnqueued,npiSrspTxAccepted,npiAsyncTxAccepted,npiTxImmediateRejects,npiTxRejectedDrops;
static volatile uint32_t npiStackFrameFailed,npiStackQueueFailed,npiSrspAllocFailed,npiSrspEnqueueFailed,npiRxFrameFailed;
static volatile uint8_t npiTxRetryPending;
static int npiSrspBurst;
static uint32_t npiServiceTaskEvents;
static int npiSemHandle,live,allocs,fail_at,fail_frame;
enum { NONE=0,ECHO=1,INTERCEPT=2 };
static int incomingTXReroute=NONE;
static int callbacks;
static void *tracked(size_t n){void*p=calloc(1,n);CHECK(p);live++;return p;}
static void OsalPort_free(void*p){CHECK(p&&live>0);live--;free(p);}
static void OsalPort_msgDeallocate(void*p){OsalPort_free(p);}
static void *OsalPort_malloc(size_t n){allocs++;if(allocs==fail_at)return NULL;return tracked(n);}
static uint32_t OsalPort_enterCS(void){return 0;}
static void OsalPort_leaveCS(uint32_t k){(void)k;}
static void Semaphore_post(int s){(void)s;}
static void Queue_enqueue(void *q,Queue_Elem*e) {
    if(q==npiTxQueue){CHECK(!areq);areq=(NPI_QueueRec*)e;}
    else if(q==npiSrspTxQueue){CHECK(!srsp);srsp=(NPI_QueueRec*)e;}
    else CHECK(0);
}
static void callback(uint8_t *p){callbacks++;if(incomingTXReroute==INTERCEPT)OsalPort_msgDeallocate(p);}
static void (*incomingTXEventAppCBFunc)(uint8_t *)=NULL;
static NPIMSG_msg_t *NPIFrame_frameMsg(uint8_t *p){
    if(fail_frame){OsalPort_msgDeallocate(p);return NULL;}
    NPIMSG_msg_t *n=OsalPort_malloc(sizeof(*n));
    if(!n){OsalPort_msgDeallocate(p);return NULL;}
    n->pBuf=tracked(8);
    n->pBuf[0]=0xFE;n->pBuf[1]=0;n->pBuf[2]=p[1];
    n->pBufSize=8;n->msgType=NPIMSG_Type_ASYNC;
    OsalPort_msgDeallocate(p);
    return n;
}
static uint8_t *newFrame(uint8_t cmd0){
    uint8_t*p=tracked(5);p[0]=2;p[1]=cmd0;return p;
}
static void cleanQueue(NPI_QueueRec **p){
    if(*p){OsalPort_msgDeallocate((*p)->npiMsg->pBuf);OsalPort_free((*p)->npiMsg);OsalPort_free(*p);*p=NULL;}
}
static uint8_t diagRsp[100],diagLen,diagCmd;
static void MT_BuildAndSendZToolResponse(uint8_t type,uint8_t cmd,uint8_t len,uint8_t *data){
    CHECK(type==MT_SRSP_SYS);CHECK(len<=sizeof(diagRsp));
    diagLen=len;diagCmd=cmd;memcpy(diagRsp,data,len);
}
static uint32_t unpack(unsigned n){
    unsigned p=2+4*n;
    return (uint32_t)diagRsp[p]|((uint32_t)diagRsp[p+1]<<8)|
          ((uint32_t)diagRsp[p+2]<<16)|((uint32_t)diagRsp[p+3]<<24);
}
"""
TESTS = r"""
int main(void){
 for (int k=0;k<128;k++){
  CHECK(live==0&&!srsp&&!areq);
  allocs=fail_at=fail_frame=callbacks=0;
  incomingTXEventAppCBFunc=NULL;incomingTXReroute=NONE;
  npiSrspTxQueue=(void*)2;
  NPITask_processStackMsg(newFrame(0x61));
  CHECK(srsp&&srsp->rejectCount==0&&!areq);
  CHECK(npiSrspQueueDepth==1&&npiSrspEnqueued>0);
  cleanQueue(&srsp);npiSrspQueueDepth=0;
  NPITask_processStackMsg(newFrame(0x41));
  CHECK(areq&&!srsp&&npiAsyncQueueDepth==1);
  cleanQueue(&areq);npiAsyncQueueDepth=0;
  CHECK(live==0);

  // Fault in message framing: input is consumed and failure counted.
  fail_frame=1;
  uint32_t before=npiStackFrameFailed;
  NPITask_processStackMsg(newFrame(0x61));
  CHECK(npiStackFrameFailed==before+1&&live==0);
  fail_frame=0;allocs=0;fail_at=2;
  before=npiStackQueueFailed;
  NPITask_processStackMsg(newFrame(0x61));
  CHECK(npiStackQueueFailed==before+1&&live==0);
  fail_at=0;allocs=0;

  // SRSP queue unavailable: fall back to the existing asynchronous path.
  npiSrspTxQueue=NULL;
  NPITask_processStackMsg(newFrame(0x61));
  CHECK(areq&&!srsp&&npiAsyncQueueDepth==1);
  cleanQueue(&areq);npiAsyncQueueDepth=0;
  npiSrspTxQueue=(void*)2;

  // Alternate producer preserves ownership and prioritizes SRSP.
  NPITask_sendToHost(newFrame(0x61));
  CHECK(srsp&&!areq&&srsp->rejectCount==0);
  cleanQueue(&srsp);npiSrspQueueDepth=0;
  incomingTXReroute=INTERCEPT;incomingTXEventAppCBFunc=callback;
  NPITask_processStackMsg(newFrame(0x61));
  CHECK(callbacks==1&&!srsp&&!areq&&live==0);
  incomingTXEventAppCBFunc=NULL;incomingTXReroute=NONE;

  // Wire diagnostics include only aggregated counters in deterministic LE.
  NPITask_noteSrspAllocFailure();
  NPITask_noteSrspEnqueueFailure();
  MT_SysBseedNpiDiag();
  CHECK(diagCmd==BSEED_MT_SYS_NPI_DIAG&&diagRsp[0]==1&&diagLen==62);
  CHECK((diagRsp[1]&1u)==1u);
  CHECK(unpack(0)==0&&unpack(1)>0);
  CHECK(unpack(4)==npiSrspEnqueued);
  CHECK(unpack(9)==npiStackFrameFailed);
  CHECK(unpack(10)==npiStackQueueFailed);
  CHECK(unpack(11)==npiSrspAllocFailed);
  CHECK(unpack(12)==npiSrspEnqueueFailed);
  CHECK(live==0);
 }
 puts("PASS patched TI stack-message ownership/SRSP split/diag 128 cycles");
 return 0;
}
"""

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--sdk",type=Path,required=True)
    a=p.parse_args()
    src=(a.sdk/"source/ti/zstack/npi/npi_task.c").read_text()
    m=(a.sdk/"source/ti/zstack/mt/mt_sys.c").read_text()
    h=(a.sdk/"source/ti/zstack/npi/npi_task.h").read_text()
    start=h.index("typedef struct NPITask_DiagSnapshot_s {")
    end=h.index("} NPITask_DiagSnapshot;",start)+len("} NPITask_DiagSnapshot;")
    funcs=[
       function(src,"void NPITask_sendToHost(uint8_t *pMsg)\n"),
       function(src,"static void NPITask_processStackMsg(uint8_t *pMsg)\n"),
       function(src,"void NPITask_getDiagSnapshot(NPITask_DiagSnapshot *dst)\n"),
       function(src,"void NPITask_noteSrspAllocFailure(void)\n"),
       function(src,"void NPITask_noteSrspEnqueueFailure(void)\n"),
       function(m,"static void MT_SysBseedNpiDiag(void)\n")
    ]
    full=PREFIX+h[start:end]+"\n\n"+"\n\n".join(funcs)+TESTS
    with tempfile.TemporaryDirectory() as tmp:
        c=Path(tmp)/"stackmsg.c";exe=Path(tmp)/"stackmsg"
        c.write_text(full)
        subprocess.run(["cc","-std=c11","-Wall","-Wextra","-Werror",
                        "-Wno-unused-variable","-Wno-unused-function",
                        "-o",str(exe),str(c)],check=True)
        subprocess.run([str(exe)],check=True)
if __name__=="__main__":
    main()
