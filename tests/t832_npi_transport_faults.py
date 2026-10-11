#!/usr/bin/env python3
"""Compile and fault-inject actual patched NPI TX/queue functions. Offline only.

Tests synchronous UART rejection, busy-latch recovery, bounded deferred retry,
successful ownership handoff and exhaustion without leaked buffers.
"""
import argparse
from pathlib import Path
import subprocess
import tempfile
from t832_npi_ownership_faults import function

PREFIX = r"""
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
typedef uint8_t uint8;
typedef uint16_t uint16;
typedef struct { int dummy; } Queue_Elem;
typedef void *Queue_Handle;
typedef struct { uint8_t *pBuf; uint16 pBufSize; } NPIMSG_msg_t;
typedef struct { Queue_Elem _elem; NPIMSG_msg_t *npiMsg; uint8_t rejectCount; } NPI_QueueRec;
#define NPI_FLOW_CTRL 0
#define NPI_MAX_FRAG_SIZE 1080
#define NPI_TX_RETRY_MAX 3
#define NPI_SRSP_BURST_LIMIT 4u
#define NPITASK_TX_READY_EVENT 0x10
#define TRUE 1
#define FALSE 0
#define CHECK(c) do { if (!(c)) {fprintf(stderr, "FAIL %d: %s\n",__LINE__,#c);exit(9);} } while(0)
static uint8_t npiTxBuf[1080];
static uint16 npiTxBufLen;
static uint8_t npiTxActive;
static uint8_t *msgFrag;
static uint16 msgFragLen;
static uint32_t txPktCount;
static int uart_accept;
static int alloc_live, timer_starts, sem_posts, queue_count;
static uint8_t expected_data[12];
static NPI_QueueRec *queued;
static NPI_QueueRec *queued_srsp;
static void *npiTxQueue=(void *)1;
static void *npiSrspTxQueue=(void *)3;
static volatile uint32_t npiSrspQueueDepth;
static volatile uint32_t npiAsyncQueueDepth,npiSrspTxAccepted,npiAsyncTxAccepted;
static uint8_t npiSrspBurst;
static void *npiTxRetryHandle=(void *)2;
static volatile uint8_t npiTxRetryPending;
static volatile uint32_t npiTxImmediateRejects, npiTxRejectedDrops;
static uint32_t npiServiceTaskEvents;
static int npiSemHandle;
static void *alloc(size_t n){void *p=calloc(1,n);CHECK(p);alloc_live++;return p;}
static void OsalPort_free(void *p){CHECK(p&&alloc_live>0);alloc_live--;free(p);}
static void OsalPort_msgDeallocate(void *p){OsalPort_free(p);}
static uint32_t OsalPort_enterCS(void){return 0;}
static void OsalPort_leaveCS(uint32_t v){(void)v;}
static int NPITL_checkNpiBusy(void){return npiTxActive!=0;}
static uint16 transportWrite(uint16 n){return uart_accept ? n : 0;}
#define SRDY_ENABLE() ((void)0)
static int Queue_empty(void *handle) {
    CHECK(handle==npiTxQueue||handle==npiSrspTxQueue);
    return handle==npiTxQueue ? queued==NULL : queued_srsp==NULL;
}
static void *Queue_dequeue(void *handle) {
    CHECK(handle==npiTxQueue||handle==npiSrspTxQueue);
    NPI_QueueRec *p;
    if(handle==npiTxQueue) {p=queued;queued=NULL;}
    else {p=queued_srsp;queued_srsp=NULL;}
    if(p)queue_count--;
    return p;
}
static void Queue_putHead(void *handle, Queue_Elem *elem){
    CHECK(handle==npiTxQueue||handle==npiSrspTxQueue);
    if(handle==npiTxQueue) {CHECK(queued==NULL);queued=(NPI_QueueRec *)elem;}
    else {CHECK(queued_srsp==NULL);queued_srsp=(NPI_QueueRec *)elem;}
    queue_count++;
}
static void ClockP_start(void *handle){CHECK(handle==npiTxRetryHandle);timer_starts++;}
static void Semaphore_post(int handle){(void)handle;sem_posts++;}
static void enqueue_test(void) {
    CHECK(queued==NULL);
    queued=alloc(sizeof(*queued));
    queued->npiMsg=alloc(sizeof(*queued->npiMsg));
    queued->npiMsg->pBuf=alloc(12);
    queued->npiMsg->pBufSize=12;
    for(int i=0;i<12;i++)queued->npiMsg->pBuf[i]=expected_data[i];
    queue_count++;npiAsyncQueueDepth++;
}
static void enqueue_srsp_test(void) {
    CHECK(queued_srsp==NULL);
    queued_srsp=alloc(sizeof(*queued_srsp));
    queued_srsp->npiMsg=alloc(sizeof(*queued_srsp->npiMsg));
    queued_srsp->npiMsg->pBuf=alloc(12);
    queued_srsp->npiMsg->pBufSize=12;
    memset(queued_srsp->npiMsg->pBuf,0xA5,12);
    npiSrspQueueDepth++;
    queue_count++;
}
static void reset_case(void) {
    CHECK(queued==NULL&&queued_srsp==NULL&&queue_count==0&&alloc_live==0);
    npiTxActive=FALSE;npiTxBufLen=0;msgFrag=NULL;msgFragLen=0;
    npiTxRetryPending=0;timer_starts=0;sem_posts=0;
    uart_accept=0;npiTxImmediateRejects=0;npiTxRejectedDrops=0;
    npiSrspQueueDepth=0;npiSrspBurst=0;npiAsyncQueueDepth=0;npiSrspTxAccepted=0;npiAsyncTxAccepted=0;
    for(int i=0;i<12;i++)expected_data[i]=(uint8_t)(i+23);
}
"""
TESTS = r"""
int main(void){
  for(int pass=0;pass<256;pass++) {
    reset_case();enqueue_test();
    NPITask_ProcessTXQ();
    CHECK(queued!=NULL&&queued->rejectCount==1&&queue_count==1&&alloc_live==3);
    CHECK(npiTxActive==FALSE&&npiTxRetryPending==1);
    CHECK(npiTxImmediateRejects==1&&timer_starts==1);
    // Timer re-arms the deferred event. A successful write consumes ownership.
    NPITask_txRetryClockCB(0);
    CHECK(npiTxRetryPending==0&&(npiServiceTaskEvents&NPITASK_TX_READY_EVENT));
    uart_accept=1;
    NPITask_ProcessTXQ();
    CHECK(queued==NULL&&queue_count==0&&alloc_live==0);
    CHECK(npiTxActive==TRUE&&!memcmp(npiTxBuf,expected_data,12));
    CHECK(npiTxRejectedDrops==0);
    // Completion is asynchronous; mock it before next test case.
    npiTxActive=FALSE;

    reset_case();enqueue_test();
    for(int attempt=0;attempt<4;attempt++){
      NPITask_ProcessTXQ();
      if(attempt<3){
        CHECK(queued!=NULL&&npiTxRetryPending&&npiTxActive==FALSE);
        NPITask_txRetryClockCB(0);
      }
    }
    CHECK(queued==NULL&&queue_count==0&&alloc_live==0);
    CHECK(npiTxImmediateRejects==4&&npiTxRejectedDrops==1&&timer_starts==3);
    CHECK(queued==NULL&&queued_srsp==NULL);
    // Inactive reset never leaves the old NPI busy latch set.
    reset_case();uart_accept=0;
    uint8_t large[1081]={0};
    CHECK(NPITL_writeTL(large,sizeof large)==0);
    CHECK(npiTxActive==FALSE&&msgFrag==NULL&&msgFragLen==0);

    reset_case();uart_accept=1;enqueue_test();
    NPITask_ProcessTXQ();
    CHECK(queued==NULL&&alloc_live==0&&npiTxActive==TRUE);
    CHECK(npiTxRejectedDrops==0);
    npiTxActive=FALSE;

    // Both queues occupied: SRSP is first, AREQ must still be serviced next.
    reset_case();uart_accept=1;enqueue_test();enqueue_srsp_test();
    NPITask_ProcessTXQ();
    CHECK(queued_srsp==NULL&&queued!=NULL&&npiSrspQueueDepth==0);
    CHECK(npiSrspBurst==1&&npiTxBuf[0]==0xA5);
    npiTxActive=FALSE;
    NPITask_ProcessTXQ();
    CHECK(queued==NULL&&alloc_live==0&&npiSrspBurst==0);
    npiTxActive=FALSE;

    // Fairness budget exhausted: queued AREQ wins over new SRSP.
    reset_case();uart_accept=1;enqueue_test();enqueue_srsp_test();
    npiSrspBurst=NPI_SRSP_BURST_LIMIT;
    NPITask_ProcessTXQ();
    CHECK(queued==NULL&&queued_srsp!=NULL);
    CHECK(npiSrspBurst==0&&npiTxBuf[0]==expected_data[0]);
    npiTxActive=FALSE;
    NPITask_ProcessTXQ();
    CHECK(queued_srsp==NULL&&npiSrspQueueDepth==0&&alloc_live==0);
    npiTxActive=FALSE;

    // A successful unrelated SRSP must NOT reset an AREQ's retry budget.
    reset_case();enqueue_test();uart_accept=0;
    NPITask_ProcessTXQ();
    CHECK(queued && queued->rejectCount==1);
    NPITask_txRetryClockCB(0);
    uart_accept=1;enqueue_srsp_test();
    NPITask_ProcessTXQ();
    CHECK(queued && queued->rejectCount==1 && queued_srsp==NULL);
    npiTxActive=FALSE;uart_accept=0;
    NPITask_ProcessTXQ();
    CHECK(queued && queued->rejectCount==2);
    NPITask_txRetryClockCB(0);
    NPITask_ProcessTXQ();
    CHECK(queued && queued->rejectCount==3);
    NPITask_txRetryClockCB(0);
    NPITask_ProcessTXQ();
    CHECK(queued==NULL && npiTxRejectedDrops==1 && alloc_live==0);

    // Rejected SRSP must remain on the SRSP queue, not become AREQ.
    reset_case();enqueue_srsp_test();
    NPITask_ProcessTXQ();
    CHECK(queued_srsp!=NULL&&queued_srsp->rejectCount==1&&queued==NULL&&npiSrspQueueDepth==1);
    CHECK(npiTxRetryPending&&npiTxActive==FALSE);
    NPITask_txRetryClockCB(0);uart_accept=1;
    NPITask_ProcessTXQ();
    CHECK(queued_srsp==NULL&&npiSrspQueueDepth==0&&alloc_live==0);
    npiTxActive=FALSE;
  }
  puts("PASS actual TI NPI: 256 cycles UART recovery, SRSP fairness and ownership");
  return 0;
}
"""
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--sdk",type=Path,required=True)
    args=p.parse_args()
    tl=(args.sdk/"source/ti/zstack/npi/npi_tl.c").read_text()
    task=(args.sdk/"source/ti/zstack/npi/npi_task.c").read_text()
    funcs=[
        function(tl,"uint16 NPITL_writeTL(uint8 *buf, uint16 len)\n"),
        function(task,"static void NPITask_ProcessTXQ(void)\n"),
        function(task,"static void NPITask_txRetryClockCB(uintptr_t arg)\n")
    ]
    c=PREFIX+"\n\n".join(funcs)+TESTS
    with tempfile.TemporaryDirectory() as td:
        source=Path(td)/"npi_tx.c";exe=Path(td)/"npi_tx"
        source.write_text(c)
        subprocess.run(["cc","-std=c11","-Wall","-Wextra","-Werror",
                       "-Wno-unused-function","-Wno-unused-variable",
                       "-o",str(exe),str(source)],check=True)
        subprocess.run([str(exe)],check=True)
if __name__=="__main__":
    main()
