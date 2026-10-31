"""Compile pinned TI UART -> TL -> NPI completion and the real TX event body.

Only UART/RTOS primitives are mocked. Completion flags, callbacks, busy state,
fragment notification and TX_DONE dispatch come from the actual TI source.
NPI_FLOW_CTRL=0, NPI_SREQRSP disabled; no serial or household data access.
"""
from pathlib import Path
import argparse
from patch_zdapp import extract_function

PREAMBLE=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "b1_management.h"

#define NPITASK_TX_READY_EVENT 0x0010u
#define NPITASK_TRANSPORT_TX_DONE_EVENT 0x0004u
#define NPI_FLOW_CTRL 0
#define FALSE false
#define UART2_STATUS_SUCCESS 0
typedef uint16_t uint16;
typedef uint8_t uint8;
typedef void *UART2_Handle;
static uint32_t npiServiceTaskEvents;
static uint16_t TX_DONE_ISR_EVENT_FLAG,MRDY_ISR_EVENT_FLAG,TRANSPORT_RX_ISR_EVENT_FLAG;
static unsigned pending,transmitted,posts,tx_results,fragment_writes,cs_depth;
static bool npiTxActive,hold;
static uint16_t npiRxBufHead,npiRxBufTail,msgFragLen,TransportTxLen=8;
static uint8_t *msgFrag;
static int queue_object,semaphore_object,uart_object;
static void *npiTxQueue=&queue_object,*npiSemHandle=&semaphore_object;
static UART2_Handle uartHandle=&uart_object;
static bool Queue_empty(void *q) {
    assert(q==npiTxQueue);return pending==0;
}
int b1_management_transport_unavailable(void) {return hold;}
void b1_management_transport_failed(uint8_t reason) {
    assert(reason==B1_ERROR_UART_WRITE);hold=true;
}
void b1_startup_tx_result(uint16_t size,int success) {
    assert(size==TransportTxLen && success==1);++tx_results;
}
static uint32_t OsalPort_enterCS(void) {return ++cs_depth;}
static void OsalPort_leaveCS(uint32_t key) {assert(key==cs_depth);--cs_depth;}
static void Semaphore_post(void *s) {assert(s==npiSemHandle);++posts;}
static void NPITask_transportTxDoneCallBack(int size);
static void (*taskTxCB)(int)=NPITask_transportTxDoneCallBack;
static void rx_callback(int size) {(void)size;assert(!"unexpected RX in TX test");}
static void (*taskRxCB)(int)=rx_callback;
static uint16_t NPITL_writeTL(uint8_t *buf,uint16_t len) {
    assert(!npiTxActive && buf==msgFrag && len==msgFragLen && len>0);
    ++fragment_writes;TransportTxLen=len;msgFragLen=0;npiTxActive=true;return len;
}
static void NPITask_ProcessTXQ(void) {
    assert(!npiTxActive && !hold && pending>0);
    --pending;++transmitted;npiTxActive=true;
}
'''

MAIN=r'''
static void complete(int status,size_t size) {
    NPITLUART_writeCallBack(uartHandle,NULL,size,NULL,status);
    assert(cs_depth==0);
}
int main(int argc,char **argv) {
    assert(argc==2);
    npiServiceTaskEvents=NPITASK_TX_READY_EVENT;
    if(strcmp(argv[1],"busy")==0) {
        pending=2;npiTxActive=true;
        for(int i=0;i<1000;i++) cycle();
        assert(posts==0 && transmitted==0 && pending==2);
        assert(npiServiceTaskEvents & NPITASK_TX_READY_EVENT);
        puts("B1_ACTUAL_NPI_BUSY_U2_TX_NO_PRIORITY_SPIN_PASS");
    } else if(strcmp(argv[1],"tx_done")==0) {
        pending=2;npiTxActive=true;
        cycle();assert(posts==0);
        complete(UART2_STATUS_SUCCESS,TransportTxLen);
        assert(!npiTxActive && posts==1 && TX_DONE_ISR_EVENT_FLAG);
        cycle();assert(transmitted==1 && pending==1 && posts==2 && npiTxActive);
        /* A stale TX_DONE may add one wake, never a continuing busy spin. */
        for(int i=0;i<1000;i++) cycle();
        assert(posts==2 && transmitted==1);
        complete(UART2_STATUS_SUCCESS,TransportTxLen);
        assert(posts==3 && !npiTxActive);
        cycle();assert(transmitted==2 && pending==0 && posts==3);
        assert(!(npiServiceTaskEvents & NPITASK_TX_READY_EVENT));
        assert(tx_results==2);
        puts("B1_ACTUAL_UART_TL_NPI_TX_DONE_CHAIN_PASS");
    } else if(strcmp(argv[1],"idle")==0) {
        pending=1;npiTxActive=false;
        cycle();assert(transmitted==1 && pending==0 && posts==0);
        assert(!(npiServiceTaskEvents & NPITASK_TX_READY_EVENT));
        complete(UART2_STATUS_SUCCESS,TransportTxLen);cycle();
        assert(posts==1 && transmitted==1 && tx_results==1);
        puts("B1_ACTUAL_NPI_SINGLE_QUEUED_SRSP_NO_BUSY_LOOP_PASS");
    } else if(strcmp(argv[1],"hold")==0) {
        pending=3;npiTxActive=false;hold=true;
        for(int i=0;i<500;i++)cycle();
        assert(posts==0 && transmitted==0 && pending==3);
        assert(npiServiceTaskEvents & NPITASK_TX_READY_EVENT);
        complete(UART2_STATUS_SUCCESS,TransportTxLen);
        assert(posts==0 && tx_results==0);
        puts("B1_ACTUAL_NPI_STICKY_TRANSPORT_HOLD_NO_SPIN_PASS");
    } else if(strcmp(argv[1],"driver_error")==0 || strcmp(argv[1],"short_write")==0) {
        pending=2;npiTxActive=true;
        if(strcmp(argv[1],"driver_error")==0) complete(-1,TransportTxLen);
        else complete(UART2_STATUS_SUCCESS,TransportTxLen-1);
        assert(hold && posts==0 && TX_DONE_ISR_EVENT_FLAG==0 && tx_results==0);
        for(int i=0;i<500;i++)cycle();
        assert(posts==0 && transmitted==0 && pending==2);
        puts("B1_ACTUAL_UART_FAILURE_NO_FALSE_TX_DONE_PASS");
    } else if(strcmp(argv[1],"fragment")==0) {
        static uint8_t tail[10];
        pending=1;npiTxActive=true;msgFrag=tail;msgFragLen=sizeof(tail);
        complete(UART2_STATUS_SUCCESS,TransportTxLen);
        assert(fragment_writes==1 && npiTxActive && posts==0 && TX_DONE_ISR_EVENT_FLAG==0);
        complete(UART2_STATUS_SUCCESS,TransportTxLen);
        assert(posts==1 && !npiTxActive);
        cycle();assert(transmitted==1 && pending==0 && tx_results==2);
        puts("B1_ACTUAL_TL_FRAGMENT_ONLY_FINAL_COMPLETION_WAKES_NPI_PASS");
    } else return 2;
    assert(cs_depth==0);return 0;
}
'''

def statement(text, marker):
    if text.count(marker)!=1:
        raise RuntimeError("PINNED_NPI_EVENT_STATEMENT_DRIFT")
    start=text.index(marker);opening=text.index("{",start);depth=0
    for pos in range(opening,len(text)):
        if text[pos]=="{":depth+=1
        elif text[pos]=="}":
            depth-=1
            if depth==0:return text[start:pos+1]
    raise RuntimeError("PINNED_NPI_EVENT_UNBALANCED")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--source",type=Path,required=True)
    p.add_argument("--transport-source",type=Path,required=True)
    p.add_argument("--uart-source",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();text=a.source.read_text(encoding="utf8")
    beginning="            // An ASYNC message is ready to send to the Host\n"
    ending="            // The Transport Layer has received some bytes\n"
    if text.count(beginning)!=1 or text.count(ending)!=1:
        raise RuntimeError("PINNED_NPI_EVENT_SECTION_DRIFT")
    body=text.split(beginning,1)[1].split(ending,1)[0]
    if "else if (!NPITL_checkNpiBusy()" not in body:
        raise RuntimeError("PINNED_NPI_BUSY_GUARD_MISSING")
    process=extract_function(text,"static void NPITask_process(void)")
    merge=process.split("            // Capture the ISR events flags now within a critical section.\n",1)[1].split("            // MRDY event\n",1)[0]
    done=statement(process,"            if(npiServiceTaskEvents & NPITASK_TRANSPORT_TX_DONE_EVENT)")
    callback=extract_function(text,"static void NPITask_transportTxDoneCallBack(int size)")
    tl=a.transport_source.read_text(encoding="utf8")
    busy=extract_function(tl,"bool NPITL_checkNpiBusy(void)")
    transport=extract_function(tl,"static void NPITL_transmissionCallBack(uint16 Rxlen, uint16 Txlen)")
    uart=extract_function(a.uart_source.read_text(encoding="utf8"),
        "static void NPITLUART_writeCallBack(UART2_Handle handle, void *ptr, size_t size, void *userArg, int_fast16_t status)")
    source=(PREAMBLE+busy+callback+transport+
            "\nstatic void (*npiTransmitCB)(uint16,uint16)=NPITL_transmissionCallBack;\n"+uart+
            "\nstatic void cycle(void)\n{\nuint32_t key;\n"+merge+beginning+body+done+"\n}\n"+MAIN)
    a.output.write_text(source,encoding="utf8")
    print("B1_REAL_UART_TL_NPI_COMPLETION_CHAIN_EXTRACTED")

if __name__=="__main__":main()
