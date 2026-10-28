#!/usr/bin/env python3
"""P7U investigation: compile real pinned TI NPI outgoing queue/drain/producer.

Source-bound research, NOT a patch or physical failure reproduction.
Extracts real functions and TX_READY/TX_DONE event paths from the composed
on-disk R4 C. Only RTOS queues, semaphore, UART and allocation are mocked.
"""
from pathlib import Path
import argparse
import hashlib

from patch_zdapp import extract_function


def section(text: str, start: str, stop: str) -> str:
    if text.count(start) != 1 or text.count(stop) != 1:
        raise ValueError("NPI_TX_SECTION_DRIFT")
    before, tail = text.split(start, 1)
    if stop not in tail:
        raise ValueError("NPI_TX_ORDER_DRIFT")
    return start + tail.split(stop, 1)[0]


PREAMBLE = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NPITASK_TX_READY_EVENT 0x0010u
#define NPITASK_TRANSPORT_TX_DONE_EVENT 0x0004u
#define NPI_FLOW_CTRL 0
#define FALSE false
#define TRUE true
typedef uint16_t uint16;
typedef uint8_t uint8;
typedef struct {uint8_t *pBuf;uint16_t pBufSize;int msgType;} NPIMSG_msg_t;
typedef struct NPI_QueueRec {struct NPI_QueueRec *_elem;NPIMSG_msg_t *npiMsg;} NPI_QueueRec;
#define NPIMSG_Type_ASYNC 0
static unsigned npiServiceTaskEvents;
static uint16_t TX_DONE_ISR_EVENT_FLAG,MRDY_ISR_EVENT_FLAG,TRANSPORT_RX_ISR_EVENT_FLAG;
static NPI_QueueRec *queueData[1024];
static unsigned pending,transmitted,posts,freed,cs_depth,queue_checks;
static bool npiTxActive,hold,inject_on_second_empty_check;
static unsigned queues_seen_at_enter,cycles;
static int queue_object,semaphore_object;
static void *npiTxQueue=&queue_object,*npiSemHandle=&semaphore_object;
static uint32_t OsalPort_enterCS(void){return ++cs_depth;}
static void OsalPort_leaveCS(uint32_t key){assert(key==cs_depth);--cs_depth;}
static void Semaphore_post(void *s){assert(s==npiSemHandle);++posts;}
static void *OsalPort_malloc(size_t n){void *p=malloc(n);assert(p);return p;}
static void OsalPort_free(void *p){assert(p);free(p);++freed;}
static void OsalPort_msgDeallocate(void *p){OsalPort_free(p);}
static NPIMSG_msg_t *NPIFrame_frameMsg(uint8_t *msg){
    NPIMSG_msg_t *p=OsalPort_malloc(sizeof(*p));
    p->pBuf=msg;p->pBufSize=5;p->msgType=NPIMSG_Type_ASYNC;
    return p;
}
static void Queue_enqueue(void *q,void *elem){
    assert(q==npiTxQueue && pending<1024 && cs_depth>0);
    queueData[pending++]=(NPI_QueueRec*)elem;
}
static void *Queue_dequeue(void *q){
    assert(q==npiTxQueue && cs_depth>0);
    if(!pending)return NULL;
    NPI_QueueRec *p=queueData[0];
    for(unsigned i=1;i<pending;i++)queueData[i-1]=queueData[i];
    --pending;return p;
}
static uint8_t *newMsg(void){
    uint8_t *data=OsalPort_malloc(5);
    memset(data,0x5A,5);
    return data;
}
static void NPITask_sendToHost(uint8_t *pMsg);
static bool Queue_empty(void *q){
    assert(q==npiTxQueue);
    bool answer=pending==0;
    ++queue_checks;
    /* Synthetic higher-priority enqueue AFTER empty observation, BEFORE
       consumer clears the event flag. Not a claim this runs in live ZNP. */
    if(inject_on_second_empty_check && queue_checks==2 && answer){
        inject_on_second_empty_check=false;
        NPITask_sendToHost(newMsg());
    }
    return answer;
}
static uint16 NPITL_writeTL(uint8 *buf,uint16 len){
    assert(cs_depth>0 && !hold && !npiTxActive && buf!=NULL && len==5);
    npiTxActive=true;++transmitted;
    return len; /* Hardware UART is MOCKED, not tested here. */
}
static int b1_management_transport_unavailable(void){return hold;}
'''


MAIN = r'''
int main(int argc,char **argv){
    assert(argc==2);
    if(strcmp(argv[1],"burst")==0){
        for(unsigned i=0;i<100;i++)NPITask_sendToHost(newMsg());
        assert(pending==100 && (npiServiceTaskEvents&NPITASK_TX_READY_EVENT));
        cycle();
        assert(transmitted==1 && pending==99 && npiTxActive);
        for(unsigned i=1;i<100;i++){
            npiTxActive=false;
            NPITask_transportTxDoneCallBack(0);
            cycle();
            assert(transmitted==i+1 && pending==99-i && npiTxActive);
        }
        npiTxActive=false;NPITask_transportTxDoneCallBack(0);cycle();
        assert(pending==0 && !(npiServiceTaskEvents&NPITASK_TX_READY_EVENT));
        assert(!npiTxActive && transmitted==100 && freed==300 && cs_depth==0);
        puts("REAL_TI_NPI_TXQ_BURST_BOUNDED_DRAIN_PASS");
    } else if(strcmp(argv[1],"edge_loss")==0){
        /* TX_READY already set when queue becomes empty. */
        npiServiceTaskEvents=NPITASK_TX_READY_EVENT;
        inject_on_second_empty_check=true;
        cycle();
        assert(pending==1 && !npiTxActive && cs_depth==0);
        assert(!(npiServiceTaskEvents&NPITASK_TX_READY_EVENT));
        cycle(); /* Posted semaphore does not help if the event bit was lost. */
        assert(pending==1 && transmitted==0 && !npiTxActive);
        puts("REAL_TI_NPI_TX_READY_CLEAR_INTERLEAVING_POSSIBLE");
        /* A later producer is an important counterfactual: re-arms the queue. */
        NPITask_sendToHost(newMsg());
        cycle();assert(transmitted==1 && pending==1);
        npiTxActive=false;NPITask_transportTxDoneCallBack(0);
        cycle();assert(transmitted==2 && pending==0);
        npiTxActive=false;NPITask_transportTxDoneCallBack(0);
        cycle();assert(pending==0 && freed==6 && cs_depth==0);
        puts("REAL_TI_NPI_NEXT_ENQUEUE_REARMS_QUEUE_PASS");
    } else return 2;
    return 0;
}
'''


def build(source: str, tl: str, *, no_clear_mutant: bool = False):
    check = (
        "static void NPITask_ProcessTXQ(void)",
        "void NPITask_sendToHost(uint8_t *pMsg)",
        "static void NPITask_transportTxDoneCallBack(int size)",
        "static void NPITask_process(void)",
    )
    for name in check:
        if not source.count(name):
            raise ValueError("PINNED_FUNCTION_MISSING_" + name)
    tx = extract_function(source, check[0])
    prod = extract_function(source, check[1])
    cb = extract_function(source, check[2])
    busy = extract_function(tl, "bool NPITL_checkNpiBusy(void)")
    loop = extract_function(source, check[3])
    begin = "            // An ASYNC message is ready to send to the Host\n"
    end = "            // The Transport Layer has received some bytes\n"
    if source.count(begin) != 1 or source.count(end) != 1:
        raise ValueError("PINNED_TX_EVENT_SECTION_DRIFT")
    event = section(source, begin, end)
    if ("else if (!NPITL_checkNpiBusy()" not in event
            or "!b1_management_transport_unavailable()" not in event):
        raise ValueError("REQUIRES_ACTUAL_COMPOSED_B1_TX_BUSY_FIX")
    if no_clear_mutant:
        target = "npiServiceTaskEvents &= ~NPITASK_TX_READY_EVENT;"
        if event.count(target) != 1:
            raise ValueError("TX_CLEAR_MUTANT_ANCHOR_DRIFT")
        event = event.replace(target, "/* research negative mutant: event not cleared */", 1)
    start = "            // Capture the ISR events flags now within a critical section.\n"
    stop = "            // MRDY event\n"
    if loop.count(start) != 1 or loop.count(stop) != 1:
        raise ValueError("PINNED_ISR_MERGE_SECTION_DRIFT")
    merge = loop.split(start,1)[1].split(stop,1)[0]
    if "TX_DONE_ISR_EVENT_FLAG = 0;" not in merge:
        raise ValueError("PINNED_ISR_CLEAR_MISSING")
    done_marker="            if(npiServiceTaskEvents & NPITASK_TRANSPORT_TX_DONE_EVENT)"
    if loop.count(done_marker) != 1:
        raise ValueError("PINNED_TX_DONE_SECTION_DRIFT")
    # Parenthesized statement with C preprocessor branches still has balanced braces.
    a=loop.index(done_marker)
    opening=loop.index("{",a)
    level=0
    done=None
    for i in range(opening,len(loop)):
        if loop[i]=="{":level+=1
        elif loop[i]=="}":
            level-=1
            if level==0:
                done=loop[a:i+1]
                break
    if not done:
        raise ValueError("UNBALANCED_TX_DONE_SOURCE")
    generated = (PREAMBLE + "\n" + busy + "\n" + prod + "\n" + tx
                 + "\n" + cb + "\nstatic void cycle(void){\n"
                 + " uint32_t key;\n ++cycles;\n key=OsalPort_enterCS();\n"
                 + merge + "\n OsalPort_leaveCS(key);\n"
                 + event + "\n" + done + "\n}\n" + MAIN)
    return generated


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--source",type=Path,required=True)
    parser.add_argument("--tl-source",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--no-clear-mutant",action="store_true")
    args=parser.parse_args()
    c=build(args.source.read_text(),args.tl_source.read_text(),
            no_clear_mutant=args.no_clear_mutant)
    args.output.write_text(c,encoding="utf-8")
    print("REAL_COMPOSED_TXQ_EXTRACTED",hashlib.sha256(c.encode()).hexdigest(),
          "negative_mutant",args.no_clear_mutant)


if __name__=="__main__":
    main()
