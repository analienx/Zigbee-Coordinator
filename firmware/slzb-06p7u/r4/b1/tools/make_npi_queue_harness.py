"""Compile actual TI NPITask_incomingFrameCB with synthetic alloc/queue failures.

Proves RX ownership stays bounded with no leaked frame/record/container after
either allocation fails, and after an irrevocable transport fault. No serial.
"""
from pathlib import Path
import argparse
from patch_zdapp import extract_function

PREAMBLE=r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "b1_management.h"

#define NPIMSG_Type_ASYNC 0
#define NPITASK_FRAME_RX_EVENT 0x80u
typedef int NPIMSG_Type;
typedef struct {uint8_t *pBuf; uint16_t pBufSize; uint8_t msgType;} NPIMSG_msg_t;
typedef struct {int _elem; NPIMSG_msg_t *npiMsg;} NPI_QueueRec;
static uintptr_t cs_depth;
static unsigned allocations, free_count, live_alloc, posts, enqueued, events;
static unsigned fail_at;
static NPI_QueueRec *queued;
static int rx_queue, npi_semaphore;
static void *npiRxQueue=&rx_queue;
static void *npiSemHandle=&npi_semaphore;
static uint32_t npiServiceTaskEvents;
uintptr_t b1_management_test_disable(void)
{ assert(cs_depth==0); cs_depth=1; return 1; }
void b1_management_test_restore(uintptr_t key)
{ assert(cs_depth==1 && key==1); cs_depth=0; }
static void *OsalPort_malloc(size_t n)
{
    ++allocations;
    if (allocations==fail_at) return NULL;
    void *p=malloc(n); assert(p); ++live_alloc; return p;
}
static void OsalPort_free(void *p)
{
    if(p){assert(live_alloc>0); --live_alloc; ++free_count;free(p);}
}
static void OsalPort_msgDeallocate(void *p){OsalPort_free(p);}
static void Queue_enqueue(void *queue,void *elem)
{
    assert(queue==npiRxQueue && queued==NULL);
    queued=(NPI_QueueRec*)elem;
    ++enqueued;
}
static void Semaphore_post(void *sem){assert(sem==npiSemHandle);++posts;}

static uint8_t* frame(void)
{
    uint8_t *p=OsalPort_malloc(3); assert(p);
    p[0]=0;p[1]=0x21;p[2]=1;return p;
}
static void clear_healthy(void)
{
    assert(queued && queued->npiMsg);
    OsalPort_msgDeallocate(queued->npiMsg->pBuf);
    OsalPort_free(queued->npiMsg);
    OsalPort_free(queued);
    queued=NULL;
}
'''

MAIN=r'''
int main(int argc,char **argv)
{
    assert(argc==2);
    if(strcmp(argv[1],"healthy")==0)
    {
        NPITask_incomingFrameCB(3,frame(),NPIMSG_Type_ASYNC);
        assert(enqueued==1 && posts==1 && (npiServiceTaskEvents & NPITASK_FRAME_RX_EVENT));
        assert(live_alloc==3 && !b1_management_transport_unavailable());
        clear_healthy();
        assert(live_alloc==0);
        puts("B1_REAL_NPI_RX_OWNERSHIP_POSITIVE_PASS");
    }
    else if(strcmp(argv[1],"record_oom")==0)
    {
        uint8_t *p=frame(); fail_at=allocations+1;
        NPITask_incomingFrameCB(3,p,NPIMSG_Type_ASYNC);
        assert(live_alloc==0 && !queued && !enqueued && !posts);
        assert(b1_management_transport_unavailable());
        puts("B1_REAL_NPI_RECORD_OOM_NO_LEAK_PASS");
    }
    else if(strcmp(argv[1],"container_oom")==0)
    {
        uint8_t *p=frame(); fail_at=allocations+2;
        NPITask_incomingFrameCB(3,p,NPIMSG_Type_ASYNC);
        assert(live_alloc==0 && !queued && !enqueued && !posts);
        assert(b1_management_transport_unavailable());
        puts("B1_REAL_NPI_CONTAINER_OOM_NO_LEAK_PASS");
    }
    else if(strcmp(argv[1],"held_drop")==0)
    {
        b1_management_transport_failed(B1_ERROR_NPI_RX_OVERFLOW);
        unsigned before=allocations;
        NPITask_incomingFrameCB(3,frame(),NPIMSG_Type_ASYNC);
        assert(allocations==before+1 && live_alloc==0 && !queued);
        assert(!posts && b1_management_transport_unavailable());
        puts("B1_REAL_NPI_POST_CORRUPTION_DROP_PASS");
    }
    else return 2;
    return 0;
}
'''


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--source",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    source=args.source.read_text(encoding="utf-8")
    body=extract_function(source,
                          "static void NPITask_incomingFrameCB(uint8_t frameSize, uint8_t *pFrame,\n"
                          "                                    NPIMSG_Type msgType)")
    if "b1_management_transport_unavailable()" not in body or "b1_management_transport_failed(B1_ERROR_NPI_QUEUE)" not in body:
        raise RuntimeError("B1_RX_UNSAFE_QUEUE_HANDLING")
    args.output.write_text(PREAMBLE+body+MAIN,encoding="utf-8")
    print("B1_REAL_TI_RX_QUEUE_ALLOCATOR_BODY_EXTRACTED")

if __name__=="__main__":
    main()
