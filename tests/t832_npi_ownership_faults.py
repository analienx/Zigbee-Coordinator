#!/usr/bin/env python3
"""Real patched TI NPI ownership fault-injection test, hosted CI only.

Extracts the three actual C functions *after* the pinned SDK patcher runs,
compiles their real source bodies with mocked OSAL allocator/queue primitives,
and executes success and first/second allocation-failure paths. No RF or P10
claims follow from these host tests.
"""
import argparse
from pathlib import Path
import subprocess
import tempfile


def function(src: str, header: str) -> str:
    assert src.count(header) == 1, f"function header not unique: {header}"
    at = src.index(header)
    brace = src.index("{", at + len(header))
    depth = 0
    for i in range(brace, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[at:i + 1]
    raise ValueError(f"unclosed function: {header}")


PREFIX = r"""
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
typedef uint8_t uint8;
typedef uint8_t byte;
typedef int NPIMSG_Type;
enum { NPIMSG_Type_ASYNC=1, NPIMSG_Type_SYNCRSP=2 };
typedef struct { uint8_t event; } osal_hdr_t;
typedef struct { osal_hdr_t hdr; uint8_t *msg; } mtOSALSerialData_t;
typedef struct { uint8_t *pBuf; uint16_t pBufSize; NPIMSG_Type msgType; } NPIMSG_msg_t;
typedef struct { int value; } Queue_Elem;
typedef struct { Queue_Elem _elem; NPIMSG_msg_t *npiMsg; } NPI_QueueRec;
enum { CMD_SERIAL_MSG=11, MT_RPC_FRAME_HDR_SZ=3, MT_RPC_POS_LEN=0 };
static int outstanding, malloc_calls, msg_calls, fail_malloc_at, fail_msg_at;
static int queued_rx, queued_tx, sem_posts, stack_sends;
static NPI_QueueRec *pending_queue;
static mtOSALSerialData_t *pending_stack;
static int npiSemHandle, MTServiceTaskID;
static void *npiRxQueue=(void *)1, *npiTxQueue=(void *)2;
static uint32_t npiServiceTaskEvents;
enum { NPITASK_FRAME_RX_EVENT=4, NPITASK_TX_READY_EVENT=16 };
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"fail line %d: %s\n", __LINE__, #x); exit(7); } } while (0)

static void *tracked_alloc(size_t n) {
    void *p=calloc(1,n ? n : 1);
    CHECK(p!=NULL); outstanding++; return p;
}
void *OsalPort_malloc(size_t n) {
    malloc_calls++;
    if (malloc_calls==fail_malloc_at) return NULL;
    return tracked_alloc(n);
}
void *OsalPort_msgAllocate(size_t n) {
    msg_calls++;
    if (msg_calls==fail_msg_at) return NULL;
    return tracked_alloc(n);
}
void OsalPort_free(void *p) { CHECK(p); CHECK(outstanding>0); outstanding--; free(p); }
void OsalPort_msgDeallocate(void *p) { OsalPort_free(p); }
uint32_t OsalPort_enterCS(void) { return 0; }
void OsalPort_leaveCS(uint32_t key) { (void)key; }
void Semaphore_post(int sem) { (void)sem; sem_posts++; }
void Queue_enqueue(void *q, Queue_Elem *elem) {
    CHECK(pending_queue == NULL);
    pending_queue=(NPI_QueueRec *)elem;
    if(q == npiRxQueue) queued_rx++; else if(q == npiTxQueue) queued_tx++;
    else CHECK(0);
}
int OsalPort_msgSend(int dest, byte *msg) {
    (void)dest; CHECK(pending_stack == NULL);
    pending_stack=(mtOSALSerialData_t *)msg; stack_sends++;
    return 0;
}
static NPIMSG_Type next_frame_type = NPIMSG_Type_ASYNC;
NPIMSG_msg_t *NPIFrame_frameMsg(uint8_t *incoming) {
    NPIMSG_msg_t *n=(NPIMSG_msg_t *)OsalPort_malloc(sizeof(*n));
    if(n) {
        n->pBuf=(uint8_t *)OsalPort_msgAllocate(8);
        if(!n->pBuf) { OsalPort_free(n); n=NULL; }
        else { n->pBufSize=8; n->msgType=next_frame_type; }
    }
    OsalPort_msgDeallocate(incoming);
    return n;
}
static void reset_failures(void) {
    fail_malloc_at=0; fail_msg_at=0; malloc_calls=0; msg_calls=0;
}
static void clean_queue(void) {
    if(pending_queue) {
        CHECK(pending_queue->npiMsg != NULL);
        OsalPort_msgDeallocate(pending_queue->npiMsg->pBuf);
        OsalPort_free(pending_queue->npiMsg);
        OsalPort_free(pending_queue);
        pending_queue=NULL;
    }
}
static void clean_stack(void) {
    if(pending_stack) {
        OsalPort_free(pending_stack->msg);
        OsalPort_msgDeallocate(pending_stack);
        pending_stack=NULL;
    }
}
static NPIMSG_msg_t *make_input(void) {
    NPIMSG_msg_t *p=tracked_alloc(sizeof(*p));
    p->pBuf=tracked_alloc(8);
    p->pBuf[0]=5; // [MT_RPC_POS_LEN] = 5
    return p;
}
"""

TESTS = r"""
int main(void) {
    // RX complete frame callback: both independent wrapper allocation failures.
    for(int fail=1; fail<=2; fail++) {
        reset_failures(); fail_malloc_at=fail;
        uint8_t *frame=tracked_alloc(8);
        NPITask_incomingFrameCB(8, frame, NPIMSG_Type_ASYNC);
        CHECK(outstanding==0); CHECK(pending_queue==NULL);
    }
    reset_failures();
    NPITask_incomingFrameCB(8, tracked_alloc(8), NPIMSG_Type_ASYNC);
    CHECK(queued_rx==1 && pending_queue!=NULL);
    clean_queue(); CHECK(outstanding==0);

    // Complete-framed outgoing path: queue-record allocation failure after
    // NPIFrame_frameMsg has already acquired message+container.
    reset_failures(); fail_malloc_at=2;
    NPITask_sendToHost(tracked_alloc(8));
    CHECK(outstanding==0 && pending_queue==NULL);
    reset_failures();
    NPITask_sendToHost(tracked_alloc(8));
    CHECK(queued_tx==1 && pending_queue!=NULL);
    clean_queue(); CHECK(outstanding==0);

    // Unsupported message type still must free ownership.
    reset_failures(); next_frame_type=99;
    NPITask_sendToHost(tracked_alloc(8));
    CHECK(outstanding==0 && pending_queue==NULL);
    next_frame_type=NPIMSG_Type_ASYNC;

    // Incoming host -> stack: fail wrapper allocation, fail second (payload)
    // allocation, then success. All paths release incoming frame & container.
    for(int mode=1; mode<=3; mode++) {
        reset_failures();
        NPIMSG_msg_t *input=make_input();
        if(mode==1) fail_msg_at=1;
        if(mode==2) fail_malloc_at=1;
        int ok=NPITask_sendBufToStack(input);
        if(mode<3) CHECK(ok==0 && stack_sends==0);
        else CHECK(ok==0 && stack_sends==1 && pending_stack!=NULL);
        clean_stack(); stack_sends=0;
        CHECK(outstanding==0);
    }
    puts("PASS actual TI NPI ownership fault injection: 9 paths, no leaks");
    return 0;
}
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdk", type=Path, required=True)
    args = parser.parse_args()
    src=(args.sdk / "source/ti/zstack/npi/npi_task.c").read_text()
    names=(
        "void NPITask_sendToHost(uint8_t *pMsg)\n",
        "static uint8_t NPITask_sendBufToStack( NPIMSG_msg_t *pMsg )\n",
        "static void NPITask_incomingFrameCB(uint8_t frameSize, uint8_t *pFrame,\n"
        "                                    NPIMSG_Type msgType)\n",
    )
    bodies=[function(src,h) for h in names]
    c=PREFIX+"\n\n".join(bodies)+TESTS
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp)
        (root / "faults.c").write_text(c)
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra",
                        "-Wno-unused-variable", "-Wno-unused-function",
                        "-o", str(root / "faults"), str(root / "faults.c")],
                       check=True)
        subprocess.run([str(root / "faults")], check=True)


if __name__ == "__main__":
    main()
