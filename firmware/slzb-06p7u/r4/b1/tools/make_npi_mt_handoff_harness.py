"""Compile the real TI NPI->MT handoff with bounded allocation failures.

Uses pinned output *after* the B1 source overlay, no real UART/stack. The
failure tests assert no leaked allocations and an explicit sticky transport
HOLD instead of silent loss of SREQ with shrinking heap.
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
typedef uint8_t uint8;
typedef uint8_t byte;
#define MT_RPC_FRAME_HDR_SZ 3u
#define MT_RPC_POS_LEN 0u
#define CMD_SERIAL_MSG 0x37u
#define OsalPort_SUCCESS 0u
#define OsalPort_INVALID_TASK 1u

typedef struct {uint8_t event;} Header;
typedef struct {Header hdr; uint8_t *msg;} mtOSALSerialData_t;
typedef struct {uint8_t msgType; uint16_t pBufSize; uint8_t *pBuf;} NPIMSG_msg_t;
static uint8_t MTServiceTaskID=2u;

static unsigned allocated, live_alloc, freed, fail_at, send_calls;
static int send_failed;
static mtOSALSerialData_t *delivered;
static int depth;
static unsigned intercepted_b1;
static void MT_BuildAndSendZToolResponse(uint8_t type, uint8_t cmd, uint8_t length, uint8_t *payload) {
    (void)type;(void)cmd;(void)length;(void)payload;
    ++intercepted_b1;
}
static void MT_ProcessIncoming(uint8_t *message) {
    (void)message;
    ++intercepted_b1;
}
uintptr_t b1_management_test_disable(void) {
    assert(depth==0);depth=1;return 5;
}
void b1_management_test_restore(uintptr_t key) {
    assert(depth==1 && key==5);depth=0;
}
static void *OsalPort_malloc(size_t n) {
    ++allocated;
    if (allocated==fail_at) return NULL;
    void *p=malloc(n);
    assert(p!=NULL);++live_alloc;return p;
}
static uint8_t *OsalPort_msgAllocate(size_t n) {
    return OsalPort_malloc(n);
}
static void OsalPort_free(void *p) {
    if(p){assert(live_alloc>0);--live_alloc;++freed;free(p);}
}
static uint8_t OsalPort_msgDeallocate(uint8_t *p) {
    OsalPort_free(p);return OsalPort_SUCCESS;
}
static uint8_t OsalPort_msgSend(uint8_t task,byte *msg) {
    assert(task==MTServiceTaskID);
    assert(msg!=NULL);++send_calls;
    if(send_failed) return OsalPort_INVALID_TASK;
    delivered=(mtOSALSerialData_t *)msg;
    return OsalPort_SUCCESS;
}
static NPIMSG_msg_t *request(void) {
    NPIMSG_msg_t *p=(NPIMSG_msg_t *)OsalPort_malloc(sizeof(*p));
    assert(p);
    p->pBuf=(uint8_t *)OsalPort_malloc(4);
    assert(p->pBuf);
    p->pBuf[0]=1;
    p->pBuf[1]=0x24;
    p->pBuf[2]=1;
    p->pBuf[3]=0;
    p->pBufSize=4;
    return p;
}
'''
MAIN=r'''
int main(int argc,char **argv) {
    assert(argc==2);
    NPIMSG_msg_t *in=request();
    if (strcmp(argv[1],"wrapper_oom")==0) fail_at=allocated+1;
    else if (strcmp(argv[1],"payload_oom")==0) fail_at=allocated+2;
    else if (strcmp(argv[1],"send_failed")==0) send_failed=1;
    else if (strcmp(argv[1],"healthy")!=0) return 2;
    uint8_t status=NPITask_sendBufToStack(in);
    assert(intercepted_b1==0); /* These cases must exercise MT handoff. */
    if (strcmp(argv[1],"healthy")==0) {
        assert(status==OsalPort_SUCCESS);
        assert(!b1_management_transport_unavailable());
        assert(send_calls==1 && delivered!=NULL && live_alloc==2);
        assert(delivered->msg[0]==1 && delivered->msg[1]==0x24);
        OsalPort_free(delivered->msg);
        (void)OsalPort_msgDeallocate((uint8_t *)delivered);
        assert(live_alloc==0);
        puts("B1_REAL_NPI_MT_HEALTHY_OWNERSHIP_PASS");
    } else {
        assert(status!=OsalPort_SUCCESS || send_calls==0);
        assert(b1_management_transport_unavailable());
        assert(b1_management_get_hold_active());
        assert(live_alloc==0 && delivered==NULL);
        if (strcmp(argv[1],"wrapper_oom")==0) assert(send_calls==0);
        if (strcmp(argv[1],"payload_oom")==0) assert(send_calls==0);
        if (strcmp(argv[1],"send_failed")==0) assert(send_calls==1);
        puts("B1_REAL_NPI_MT_LOST_REQUEST_NO_LEAK_HOLD_PASS");
    }
    assert(!depth);return 0;
}
'''
def main():
 p=argparse.ArgumentParser()
 p.add_argument("--source",type=Path,required=True)
 p.add_argument("--output",type=Path,required=True)
 a=p.parse_args()
 body=extract_function(a.source.read_text(encoding="utf8"),
                       "static uint8_t NPITask_sendBufToStack( NPIMSG_msg_t *pMsg )")
 needed=("b1_management_transport_failed(B1_ERROR_NPI_QUEUE)",
         "OsalPort_free(pOsalMsg->msg)",
         "OsalPort_msgDeallocate((uint8_t *)pOsalMsg)")
 if not all(s in body for s in needed):
  raise RuntimeError("PINNED_NPI_TO_MT_HANDOFF_NOT_SAFE")
 a.output.write_text(PREAMBLE+body+MAIN,encoding="utf8")
 print("B1_REAL_TI_NPI_MT_HANDOFF_SOURCE_EXTRACTED")
if __name__=="__main__":main()
