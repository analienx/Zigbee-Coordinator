#!/usr/bin/env python3
"""Actual pinned-TI NPI→MT ingress owner with allocator and send failures.

Run the extracted *composed C function*, not a Python reimplementation.
Every failed handoff must free its owned wrapper, data and inbound frame.
"""
import hashlib
import shutil
import subprocess
import tempfile
from pathlib import Path
from r4_uart_tx_liveness import extract
from r4_srsp_service import TASK

PREFIX=r"""
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t uint8;
typedef uint8_t byte;
#define MT_RPC_FRAME_HDR_SZ 3u
#define MT_RPC_POS_LEN 0u
#define CMD_SERIAL_MSG 0x44u
typedef struct {uint8_t *pBuf;} NPIMSG_msg_t;
typedef struct {struct {uint16_t event;} hdr; uint8_t *msg;} mtOSALSerialData_t;
static uint8_t MTServiceTaskID=1;
static int alloc_calls, fail_at, live_alloc, send_reject;
static mtOSALSerialData_t *delivered;
static uint32_t cs_level;
static uint32_t OsalPort_enterCS(void){return cs_level++;}
static void OsalPort_leaveCS(uint32_t key){assert(cs_level==key+1);--cs_level;}
static void *OsalPort_malloc(size_t n){
 ++alloc_calls;if(alloc_calls==fail_at)return NULL;
 void *p=malloc(n);assert(p);++live_alloc;return p;
}
static void OsalPort_free(void *p){if(p){assert(live_alloc>0);--live_alloc;free(p);}}
static void *OsalPort_msgAllocate(size_t n){return OsalPort_malloc(n);}
static int OsalPort_msgDeallocate(void *p){OsalPort_free(p);return 0;}
static uint8_t OsalPort_msgSend(uint8_t id, byte *msg){
 assert(id==1);
 if(send_reject)return (uint8_t)send_reject;
 assert(delivered==NULL);delivered=(mtOSALSerialData_t*)msg;return 0u;
}
static void B4_V45_Tick(volatile uint32_t *p){
 uint32_t k=OsalPort_enterCS();if(*p!=UINT32_MAX)++*p;OsalPort_leaveCS(k);
}
"""
MAIN=r"""
static NPIMSG_msg_t *incoming(void){
 NPIMSG_msg_t *p=(NPIMSG_msg_t *)OsalPort_malloc(sizeof(NPIMSG_msg_t));
 assert(p);
 p->pBuf=(uint8_t*)OsalPort_msgAllocate(8);
 assert(p->pBuf);
 p->pBuf[0]=5;p->pBuf[1]=0x24;p->pBuf[2]=0x00;
 for(unsigned i=3;i<8;++i)p->pBuf[i]=(uint8_t)i;
 return p;
}
int main(void){
 /* Failure #1: no OSAL header. The incoming frame is still freed. */
 NPIMSG_msg_t *p=incoming();
 fail_at=alloc_calls+1;
 assert(NPITask_sendBufToStack(p)!=0u);
 fail_at=0;assert(!live_alloc && B4_V45_IngressAllocFailed==1);
 /* Failure #2: header allocated, payload copy allocation fails. */
 p=incoming();fail_at=alloc_calls+2;
 assert(NPITask_sendBufToStack(p)!=0u);
 fail_at=0;assert(!live_alloc && B4_V45_IngressAllocFailed==2);
 /* Failure #3: message queue rejects the completed allocation. */
 p=incoming();send_reject=7;
 assert(NPITask_sendBufToStack(p)==7u);
 send_reject=0;assert(!live_alloc && B4_V45_IngressSendFailed==1);
 /* Success: only MT service consumer may free the transferred wrapper. */
 p=incoming();
 assert(NPITask_sendBufToStack(p)==0u);
 assert(live_alloc==2 && delivered && delivered->hdr.event==CMD_SERIAL_MSG);
 assert(delivered->msg[0]==5 && delivered->msg[1]==0x24);
 OsalPort_free(delivered->msg);
 OsalPort_msgDeallocate(delivered);delivered=NULL;
 assert(!live_alloc && !cs_level);
 printf("V45_INGRESS_OWNER_PASS allocation_failures=%u send_rejections=%u live=%d\n",
  (unsigned)B4_V45_IngressAllocFailed,(unsigned)B4_V45_IngressSendFailed,live_alloc);
 return 0;
}
"""

def exercise(sdk):
    sdk=Path(sdk)
    task=(sdk/TASK).read_text()
    fn=extract(task,"static uint8_t NPITask_sendBufToStack( NPIMSG_msg_t *pMsg )")
    source=PREFIX+"\n".join([
       "static volatile uint32_t B4_V45_IngressAllocFailed=0u;",
       "static volatile uint32_t B4_V45_IngressSendFailed=0u;",
       fn,MAIN])
    cc=shutil.which("cc") or shutil.which("gcc")
    if not cc:raise RuntimeError("V45_INGRESS_COMPILER_MISSING")
    def run(name,src,expected):
        with tempfile.TemporaryDirectory(prefix="v45-ingress-") as td:
            p=Path(td);(p/"c.c").write_text(src)
            b=subprocess.run([cc,"-std=c11","-O1","-g","-fsanitize=address,undefined",
                    "-fno-omit-frame-pointer","-Wall","-Wextra",
                    str(p/"c.c"),"-o",str(p/"t")],text=True,capture_output=True,timeout=30)
            if b.returncode:raise RuntimeError("V45_INGRESS_COMPILE_"+name+"\n"+b.stderr[-5000:])
            r=subprocess.run([str(p/"t")],text=True,capture_output=True,timeout=15)
            if (r.returncode==0)!=expected:
                raise RuntimeError("V45_INGRESS_ASSERT_"+name+"\n"+r.stdout[-2000:]+r.stderr[-5000:])
            return r.stdout.strip()
    result=run("correct_ownership",source,True)
    mutants={
        "false_success_on_alloc_failure":("uint8_t msgStatus = 1u;","uint8_t msgStatus = 0u;"),
        "leak_payload_on_rejected_send":("OsalPort_free(pOsalMsg->msg);","/* deliberately missing free */"),
        "leak_header_on_payload_failure":(
           "B4_V45_Tick(&B4_V45_IngressAllocFailed);\n            (void)OsalPort_msgDeallocate((uint8_t *)pOsalMsg);",
           "B4_V45_Tick(&B4_V45_IngressAllocFailed);\n            /* deliberately missing free */"),
    }
    for name,(old,new) in mutants.items():
        if source.count(old)!=1:raise RuntimeError("V45_INGRESS_MUTANT_ANCHOR_"+name)
        run(name,source.replace(old,new,1),False)
    return {"schema":"p7u-v45-actual-npi-ingress-ownership-v1",
            "status":"PASS","compiled_actual_ti_function":True,
            "negative_mutants":list(mutants),
            "result":result,"source_sha256":hashlib.sha256(source.encode()).hexdigest(),
            "physical_rf_or_uart_exercised":False}
