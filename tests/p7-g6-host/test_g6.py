#!/usr/bin/env python3
"""HOSTED ONLY: compile actual pinned TI function bodies, not replacement models.

Pre-fix allocation tests must fail; pre-fix overflow must time out. The same
injection vectors must succeed against the actual composed G5/G6 C bodies.
"""
import argparse, hashlib, json, os, re, subprocess, sys, tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
G6=ROOT/"firmware/slzb-06p7/ti832/g6"
sys.path.insert(0,str(G6))
import g6_overlay as g

COMMON=r'''
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "p7_g6.h"
typedef uint8_t uint8; typedef uint8_t byte; typedef uint16_t uint16;
typedef uint32_t Clock_Handle; typedef void *UART2_Handle;
#define UART2_EVENT_TX_FINISHED 0x20
#define MTRPC_POS_LEN 0
#define MTRPC_POS_CMD0 1
#define MTRPC_POS_CMD1 2
#define MTRPC_FRAME_HDR_SZ 3
#define MT_RPC_FRAME_HDR_SZ 3
#define MT_RPC_POS_LEN 0
#define MT_RPC_POS_CMD0 1
#define MT_RPC_POS_CMD1 2
#define MT_RPC_CMD_TYPE_MASK 0xE0
#define MTRPC_CMD_TYPE_MASK 0xE0
#define MTRPC_CMD_SRSP 0x60
#define MTRPC_CMD_SREQ 0x20
#define MT_RPC_CMD_SREQ 0x20
#define MT_RPC_CMD_SRSP 0x60
#define MT_RPC_SYS_SYS 1
#define CMD_SERIAL_MSG 1
#define NPI_TL_BUF_SIZE 64
#define NPITASK_TX_READY_EVENT 0x10
#define NPITASK_SYNC_TX_READY_EVENT 0x40
#define NPITASK_TRANSPORT_RX_EVENT 2
#define NPITASK_FRAME_RX_EVENT 8
typedef enum { NPIMSG_Type_ASYNC=1,NPIMSG_Type_SYNCRSP=2 } NPIMSG_Type;
typedef struct { uint8_t *pBuf; uint16_t pBufSize; NPIMSG_Type msgType; } NPIMSG_msg_t;
typedef struct { int _elem; NPIMSG_msg_t *npiMsg; } NPI_QueueRec;
typedef void (*npiIncomingFrameCBack_t)(uint8_t,uint8_t *,NPIMSG_Type);
typedef struct { struct { uint8_t event; } hdr; uint8_t *msg; } mtOSALSerialData_t;
static void *live[128]; static unsigned blocks,alloc_calls,fail_at;
static int send_status; static NPI_QueueRec *queued;
static uint32_t npiServiceTaskEvents; static uint16_t TRANSPORT_RX_ISR_EVENT_FLAG;
static int npiSemHandle, npiTxQueue, npiSyncTxQueue, npiRxQueue, MTServiceTaskID;
static uint8_t npiRxBuf[NPI_TL_BUF_SIZE]; static uint16_t npiRxBufHead,npiRxBufTail;
uint32_t fake_ticks; const uint32_t Clock_tickPeriod=1000;
uint32_t Clock_getTicks(void) { return fake_ticks; }
static void *alloc(size_t n) {
    if (++alloc_calls==fail_at) return NULL;
    void *p=calloc(1,n); assert(p); assert(blocks<128); live[blocks++]=p; return p;
}
static void release(void *p) {
    if(!p) return;
    unsigned i;
    for(i=0;i<blocks && live[i]!=p;i++);
    assert(i<blocks); free(p); live[i]=live[--blocks];
}
#define OsalPort_malloc alloc
#define OsalPort_msgAllocate alloc
#define OsalPort_free release
#define OsalPort_msgDeallocate release
static uint32_t OsalPort_enterCS(void) { return 0; }
static void (*leave_hook)(void);
static unsigned leave_counter, inject_at;
static void OsalPort_leaveCS(uint32_t k) {
    (void)k;
    if(leave_hook && ++leave_counter==inject_at) {
        void (*hook)(void)=leave_hook; leave_hook=NULL; hook();
    }
}
static void Semaphore_post(int h) { (void)h; }
static void Queue_enqueue(int q,int *elem) { (void)q; queued=(NPI_QueueRec*)elem; }
static uint8_t OsalPort_msgSend(int id,byte *p) {
    (void)id; if (!send_status) { mtOSALSerialData_t *m=(void*)p; release(m->msg); release(m); }
    return send_status;
}
static void batch(const uint8_t *p,unsigned n) { assert(n<=NPI_TL_BUF_SIZE); memcpy(npiRxBuf,p,n); npiRxBufHead=0; npiRxBufTail=n; }
'''

ALLOC_MAIN=r'''
int main(int argc,char **argv) {
    assert(argc==2);
    for(unsigned cycle=0;cycle<512;cycle++) {
        if(strcmp(argv[1],"send")==0) {
            for(unsigned f=1;f<=4;f++) {
                uint8_t *m=alloc(6); m[0]=3; m[1]=0x60;
                alloc_calls=0; fail_at=f; queued=NULL;
                NPITask_sendToHost(m); fail_at=0;
                if(queued) { release(queued->npiMsg->pBuf); release(queued->npiMsg); release(queued); }
                assert(blocks==0);
            }
        } else if(strcmp(argv[1],"stack")==0) {
            for(unsigned f=1;f<=3;f++) for(send_status=0;send_status<=1;send_status++) {
                NPIMSG_msg_t *m=alloc(sizeof(*m)); m->pBuf=alloc(6); m->pBuf[0]=3;
                alloc_calls=0; fail_at=f; uint8_t st=NPITask_sendBufToStack(m); fail_at=0;
                assert(blocks==0); assert(st==((f<=2 || send_status)?1:0));
            }
        } else {
            for(unsigned f=1;f<=3;f++) {
                uint8_t *frame=alloc(6); alloc_calls=0; fail_at=f; queued=NULL;
                NPITask_incomingFrameCB(6,frame,NPIMSG_Type_ASYNC); fail_at=0;
                if(queued) { release(queued->npiMsg->pBuf); release(queued->npiMsg); release(queued); }
                assert(blocks==0);
            }
        }
    }
    puts("PASS 512 actual-body allocation cycles"); return 0;
}
'''

RX_MAIN=r'''
static unsigned received;
static void receive(uint8_t n,uint8_t *p,NPIMSG_Type kind) {
    (void)kind; assert(n==4 && p[0]==1 && p[3]==0x42); received++; release(p);
}
static void recover(void) {
    uint32_t key;
    RECOVERY_BODY
}
static void inject_latched_batch(void) {
    uint8_t clean[]={0xfe,1,0x20,1,0x42,0x62};
    assert(p7_g6_rx_resync); batch(clean,sizeof clean);
    NPITask_transportRXCallBack(sizeof clean);
    assert(NPITL_getRxBufLen()==0 && blocks==1);
}
static void inject_fresh_batch(void) {
    uint8_t clean[]={0xfe,1,0x20,1,0x42,0x62};
    assert(!p7_g6_rx_resync); batch(clean,sizeof clean);
    NPITask_transportRXCallBack(sizeof clean);
}
int main(int argc,char **argv) {
    (void)argc; (void)argv;
    p7_diag_init(1,0,0); NPIFrame_initialize(receive);
    uint8_t partial[]={0xfe,3,0x20}; batch(partial,sizeof partial);
    NPITask_transportRXCallBack(sizeof partial); NPIFrame_collectFrameData(); assert(blocks==1);
    /* Overflow after a partial allocation; must not trap or complete it. */
    uint8_t lost[64]={0}; batch(lost,sizeof lost); NPITask_transportRXCallBack(sizeof lost);
    assert(p7_g6_rx_resync && NPITL_getRxBufLen()==0);
    /* Drop subsequent batches until task resynchronizes. */
    uint8_t clean[]={0xfe,1,0x20,1,0x42,0x62}; batch(clean,sizeof clean);
    NPITask_transportRXCallBack(sizeof clean); assert(NPITL_getRxBufLen()==0);
    leave_counter=0; inject_at=1; leave_hook=inject_latched_batch;
    recover(); assert(blocks==0 && p7_g6_rx_resync==0 && leave_hook==NULL);
    for(unsigned i=0;i<512;i++) {
        batch(clean,sizeof clean); NPITask_transportRXCallBack(sizeof clean); recover();
        assert(received==i+1 && blocks==0);
        /* Reset completed parser again: no stale pointer may be freed. */
        p7_g6_reset_parser(); assert(blocks==0);
    }
    /* A fresh callback after reset/clear must be delivered, not discarded. */
    batch(partial,sizeof partial); NPITask_transportRXCallBack(sizeof partial); recover(); assert(blocks==1);
    batch(lost,sizeof lost); NPITask_transportRXCallBack(sizeof lost);
    leave_counter=0; inject_at=2; leave_hook=inject_fresh_batch;
    recover(); assert(received==513 && blocks==0 && leave_hook==NULL);
    puts("PASS actual overflow callback, parser/ring resync, 512 clean frames"); return 0;
}
'''

ENDPOINT_MAIN=r'''
static uint8_t sent[P7_G6_MAX]; static size_t sent_len; static unsigned responses;
static void MT_BuildAndSendZToolResponse(uint8_t cmd0,uint8_t cmd1,uint8_t len,uint8_t *p) {
    assert(cmd0==0x61 && cmd1==0xf0); assert(len<=P7_G6_MAX);
    memcpy(sent,p,len); sent_len=len; responses++;
}
static void dispatch(uint8_t *pBuf) { ENDPOINT_BODY }
static void busy_hook(void) {
    uint8_t req[2]={1,0}, out[P7_G6_MAX];
    assert(p7_g6_response(req,2,1,out,sizeof out)==P7_G6_HDR+2);
    assert(out[5]==P7_G6_BUSY);
}
static void race_hook(void) {
    fake_ticks=101; p7_g6_uart_event(NULL,UART2_EVENT_TX_FINISHED,0,NULL);
}
static void print_hex(const char *name) {
    uint8_t req[2]={1,0}, out[P7_G6_MAX]; size_t n=p7_g6_response(req,2,1,out,sizeof out);
    printf("%s=",name); for(size_t i=0;i<n;i++) printf("%02x",out[i]); puts("");
}
int main(void) {
    p7_diag_init(1,0,0); fake_ticks=147;
    p7_g6_record(P7D_MT_RX,0); fake_ticks=1545;
    p7_g6_record(P7D_UART_FIFO_LOADED,1);
    p7_g6_uart_event(NULL,0x10,0,NULL); /* unrelated event must not record TX */
    assert(p7_diag_state.total==4);
    p7_g6_uart_event(NULL,UART2_EVENT_TX_FINISHED,0,NULL); assert(p7_diag_state.total==5);
    uint8_t req[258]={2,0x21,0xf0,1,0}; dispatch(req);
    assert(sent[5]==P7_G6_OK && sent_len==P7_G6_HDR+P7_DIAG_HDR+5*12+4);
    assert(sent[6]==1 && sent[7]==0 && sent[8]==0xe8 && sent[9]==3);
    printf("G6_HEX="); for(size_t i=0;i<sent_len;i++) printf("%02x",sent[i]); puts("");
    for(unsigned len=0;len<=255;len++) if(len!=2) {
        req[0]=(uint8_t)len; dispatch(req); assert(sent_len==P7_G6_HDR+2 && sent[5]==P7_G6_LENGTH);
    }
    req[0]=2; req[3]=9; dispatch(req); assert(sent[5]==P7_G6_VERSION_ERR);
    req[3]=1; req[4]=1; dispatch(req); assert(sent[5]==P7_G6_OPERATION);
    req[4]=0; req[1]=0x41; dispatch(req); assert(sent[5]==P7_G6_TYPE);
    assert(p7_g6_response(NULL,2,1,sent,sizeof sent)==P7_G6_HDR+2 && sent[5]==P7_G6_LENGTH);
    assert(p7_g6_response(req,2,1,sent,15)==0);
    p7_diag_preempt_hook=busy_hook;
    p7_g6_record(P7D_MT_RX,0);
    p7_diag_preempt_hook=NULL;
    /* Negative sampling-before-claim reproduction with the old API. */
    p7_diag_init(1,0,0); fake_ticks=100; uint32_t sampled=p7_g6_now();
    fake_ticks=101; p7_g6_uart_event(NULL,UART2_EVENT_TX_FINISHED,0,NULL);
    p7_diag_record(P7D_MT_RX,0,sampled); print_hex("PRE_RACE_HEX");
    /* Actual G6 ownership sampling: preemption loses its event rather than
     * publishing an out-of-order timestamp, with the drop explicitly exported. */
    p7_diag_init(1,0,0); fake_ticks=100; p7_diag_preempt_hook=race_hook;
    p7_g6_record(P7D_MT_RX,0); p7_diag_preempt_hook=NULL;
    fake_ticks=102; p7_g6_record(P7D_SRSP_QUEUED,0);
    assert(p7_diag_contention_dropped==1); print_hex("POST_RACE_HEX");
    puts("PASS actual SYS endpoint framing, length/version/operation/type, UART event"); return 0;
}
'''

def strip_includes(s): return re.sub(r'^#include[^\n]*\n','',s,flags=re.M)

def run_suite(sdk,output):
    paths=sorted({p[0] for p in g.diag.PATCHES}|{g.RX,g.TL,g.SYS})
    old={p:(sdk/p).read_text() for p in paths}
    stage,_=g.diag.apply_patches(old); new=g.patch(stage)
    output.mkdir(parents=True,exist_ok=True)
    (output/"inputs.json").write_text(json.dumps({p:hashlib.sha256(old[p].encode()).hexdigest() for p in paths},indent=2))
    checks=[]
    with tempfile.TemporaryDirectory() as td:
        d=Path(td); (d/"ti/sysbios/knl").mkdir(parents=True)
        (d/"ti/sysbios/knl/Clock.h").write_text("#include <stdint.h>\nextern const uint32_t Clock_tickPeriod;\nuint32_t Clock_getTicks(void);\n")
        recorder=d/"p7_clock_recorder.c"; recorder.write_text(g.clock_recorder((g.G5/"p7_crashdiag.c").read_text()))
        def build(name,body):
            c=d/(name+".c"); c.write_text(COMMON+body)
            exe=d/name
            subprocess.run(["cc","-std=c11","-Wall","-Wextra","-Wno-unused-function","-Wno-unused-variable","-g","-fsanitize=address,undefined","-DP7_DIAG_TEST_HOOKS=1",
                "-I"+str(d),"-I"+str(G6),"-I"+str(g.G5),str(c),str(G6/"p7_g6.c"),str(recorder),"-o",str(exe)],check=True)
            return exe
        for version,t in (("pre",old),("post",new)):
            body=g.function(t[g.FRAME],"NPIFrame_frameMsg")+"\n"
            body+="static uint8_t npiframe_calcMTFCS(uint8_t *p,uint8_t n);\n" if False else ""
            # frameMsg calls FCS helper; preserve the genuine helper body too.
            body=g.function(t[g.FRAME],"npiframe_calcMTFCS")+"\n"+body
            body+=g.function(t[g.TASK],"NPITask_sendToHost")+"\n"+g.function(t[g.TASK],"NPITask_sendBufToStack")+"\n"
            vectors=ALLOC_MAIN
            if version=="pre":
                # The named pre-stack negative must hit its leaking payload
                # allocation, not fail earlier on the old success-status bug.
                vectors=vectors.replace("for(unsigned f=1;f<=3;f++) for(send_status=0;",
                    "for(unsigned f=2;f<=2;f++) for(send_status=0;")
            body+=g.function(t[g.TASK],"NPITask_incomingFrameCB")+"\n"+vectors
            exe=build(version+"_alloc","#define MT_SOF 0xfe\n"+body)
            for case in ("send","stack","ingress"):
                r=subprocess.run([str(exe),case],capture_output=True,text=True)
                if (r.returncode==0)!=(version=="post"): raise AssertionError((version,case,r.stdout,r.stderr))
                (output/(version+"_"+case+".log")).write_text(r.stdout+r.stderr)
                if version=="pre" and 'blocks==0' not in r.stderr:raise AssertionError("UNRELATED_PREFIX_FAILURE:"+r.stderr)
                checks.append({"test":version+"_"+case,"returncode":r.returncode,"expected_failure":version=="pre"})
        # Real parser + RxBuf code and real transport read/discard, with only
        # platform allocator/critical-section/UART input supplied by the harness.
        t=new; recovery=t[g.TASK].split("                if (p7_g6_rx_resync) {",1)[1].split("                NPIFrame_collectFrameData();",1)[0]
        recovery="if (p7_g6_rx_resync) {"+recovery+"NPIFrame_collectFrameData();"
        body=g.function(t[g.TL],"NPITL_getRxBufLen")+"\n"+g.function(t[g.TL],"NPITL_readTL")+"\n"+g.function(t[g.TL],"p7_g6_discard_tl")+"\n"
        body+=strip_includes(t[g.RX])+"\n"+strip_includes(t[g.FRAME])+"\n"
        body+=g.function(t[g.TASK],"NPITask_transportRXCallBack")+"\n"+RX_MAIN.replace("RECOVERY_BODY",recovery)
        exe=build("post_rx",body); r=subprocess.run([str(exe)],capture_output=True,text=True,check=True); print(r.stdout)
        checks.append({"test":"post_overflow_512_frames","returncode":r.returncode})
        # Unpatched infinite callback demonstrably fails the same overflow input.
        pre=body.replace(g.function(new[g.TASK],"NPITask_transportRXCallBack"),g.function(old[g.TASK],"NPITask_transportRXCallBack"))
        exe=build("pre_rx",pre)
        try: subprocess.run([str(exe)],timeout=1,capture_output=True,check=True)
        except subprocess.TimeoutExpired: checks.append({"test":"pre_overflow","expected_timeout":True})
        else: raise AssertionError("PRE_OVERFLOW_DID_NOT_TRAP")
        endpoint=g.function(t[g.SYS],"MT_SysCommandProcessing")
        endpoint=endpoint.split("    case P7_G6_CMD:\n",1)[1].split("    case MT_SYS_RESET_REQ:",1)[0]
        # Keep the exact case body but remove its switch-only break statement.
        endpoint=endpoint.replace("      break;\n","")
        uart=g.function(t[g.UART],"p7_g6_uart_event")
        exe=build("endpoint",uart+"\n"+ENDPOINT_MAIN.replace("ENDPOINT_BODY",endpoint))
        r=subprocess.run([str(exe)],capture_output=True,text=True,check=True); print(r.stdout)
        (output/"g6-snapshot.txt").write_text(r.stdout)
        checks.append({"test":"compiled_SYS_F0_and_UART_event","returncode":r.returncode})
        # Missing and duplicated anchors must fail before any write.
        for variant in (dict(stage,**{g.TASK:"missing"}),dict(stage,**{g.SYS:stage[g.SYS]+stage[g.SYS]})):
            try:g.patch(variant)
            except ValueError: pass
            else:raise AssertionError("BAD_ANCHOR_ACCEPTED")
    (output/"regressions.json").write_text(json.dumps(checks,indent=2)+"\n")
    print("PASS actual-source G6 regressions",checks)

if __name__=="__main__":
    p=argparse.ArgumentParser(); p.add_argument("--sdk",type=Path,required=True); p.add_argument("--out",type=Path,required=True)
    a=p.parse_args(); run_suite(a.sdk,a.out)
