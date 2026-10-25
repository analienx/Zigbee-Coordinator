"""Actual TI NPI/MT/SYS/client/UART bodies with synthetic RTOS/UART boundary.

No serial port is opened. The boundary sender drains synthetic messages; PASS
does not attest an actual UART delivery, scheduler interleaving, RF or reboot.
"""
import argparse
import re
from pathlib import Path
from patch_zdapp import extract_function

SCENARIOS = (
    "healthy", "hold_nv", "hold_security", "first_current", "sticky",
    "bad_query", "bad_fcs", "areq", "alloc_fail", "npi_queue", "npi_sem",
    "npi_register", "uart_open", "uart_read", "start_hold", "start_healthy", "npi_first",
    "storm", "nv4_detail", "retained_commands", "uncommissioned_commands",
    "startup_tx_generation", "startup_tx_coalesced", "startup_tx_short",
)

PREAMBLE = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include "b1_management.h"
#include "b1_admission.h"
#define NPI_FLOW_CTRL 0
#define DeviceFamily_CC13X2X7 1
#define MT_RPC_FRAME_HDR_SZ 3
#define MT_RPC_POS_LEN 0
#define MT_RPC_POS_CMD0 1
#define MT_RPC_POS_CMD1 2
#define MT_RPC_POS_DAT0 3
#define MT_RPC_CMD_TYPE_MASK 0xE0
#define MT_RPC_SUBSYSTEM_MASK 0x1F
#define MT_RPC_CMD_SREQ 0x20
#define MT_RPC_CMD_SRSP 0x60
#define MT_RPC_SYS_RES0 0
#define MT_RPC_SYS_SYS 1
#define MT_RPC_SYS_MAX 14
#define MT_RPC_DATA_MAX 250
#define MT_RPC_SUCCESS 0
#define MT_RPC_ERR_SUBSYSTEM 1
#define MT_RPC_ERR_COMMAND_ID 2
#define MT_RPC_ERR_PARAMETER 3
#define MT_RPC_ERR_LENGTH 4
#define MT_SRSP_SYS 0x61
#define MTRPC_FRAME_HDR_SZ 3
#define MTRPC_POS_LEN 0
#define MTRPC_POS_CMD0 1
#define MTRPC_POS_CMD1 2
#define LO_UINT16(x) ((uint8_t)(x))
#define HI_UINT16(x) ((uint8_t)((x)>>8))
#define MT_CAP_SYS 1
#define MT_CAP_MAC 2
#define MT_CAP_NWK 4
#define MT_CAP_AF 8
#define MT_CAP_ZDO 16
#define MT_CAP_SAPI 32
#define MT_CAP_UTIL 64
#define MT_CAP_DEBUG 128
#define MT_CAP_APP 256
#define MT_CAP_GP 512
#define MT_CAP_ZOAD 4096
#define MT_CAP_APP_CNF 1024
#define CMD_SERIAL_MSG 1
#define UART_ISR_BUF_SIZE 32
#define NPI_UART_BR 115200
#define UART2_DataLen_8 8
#define UART2_StopBits_1 1
#define UART2_Mode_CALLBACK 1
#define UART2_ReadReturnMode_PARTIAL 1
#define CONFIG_DISPLAY_UART 0
#define UART2_STATUS_SUCCESS 0
#define UART2_EVENT_TX_FINISHED 1u
typedef uint8_t uint8;
typedef uint8_t byte;
typedef uint16_t uint16;
typedef void Void;
typedef uintptr_t UArg;
typedef void (*npiCB_t)(uint16_t, uint16_t);
typedef void (*npiRtosCB_t)(int);
typedef struct { uint8_t event; } OsalPort_EventHdr;
typedef struct { OsalPort_EventHdr hdr; uint8_t *msg; } mtOSALSerialData_t;
typedef struct { uint8_t msgType; uint16_t pBufSize; uint8_t *pBuf; } NPIMSG_msg_t;
typedef int NPIMSG_Type;
#define NPIMSG_Type_ASYNC 0
typedef void (*npiIncomingFrameCBack_t)(uint8_t,uint8_t*,NPIMSG_Type);
#define NPIFRAMEMT_SOP_STATE 0
#define NPIFRAMEMT_CMD_STATE1 1
#define NPIFRAMEMT_CMD_STATE2 2
#define NPIFRAMEMT_LEN_STATE 3
#define NPIFRAMEMT_DATA_STATE 4
#define NPIFRAMEMT_FCS_STATE 5
#define MT_SOF 0xFE
typedef void *UART2_Handle;
typedef struct { int baudRate, dataLength, stopBits, readMode, writeMode, readReturnMode;
                 void (*readCallback)(void); void (*writeCallback)(void);
                 uint32_t eventMask;
                 void (*eventCallback)(UART2_Handle,uint32_t,uint32_t,void*); } UART2_Params;
typedef struct { int mode; } Semaphore_Params;
#define MAX_TASKS 15
typedef int sem_t;
typedef struct { uint8_t taskId; void *taskHndl; void *qHandle; sem_t *taskSem;
                 bool conservePower; uint32_t *pEventFlag; } TaskEntry;
static TaskEntry taskTbl[MAX_TASKS];
static uint8_t taskCnt;
static unsigned live_alloc, peak_alloc, allocations, cs_depth;
static unsigned mutations, sent, forwarded, process_started, mt_id_reads;
static unsigned queue_calls, queue_deleted, sem_posts, uart_reads, uart_opens;
static int fail_alloc, fail_queue, fail_sem, fail_register, fail_uart, fail_read;
static uint8_t last_reply[255];
static uint8_t wire_buffer[255], wire_size, wire_cursor;
static uint8_t state, LEN_Token, FSC_Token, tempDataLen, *pMsg;
static npiIncomingFrameCBack_t incomingFrameCBFunc;
static uint8_t npiTaskID = 0xEEu, npiServiceTaskId;
static uint32_t npiServiceTaskEvents;
static uint32_t MTServiceTaskID;
static int structSem, queue_sentinels[4], task_sentinel;
static void *npiTxQueue, *npiRxQueue, *npiSemHandle;
static void *npiInitializationMutexHandle = &task_sentinel;
static uint8_t *TransportRxBuf, *TransportTxBuf;
static uint16_t TransportRxLen;
static uint8_t isrRxBuf[UART_ISR_BUF_SIZE];
static npiCB_t npiTransmitCB;
static UART2_Handle uartHandle;
static const uint8_t MTVersionString[] = { 2u, 1u, 3u, 0u, 0u, 0u };
void MT_ProcessIncoming(uint8_t*);
uintptr_t b1_management_test_disable(void) { assert(cs_depth==0); cs_depth=1; return 9; }
void b1_management_test_restore(uintptr_t key) { assert(key==9 && cs_depth==1); cs_depth=0; }
void *OsalPort_malloc(uint32_t n) {
    ++allocations;
    if (fail_alloc) return NULL;
    void *p=malloc(n); assert(p); ++live_alloc;
    if(live_alloc>peak_alloc) peak_alloc=live_alloc;
    return p;
}
void OsalPort_free(void *p) { if(p) { assert(live_alloc>0); --live_alloc; free(p); } }
void *OsalPort_msgAllocate(uint32_t n) { return OsalPort_malloc(n); }
void OsalPort_msgDeallocate(void *p) { OsalPort_free(p); }
uint8_t OsalPort_msgSend(uint8_t id, uint8_t *p) {
    if(id==8u) {
        mtOSALSerialData_t *m=(mtOSALSerialData_t*)p;
        ++forwarded; MT_ProcessIncoming(m->msg); OsalPort_free(m->msg); OsalPort_free(m); return 0;
    }
    assert(id==npiServiceTaskId && id==npiTaskID);
    assert((size_t)p[0]+3u <= sizeof(last_reply));
    memcpy(last_reply,p,(size_t)p[0]+3u); ++sent; OsalPort_free(p); return 0;
}
uint32_t OsalPort_enterCS(void) { return 0; }
void OsalPort_leaveCS(uint32_t key) { (void)key; }
void *Queue_create(void *a,void *b) { (void)a; (void)b; ++queue_calls;
    if(fail_queue && queue_calls==2) return NULL;
    assert(queue_calls<=4); return &queue_sentinels[queue_calls-1]; }
void Queue_delete(void **q) { assert(*q); *q=NULL; ++queue_deleted; }
void Semaphore_Params_init(Semaphore_Params *p) { p->mode=0; }
void Semaphore_construct(int *s,int n,Semaphore_Params *p) { (void)s; (void)n; (void)p; }
void *Semaphore_handle(int *s) { return fail_sem?NULL:s; }
void Semaphore_post(void *s) { assert(s); ++sem_posts; }
void *Task_self(void) { return &task_sentinel; }
uint8_t OsalPort_registerTask(void*,void*,uint32_t*);
uint8_t MTTask_getServiceTaskId(void) { ++mt_id_reads; return 8u; }
void NPITask_process(void) { ++process_started; }
void NPITask_transportTxDoneCallBack(int size) { (void)size; }
void NPITask_transportRXCallBack(int size) { (void)size; }
void NPITask_MRDYEventCB(int size) { (void)size; }
static uint8_t NPITask_sendBufToStack(NPIMSG_msg_t*);
void NPITask_incomingFrameCB(uint8_t a,uint8_t *b,NPIMSG_Type c) {
    NPIMSG_msg_t *m=OsalPort_malloc(sizeof(*m)); assert(m);
    m->pBuf=b; m->pBufSize=a; m->msgType=(uint8_t)c;
    assert(NPITask_sendBufToStack(m)==0);
}
uint8_t NPIRxBuf_GetRxBufCount(void) { return (uint8_t)(wire_size-wire_cursor); }
void NPIRxBuf_ReadFromRxBuf(uint8_t *dst,uint8_t n) {
    assert(n<=NPIRxBuf_GetRxBufCount()); memcpy(dst,wire_buffer+wire_cursor,n); wire_cursor+=n;
}
uint8_t npiframe_calcMTFCS(uint8_t*,uint8_t);
void UART2_Params_init(UART2_Params *p) { memset(p,0,sizeof(*p)); }
UART2_Handle UART2_open(int index,UART2_Params *p) { assert(index==0 && p->baudRate==115200);
    assert(p->eventMask & UART2_EVENT_TX_FINISHED);
    assert(p->eventCallback != NULL);
    ++uart_opens; return fail_uart?NULL:&task_sentinel; }
int UART2_read(UART2_Handle h,void *p,size_t n,void *unused) {
    (void)p;(void)unused; assert(h && n==32); ++uart_reads; return fail_read?-1:0; }
void NPITLUART_readCallBack(void) {}
void NPITLUART_writeCallBack(void) {}
void NPITLUART_readTransport(void);
void NPITLUART_initializeTransport(uint8_t*,uint8_t*,npiCB_t);
void NPIClient_saveNPITaskInfo(uint8_t);
void MT_ProcessIncoming(uint8_t*);
void MT_BuildAndSendZToolResponse(uint8_t,uint8_t,uint8_t,uint8_t*);
void NPITL_initTL(npiRtosCB_t a,npiRtosCB_t b,npiRtosCB_t c) {
    static uint8_t rx[270],tx[270]; assert(a&&b&&c);
    NPITLUART_initializeTransport(rx,tx,NULL);
}
uint8_t synthetic_other_command(uint8_t *p) { (void)p; ++mutations; return 0; }
typedef uint8_t (*mtProcessMsg_t)(uint8_t *);
static mtProcessMsg_t mtProcessIncoming[MT_RPC_SYS_MAX];
'''

MAIN = r'''
static void init_dispatch(void) {
    for(unsigned i=0;i<MT_RPC_SYS_MAX;i++) mtProcessIncoming[i]=synthetic_other_command;
    mtProcessIncoming[0]=NULL; mtProcessIncoming[1]=MT_SysCommandProcessing;
}
static void route(uint8_t cmd0,uint8_t cmd1,const uint8_t *data,uint8_t len) {
    NPIMSG_msg_t *m=OsalPort_malloc(sizeof(*m)); assert(m);
    m->pBuf=OsalPort_msgAllocate((uint32_t)len+3u); assert(m->pBuf);
    m->pBufSize=(uint16_t)len+3u; m->msgType=0;
    m->pBuf[0]=len;m->pBuf[1]=cmd0;m->pBuf[2]=cmd1;
    if(len) memcpy(m->pBuf+3,data,len);
    assert(NPITask_sendBufToStack(m)==0);
}
static void query(void) {
    static const uint8_t q[8]={'B','1','Q','1',1,8,0,0};
    route(0x21,B1_STATUS_COMMAND,q,sizeof(q));
    assert(last_reply[0]==B1_STATUS_REPLY_SIZE && last_reply[1]==0x61 && last_reply[2]==B1_STATUS_COMMAND);
    assert(memcmp(last_reply+3,"B1S1",4)==0 && last_reply[7]==1 && last_reply[8]==B1_STATUS_REPLY_SIZE);
    assert(last_reply[12]==7); /* snapshot+gate+synthetic commit prefix */
    assert(last_reply[15]==0x12 && last_reply[16]==0x34 && last_reply[17]==0x56 && last_reply[18]==0x78);
    for(unsigned i=19;i<27;i++) assert(last_reply[i]==0);
}
int main(int argc,char **argv) {
    assert(argc==2); const char *s=argv[1]; init_dispatch();
    if(strcmp(s,"startup_tx_generation")==0 || strcmp(s,"startup_tx_coalesced")==0 ||
       strcmp(s,"startup_tx_short")==0) {
        /* TX_FINISHED means FIFO drain, not completion of a single write.
         * Case 1: prior write physically drains before the selected startup
         * SRSP is even submitted. Case 2: both queued writes drain together
         * under one TX_FINISHED interrupt. Neither may start BDB early. */
        uint8_t unrelated[]={0xfe,1,0x61,2,0,0x62};
        uint8_t startup[]={0xfe,1,0x65,0x40,0,0x24};
        assert(b1_startup_admit(0x65u,0x40u));
        b1_startup_tx_submit(unrelated,sizeof(unrelated));
        b1_startup_tx_accepted(sizeof(unrelated),1);
        b1_startup_tx_result(sizeof(unrelated),1);
        if(strcmp(s,"startup_tx_generation")==0) {
            b1_startup_tx_eot(); /* unrelated physical drain before SRSP */
            assert(b1_startup_state()==B1_STARTUP_WAIT_SRSP_TX);
        }
        b1_startup_tx_submit(startup,sizeof(startup));
        assert(b1_startup_state()==B1_STARTUP_WAIT_SRSP_TX);
        if(strcmp(s,"startup_tx_short")==0) {
            b1_startup_tx_accepted(sizeof(startup),1);
            b1_startup_tx_result(sizeof(startup)-1,1);
            assert(b1_startup_state()==B1_STARTUP_FAILED);
            assert(b1_management_get_hold_active());
        } else {
            b1_startup_tx_accepted(sizeof(startup),1);
            /* No physical drain event may release BDB before FIFO completion. */
            b1_startup_tx_eot();
            assert(b1_startup_state()==B1_STARTUP_WAIT_SRSP_TX);
            b1_startup_tx_result(sizeof(startup),1);
            b1_startup_tx_eot(); /* FIFO now empty; target fully on wire */
            assert(b1_startup_state()==B1_STARTUP_QUEUED);
            assert(b1_startup_begin());
            assert(!b1_startup_begin());
        }
    } else if(strcmp(s,"start_healthy")==0) {
        b1_management_note_mt_registered();
        NPITask_Fxn(0,0);
        assert(mt_id_reads==1 && process_started==1 && sem_posts==1 && npiTaskID==0);
        assert(b1_management_npi_initialized());
    } else if(strcmp(s,"npi_queue")==0 || strcmp(s,"npi_sem")==0 || strcmp(s,"npi_register")==0 ||
              strcmp(s,"uart_open")==0 || strcmp(s,"uart_read")==0) {
        fail_queue=strcmp(s,"npi_queue")==0; fail_sem=strcmp(s,"npi_sem")==0;
        fail_register=strcmp(s,"npi_register")==0; fail_uart=strcmp(s,"uart_open")==0;
        fail_read=strcmp(s,"uart_read")==0;
        if(fail_register) taskCnt=15u; /* actual provider's full-table boundary */
        b1_management_hold_nv(B1_ERROR_NV_OPEN); NPITask_Fxn(0,0);
        assert(mt_id_reads==0 && process_started==0 && sem_posts==0);
        assert(!b1_management_npi_initialized() && sent==0 && mutations==0);
        if(fail_queue) assert(queue_deleted==1 && uart_opens==0);
        if(fail_sem||fail_register) assert(uart_opens==0);
        if(fail_uart) assert(uart_reads==0);
    } else if(strcmp(s,"npi_first")==0) {
        /* NPI before the donor MT service is registered is an impossible
         * healthy initialization order. Fail closed, do not advertise a
         * functional transport or invent a SYS response. */
        NPITask_Fxn(0,0);
        assert(b1_management_get_hold_active());
        assert(!b1_management_npi_initialized());
        assert(mt_id_reads==0 && process_started==0 && sem_posts==0);
        assert(sent==0 && forwarded==0 && mutations==0);
    } else {
        if(strcmp(s,"healthy")==0 || strcmp(s,"retained_commands")==0 || strcmp(s,"uncommissioned_commands")==0) b1_management_note_mt_registered();
        else if(strcmp(s,"hold_security")==0) b1_security_runtime_hold_latch();
        else b1_management_hold_nv(B1_ERROR_NV_OPEN);
        NPITask_Fxn(0,0); assert(process_started==1 && b1_management_npi_initialized());
        assert(mt_id_reads==((strcmp(s,"healthy")==0 || strcmp(s,"retained_commands")==0 || strcmp(s,"uncommissioned_commands")==0)?1u:0u));
        if(strcmp(s,"healthy")==0) {
            route(0x24,1,NULL,0); assert(forwarded==1 && sent==0);
            uint8_t ping[]={0,0x21,1}; MT_ProcessIncoming(ping);
            assert(sent==1 && last_reply[0]==2 && last_reply[1]==0x61 && last_reply[2]==1);
            assert(last_reply[3]==0xFF && last_reply[4]==0x17);
            uint8_t version[]={0,0x21,2}; MT_ProcessIncoming(version);
            assert(last_reply[0]==sizeof(MTVersionString));
            assert(memcmp(last_reply+3,MTVersionString,sizeof(MTVersionString))==0);
            query(); assert(last_reply[9]==0 && last_reply[10]==0);
        } else if(strcmp(s,"retained_commands")==0 || strcmp(s,"uncommissioned_commands")==0) {
            uint8_t reply[24], error, frame[4]={1,0x2f,5,4};
            b1_management_note_nv4(8,strcmp(s,"uncommissioned_commands")==0?1:2,2421,952,779,0,0x7f);
            b1_management_note_nv_candidate();
            for(unsigned ready=0;ready<2;ready++) {
                if(ready) b1_management_note_zdo_state(1,1);
                frame[0]=1;frame[1]=0x2f;frame[2]=5;frame[3]=4;
                assert(b1_management_mt_filter(frame,reply,&error)==B1_MT_REJECT);
                /* Non-forming commissioning is allowed only after attested
                 * coordinator readiness; B1 must deny it on retained HOLD. */
                assert(b1_management_network_ready()==(int)ready);
                frame[3]=2;assert(b1_management_mt_filter(frame,reply,&error)==
                                  (ready?B1_MT_CONTINUE:B1_MT_REJECT));
                frame[3]=0x10;assert(b1_management_mt_filter(frame,reply,&error)==
                                     (ready?B1_MT_CONTINUE:B1_MT_REJECT));
                frame[0]=0;assert(b1_management_mt_filter(frame,reply,&error)==B1_MT_REJECT && error==4);
                frame[1]=0x26;frame[2]=5;assert(b1_management_mt_filter(frame,reply,&error)==B1_MT_REJECT);
                frame[1]=0x21;frame[2]=3;assert(b1_management_mt_filter(frame,reply,&error)==B1_MT_REJECT);
                frame[1]=0x2b;frame[2]=0;assert(b1_management_mt_filter(frame,reply,&error)==B1_MT_REJECT);
            }
            assert(mutations==0 && !b1_management_get_hold_active());
        } else if(strcmp(s,"nv4_detail")==0) {
            uint8_t detail[8]={'B','1','Q','1',1,8,1,0};
            route(0x21,B1_STATUS_COMMAND,detail,8);
            assert(memcmp(last_reply+3,"B1N1",4)==0 && last_reply[9]==0xff && last_reply[10]==0xff);
            b1_management_note_nv4(8,0,2083,783,778,0,0x2f);
            route(0x21,B1_STATUS_COMMAND,detail,8);
            assert(last_reply[0]==24 && last_reply[9]==8 && last_reply[10]==0);
            assert(last_reply[11]==15 && last_reply[12]==3); /* 783 */
            assert(last_reply[13]==10 && last_reply[14]==3); /* 778 */
            assert(last_reply[15]==35 && last_reply[16]==8); /* 2083 */
            assert(last_reply[23]==1 && last_reply[24]==0x2f && mutations==0 && b1_management_get_hold_active());
            query(); assert(memcmp(last_reply+3,"B1S1",4)==0); /* old query unchanged */
        } else if(strcmp(s,"bad_query")==0) {
            uint8_t bad[8]={'B','1','Q','1',1,8,0,0};
            route(0x21,B1_STATUS_COMMAND,bad,7); assert(last_reply[3]==4);
            for(unsigned i=0;i<8;i++) { uint8_t flip=i==6?2u:1u; bad[i]^=flip; route(0x21,B1_STATUS_COMMAND,bad,8);
                if(i==6) {
                    /* Byte six changes op0 to the new, valid RAM-only op2. */
                    assert(last_reply[0]==B1_STARTUP_REPLY_SIZE && last_reply[1]==0x61);
                    assert(memcmp(last_reply+3,"B1P1",4)==0 && mutations==0);
                } else assert(last_reply[0]==3 && last_reply[1]==0x60 && last_reply[3]==3);
                bad[i]^=flip; }
        } else if(strcmp(s,"bad_fcs")==0) {
            static const uint8_t good[]={0xFE,8,0x21,B1_STATUS_COMMAND,'B','1','Q','1',1,8,0,0,0};
            memcpy(wire_buffer,good,sizeof(good)); wire_size=sizeof(good); wire_cursor=0;
            wire_buffer[12]=npiframe_calcMTFCS(wire_buffer+1,11)^1u;
            NPIFrame_collectFrameData(); assert(sent==0 && live_alloc==0 && mutations==0);
            wire_cursor=0; wire_buffer[12]^=1u; NPIFrame_collectFrameData();
            assert(sent==1 && live_alloc==0 && last_reply[2]==B1_STATUS_COMMAND);
        } else if(strcmp(s,"areq")==0) {
            route(0x41,0,NULL,0);route(0x45,1,NULL,0);route(0x61,1,NULL,0);
            assert(sent==0 && forwarded==0 && mutations==0);
        } else if(strcmp(s,"alloc_fail")==0) {
            uint8_t frame[]={0,0x21,1}; fail_alloc=1; MT_ProcessIncoming(frame); fail_alloc=0;
            assert(sent==0); query(); assert(sent==1);
        } else {
            if(strcmp(s,"hold_security")==0 || strcmp(s,"first_current")==0)
                b1_security_runtime_hold_latch();
            if(strcmp(s,"sticky")==0) { b1_management_note_nv_candidate(); b1_management_note_nv_probe(7); }
            unsigned count=strcmp(s,"storm")==0?1001u:1u;
            for(unsigned i=0;i<count;i++) { route(0x24,1,NULL,0); route(0x45,1,NULL,0); }
            assert(sent==count && forwarded==0 && mutations==0);
            route(0x21,1,NULL,0); assert(last_reply[0]==2 && last_reply[3]==0xFF && last_reply[4]==0x17);
            route(0x21,2,NULL,0); assert(memcmp(last_reply+3,MTVersionString,sizeof(MTVersionString))==0);
            query(); assert(last_reply[10]==(strcmp(s,"hold_security")==0?
                               B1_ERROR_SECURITY_RESTORE:strcmp(s,"npi_first")==0?
                               B1_ERROR_MT_NOT_REGISTERED:B1_ERROR_NV_OPEN));
            assert(last_reply[11]&B1_FLAG_MT_HANDLER_REACHED);
            if(strcmp(s,"first_current")==0 || strcmp(s,"hold_security")==0) {
                assert(last_reply[9]==B1_STAGE_HOLD_SECURITY && last_reply[13]==B1_ERROR_SECURITY_RESTORE);
            }
            assert(b1_nv_runtime_hold_active());
        }
    }
    assert(live_alloc==0 && cs_depth==0);
    assert(peak_alloc<=(strcmp(s,"healthy")==0?5u:3u));
    printf("B1_ACTUAL_NPI_MT_SINGLE_OWNER_HOSTED_SYNTHETIC_PASS %s sent=%u forwarded=%u mutations=%u peak_alloc=%u NOT_MEASURED=physical_uart,RF,RTOS_interleavings\n",s,sent,forwarded,mutations,peak_alloc);
    return 0;
}
'''


def make(sdk):
    def read(path):
        return (sdk / path).read_text(encoding="utf-8")
    mt = read("source/ti/zstack/mt/mt.c")
    sys = read("source/ti/zstack/mt/mt_sys.c")
    npi = read("source/ti/zstack/npi/npi_task.c")
    uart = read("source/ti/zstack/npi/npi_tl_uart.c")
    client = read("source/ti/zstack/npi/npi_client_mt.c")
    headers = read("source/ti/zstack/mt/mt.h")
    osal = read("source/ti/ti154stack/common/osal_port/osal_port_posix/osal_port.c")
    frame = read("source/ti/zstack/npi/npi_frame_mt.c")
    sys_dispatch = extract_function(sys, "uint8_t MT_SysCommandProcessing(uint8_t *pBuf)")
    defines = "\n".join(re.findall(r"^#define\s+MT_SYS_\w+\s+0x[0-9A-Fa-f]+\s*$", headers, re.M))
    stubs = []
    for name, arg in sorted(set(re.findall(r"\b(MT_Sys\w+)\(([^()]*)\);", sys_dispatch))):
        if name in ("MT_SysPing", "MT_SysVersion"):
            continue
        stubs.append("void %s(%s) { %s ++mutations; }" % (
            name, "uint8_t *pBuf" if arg.strip() else "void",
            "(void)pBuf;" if arg.strip() else ""))
    functions = [
        extract_function(client, "void MT_BuildAndSendZToolResponse(uint8_t cmdType, uint8_t cmdId,\n                                  uint8_t dataLen, uint8_t *pData)"),
        extract_function(client, "void NPIClient_saveNPITaskInfo(uint8_t taskID)"),
        extract_function(sys, "static void MT_SysPing(void)"),
        extract_function(sys, "static void MT_SysVersion(void)"), sys_dispatch,
        extract_function(mt, "void MT_ProcessIncoming(uint8_t *pBuf)"),
        extract_function(uart, "static void b1_startup_uart_event(UART2_Handle handle, uint32_t event,\n                                 uint32_t data, void *userArg)"),
        extract_function(uart, "void NPITLUART_readTransport(void)"),
        extract_function(uart, "void NPITLUART_initializeTransport(uint8_t *tRxBuf, uint8_t *tTxBuf, npiCB_t npiCBack)"),
        extract_function(osal, "uint8_t OsalPort_registerTask(void* taskHndl, void* taskSem, uint32_t* pEvent)"),
        extract_function(frame, "void NPIFrame_initialize(npiIncomingFrameCBack_t incomingFrameCB)"),
        extract_function(frame, "uint8_t npiframe_calcMTFCS(uint8_t *msg_ptr, uint8_t len)"),
        extract_function(frame, "void NPIFrame_collectFrameData(void)"),
        extract_function(npi, "void NPITask_inititializeTask(void)"),
        extract_function(npi, "void NPITask_task(void)"),
        extract_function(npi, "Void NPITask_Fxn(UArg a0, UArg a1)"),
        extract_function(npi, "static uint8_t NPITask_sendBufToStack( NPIMSG_msg_t *pMsg )"),
    ]
    if "b1_management_mt_filter" not in functions[5] or "MT_ProcessIncoming(pReq)" not in functions[-1]:
        raise RuntimeError("BLOCKED: real MT/NPI management guard not present")
    return PREAMBLE + defines + "\n" + "\n".join(stubs + functions) + MAIN


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--sdk", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    a.output.write_text(make(a.sdk), encoding="utf-8")
    print("B1_ACTUAL_NPI_MT_SYS_CLIENT_UART_FUNCTIONS_EXTRACTED")


if __name__ == "__main__":
    main()
