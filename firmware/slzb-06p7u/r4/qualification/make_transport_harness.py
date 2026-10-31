"""Extract real transformed TI bodies; simulate only RTOS/UART boundaries.

The output never opens a device. Host success does not attest native ARM code,
actual pins, RF absence on silicon, boot or a host receiving serial bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "b1" / "tools"))
from make_management_harness import PREAMBLE
from patch_zdapp import extract_function
import transport_profile as profile

SCENARIOS = ("requests", "framing", "ownership", "allocation", "queue", "semaphore",
             "uart_open", "uart_read", "startup", "startup_semaphore")

BOOT_BOUNDARY = r'''
#define TRUE 1
#define VIMS_BASE 0u
#define VIMS_MODE_ENABLED 1u
#define VIMS_MODE_DISABLED 0u
#define ti_sysbios_knl_Semaphore_Mode_COUNTING 1
static int npiInitializationMutex;
static unsigned board_calls, npi_task_creates, bios_calls, diagnostic_delays;
static const uint32_t Clock_tickPeriod = 1000u;
void Task_sleep(uint32_t ticks) { assert(ticks == 2000u); ++diagnostic_delays; }
void VIMSConfigure(unsigned a,unsigned b,unsigned c) { (void)a;(void)b;(void)c; }
void VIMSModeSet(unsigned a,unsigned b) { (void)a;(void)b; }
void Board_initGeneral(void) { ++board_calls; }
void NPITask_createTask(void) { ++npi_task_creates; }
void BIOS_start(void) { ++bios_calls; }
'''

TEST_MAIN = r'''
static void route(uint8_t cmd0,uint8_t cmd1,uint8_t length,int declared_size) {
    NPIMSG_msg_t *m=OsalPort_malloc(sizeof(*m)); assert(m);
    m->pBuf=OsalPort_msgAllocate((uint32_t)length+3u); assert(m->pBuf);
    m->pBufSize=(uint16_t)declared_size; m->msgType=0;
    m->pBuf[0]=length; m->pBuf[1]=cmd0; m->pBuf[2]=cmd1;
    if(length) memset(m->pBuf+3,0,length);
    assert(NPITask_sendBufToStack(m)==0);
}
static void start_transport(void) {
    NPITask_Fxn(0,0);
    assert(mt_id_reads==0 && process_started==1 && sem_posts==1);
    assert(npiTaskID==0 && uart_opens==1 && uart_reads==1);
    assert(r4q_npi_initialized());
    assert(diagnostic_delays==1 && sent==1);
    assert(last_reply[0]==1u && last_reply[1]==0x41u &&
           last_reply[2]==0xF7u && last_reply[3]==0xA7u);
    sent=0; /* Beacon is independent from requested SYS_PING/VERSION. */
}
int main(int argc,char **argv) {
    assert(argc==2); const char *scenario=argv[1];
    if(!strcmp(scenario,"startup") || !strcmp(scenario,"startup_semaphore")) {
        fail_sem=!strcmp(scenario,"startup_semaphore");
        int result=r4q_actual_main();
        assert(board_calls==1 && uart_opens==0);
        assert(npi_task_creates==(fail_sem?0u:1u));
        assert(bios_calls==(fail_sem?0u:1u));
        assert(result==(fail_sem?1:0));
        assert(r4q_transport_unavailable()==fail_sem);
    } else if(!strcmp(scenario,"queue") || !strcmp(scenario,"semaphore") ||
              !strcmp(scenario,"uart_open") || !strcmp(scenario,"uart_read")) {
        fail_queue=!strcmp(scenario,"queue"); fail_sem=!strcmp(scenario,"semaphore");
        fail_uart=!strcmp(scenario,"uart_open"); fail_read=!strcmp(scenario,"uart_read");
        NPITask_Fxn(0,0);
        assert(r4q_transport_unavailable() && !r4q_npi_initialized());
        assert(process_started==0 && sem_posts==0 && mt_id_reads==0 && sent==0);
        assert(diagnostic_delays==0);
        if(fail_queue) assert(queue_deleted==1 && uart_opens==0);
        if(fail_uart) assert(uart_reads==0);
    } else {
        start_transport();
        if(!strcmp(scenario,"requests")) {
            assert(!r4q_accept_frame(NULL)); MT_ProcessIncoming(NULL);
            /* Every type/subsystem/command pair: exactly PING and VERSION pass. */
            for(unsigned cmd0=0;cmd0<256;cmd0++)
                for(unsigned cmd1=0;cmd1<256;cmd1++) {
                    uint8_t frame[]={0,(uint8_t)cmd0,(uint8_t)cmd1};
                    MT_ProcessIncoming(frame);
                }
            assert(sent==2);
            for(unsigned len=1;len<256;len++) {
                uint8_t a[]={(uint8_t)len,0x21,1},b[]={(uint8_t)len,0x21,2};
                MT_ProcessIncoming(a);MT_ProcessIncoming(b);
            }
            assert(sent==2 && mutations==0 && forwarded==0);
            route(0x21,1,0,3); assert(last_reply[0]==2 && last_reply[1]==0x61 && last_reply[2]==1);
            assert(last_reply[3]==0xFF && last_reply[4]==0x17);
            route(0x21,2,0,3); assert(last_reply[0]==sizeof(MTVersionString));
            assert(!memcmp(last_reply+3,MTVersionString,sizeof(MTVersionString)));
        } else if(!strcmp(scenario,"framing")) {
            uint8_t ping[]={0xFE,0,0x21,1,0x21^1};
            memcpy(wire_buffer,ping,sizeof(ping));wire_size=sizeof(ping);wire_cursor=0;
            wire_buffer[4]^=1;NPIFrame_collectFrameData();assert(sent==0 && live_alloc==0);
            wire_cursor=0;wire_buffer[4]^=1;NPIFrame_collectFrameData();assert(sent==1 && live_alloc==0);
            /* Split across reads is handled by the genuine donor parser. */
            wire_cursor=0;wire_size=2;NPIFrame_collectFrameData();assert(sent==1);
            wire_size=sizeof(ping);NPIFrame_collectFrameData();assert(sent==2 && live_alloc==0);
        } else if(!strcmp(scenario,"ownership")) {
            assert(NPITask_sendBufToStack(NULL)==1);
            for(unsigned length=0;length<16;length++)
                for(unsigned declared=0;declared<20;declared++)
                    route(0x21,1,(uint8_t)length,(int)declared);
            assert(sent==1 && live_alloc==0 && forwarded==0);
            r4q_transport_failed(R4Q_ERROR_UART_READ);
            route(0x21,1,0,3);assert(sent==1 && live_alloc==0 && !r4q_npi_initialized());
            r4q_note_uart_opened();r4q_note_npi_initialized();assert(!r4q_npi_initialized());
        } else if(!strcmp(scenario,"allocation")) {
            uint8_t ping[]={0,0x21,1};fail_alloc=1;MT_ProcessIncoming(ping);fail_alloc=0;
            assert(sent==0 && live_alloc==0);MT_ProcessIncoming(ping);assert(sent==1 && live_alloc==0);
        } else assert(!"unknown scenario");
    }
    assert(mutations==0 && forwarded==0 && live_alloc==0 && cs_depth==0);
    printf("R4_TRANSPORT_REAL_TI_BODIES_HOSTED_SYNTHETIC_PASS %s NOT_MEASURED=native_ARM,physical_UART,board,RF,network\n",scenario);
    return 0;
}
'''


def make(sdk: Path, source_receipt: Path) -> str:
    report = json.loads(source_receipt.read_text(encoding="utf-8"))
    source_sha = report.get("source_sha", "")
    profile.identity(source_sha)
    if report.get("profile") != profile.PROFILE or report.get("donor_git_blobs") != profile.PINS:
        raise ValueError("TRANSPORT_HARNESS_SOURCE_RECEIPT_MISMATCH")
    for relative, expected in report["changed_sources_sha256"].items():
        if hashlib.sha256((sdk / relative).read_bytes()).hexdigest() != expected:
            raise ValueError("TRANSPORT_HARNESS_SOURCE_DRIFT " + relative)
    def read(relative):
        return (sdk / relative).read_text(encoding="utf-8")
    for relative, expected in profile.PINS.items():
        if relative not in report["changed_sources_sha256"] and profile.patch_management.blob(read(relative)) != expected:
            raise ValueError("TRANSPORT_HARNESS_PREREQUISITE_DRIFT " + relative)
    mt, sys_source, npi, uart = (read(p) for p in (profile.MT, profile.SYS, profile.NPI, profile.UART))
    client = read("source/ti/zstack/npi/npi_client_mt.c")
    osal = read("source/ti/ti154stack/common/osal_port/osal_port_posix/osal_port.c")
    frame = read("source/ti/zstack/npi/npi_frame_mt.c")
    defines = "\n".join(re.findall(r"^#define\s+MT_SYS_\w+\s+0x[0-9A-Fa-f]+\s*$",
                                   read("source/ti/zstack/mt/mt.h"), re.M))
    preamble = PREAMBLE.replace('#include "b1_management.h"', '#include "r4_transport_only_support.h"')
    preamble = preamble.replace('#include "b1_admission.h"', '')
    preamble = preamble.replace("b1_management_test_disable", "r4q_test_disable")
    preamble = preamble.replace("b1_management_test_restore", "r4q_test_restore")
    # This isolated SYS_PING/VERSION profile deliberately strips the B1
    # retained-startup UART EOT observer. No event callback is registered.
    event_assertions = (
        "assert(p->eventMask & UART2_EVENT_TX_FINISHED);\n"
        "    assert(p->eventCallback != NULL);"
    )
    if preamble.count(event_assertions) != 1:
        raise RuntimeError("TRANSPORT_HARNESS_UART_CALLBACK_ASSERTION_DRIFT")
    preamble = preamble.replace(
        event_assertions,
        "assert(p->eventMask == 0u);\n"
        "    assert(p->eventCallback == NULL);",
        1,
    )
    # The real dispatcher replaces the synthetic subsystem table entirely.
    preamble += "\nuint8_t MT_SysCommandProcessing(uint8_t*);\n"
    functions = [
        extract_function(client, "void MT_BuildAndSendZToolResponse(uint8_t cmdType, uint8_t cmdId,\n                                  uint8_t dataLen, uint8_t *pData)"),
        extract_function(client, "void NPIClient_saveNPITaskInfo(uint8_t taskID)"),
        extract_function(sys_source, "static __attribute__((noinline)) void MT_SysPing(void)"),
        extract_function(sys_source, "static __attribute__((noinline)) void MT_SysVersion(void)"),
        extract_function(sys_source, "uint8_t MT_SysCommandProcessing(uint8_t *pBuf)"),
        extract_function(mt, "__attribute__((noinline)) uint8_t r4q_accept_frame(const uint8_t *frame)"),
        extract_function(mt, "void MT_ProcessIncoming(uint8_t *pBuf)"),
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
        extract_function(read(profile.MAIN), "__attribute__((noinline)) int r4q_transport_start(void)"),
        extract_function(read(profile.MAIN), "int main()").replace("int main()", "int r4q_actual_main(void)", 1),
    ]
    return preamble + defines + "\n" + BOOT_BOUNDARY + "\n" + \
        (HERE / "r4_transport_only_support.c").read_text(encoding="utf-8") + "\n" + \
        "\n\n".join(functions) + "\n" + TEST_MAIN


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdk", required=True, type=Path)
    parser.add_argument("--profile-receipt", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.write_text(make(args.sdk, args.profile_receipt), encoding="utf-8")
    print("R4_TRANSPORT_REAL_TI_BODIES_EXTRACTED_HOST_BOUNDARIES_SYNTHETIC")


if __name__ == "__main__":
    main()
