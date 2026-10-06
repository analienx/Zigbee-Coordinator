/* Hosted test on the actual R6-patched recorder, not a mirror. */
#include "nv_r6_probe.h"
volatile T832R6NvSnapshot t832R6Nv;
#define T832Diag_uartTxFinished T832Diag_uartWriteComplete
#define main original_recorder_main
#include "t832_diag_host_test.c"
#undef main
int main(void)
{
    fresh(9u);
    CHECK((t832Diag.capabilities&(1u<<28))!=0);
    CHECK((t832Diag.capabilities&T832_DIAG_CAP_TX_FINISHED)==0);
    uint32_t before=t832Diag.record_sequence;
    t832R6Nv.sequence=1;T832R6Nv_poll(1000);
    CHECK(t832Diag.record_sequence==before);
    t832R6Nv.pages=NVOCMP_NVPAGES;t832R6Nv.tail=NVOCMP_NVPAGES-1;
    t832R6Nv.ready=1;t832R6Nv.requests=400;t832R6Nv.first_failure=5;t832R6Nv.first_failure_requested=1;
    for(unsigned i=0;i<NVOCMP_NVPAGES;i++){t832R6Nv.states[i]=0x7E;t832R6Nv.offsets[i]=16;}
    t832R6Nv.sequence=2;t832Diag.sync_outstanding=1;
    advance_ms(1000);T832Diag_exportPoll();
    CHECK(t832R6NvLastSequence==2);
    CHECK(t832Diag.record_sequence>before);
    CHECK(host_frame_count==0); /* Snapshot survives suppressed UART output. */
    CHECK(t832Diag.first_fault_valid!=0);
    CHECK(t832Diag.first_fault.kind==T832_DIAG_EV_NV_FAULT);
    CHECK(t832Diag.first_fault.a==8 && t832Diag.first_fault.b==5 && t832Diag.first_fault.c==1);
    fresh(9u);
    T832Diag_commandRx(0x21u,2u);T832Diag_commandDispatch(0x21u,2u);
    T832Diag_responseQueued(0x61u,2u,0u,NULL);
    T832Diag_npiQueueAccepted(0x61u,2u,0u);T832Diag_commandEnd();
    T832Diag_npiTxDequeue(0xFEu,0x61u,2u,0u);
    T832Diag_uartTxStart(5u);T832Diag_uartEvent(2u,5u,0);
    T832Diag_uartWriteComplete(5u);
    CHECK(t832Diag.inflight_valid==0);
    CHECK(t832Diag.sync_outstanding==0);
    CHECK(t832R5.stage==8);
    T832Diag_uartEvent(4u,0,0);
    CHECK(t832R5.stage==8);
    CHECK((t832R5.stage_seen&(1u<<9))==0);
    CHECK(t832R5.uart_count[3]==1);
    puts("R6 HOST PASS: bounded POD sampling during stalls and truthful driver/wire separation");
    return failures?1:0;
}
