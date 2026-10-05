/* Hosted-only regressions on the real recorder and fatal latch. */
#define main t832_original_main
#include "t832_diag_host_test.c"
#undef main

int main(void)
{
    unsigned int stack[16];
    uint32_t i;
    fresh(9u);
    T832Diag_commandRx(0x21u, 2u);
    T832Diag_commandDispatch(0x21u, 2u);
    advance_ms(10u);
    T832Diag_responseQueued(0x61u, 2u, 0u, NULL);
    T832Diag_npiQueueAccepted(0x61u, 2u, 0u);
    T832Diag_commandComplete(0x21u, 2u, 0u);
    T832Diag_commandEnd();
    CHECK(t832R5.stage == 5u);
    advance_ms(60000u);
    T832Diag_exportPoll();
    CHECK(host_frame_count == 0u);
    CHECK(t832R5.sampled_ms == 60010u);
    CHECK(t832R5.current[0] == 9u);
    CHECK(t832R5.current[2] == 1u);
    CHECK(t832R5.current[11] == 60000u);
    CHECK(t832R5.maximum[3] == 60000u);
    T832Diag_npiTxDequeue(0xFEu, 0x61u, 2u, 0u);
    T832Diag_uartTxStart(5u);
    T832Diag_uartEvent(3u, 5u, 0);
    T832Diag_uartEvent(1u, 5u, 0);
    advance_ms(15000u);
    T832Diag_exportPoll();
    CHECK(t832R5.accepted_age_max == 15000u);
    T832Diag_uartEvent(2u, 5u, 0);
    T832Diag_uartTxFinished(5u);
    CHECK(t832R5.stage == 10u);
    CHECK(t832R5.stage_seen == 0x3FFu);
    /* Repeated command, late old completion cannot advance the new one. */
    T832Diag_commandRx(0x21u, 2u);
    T832Diag_commandDispatch(0x21u, 2u);
    T832Diag_responseQueued(0x61u, 2u, 0u, NULL);
    T832Diag_commandEnd();
    T832Diag_commandRx(0x21u, 2u);
    CHECK(t832R5.stage == 1u);
    wire_dequeue_finish(0xFEu, 0x61u, 2u, 0u);
    CHECK(t832R5.stage == 1u);
    CHECK(t832Diag.sync_outstanding == 1u);
    /* Unknown asynchronous SRSP outside the executing MT scope is gen 0. */
    T832Diag_commandEnd();
    T832Diag_responseQueued(0x61u, 2u, 0u, NULL);
    wire_dequeue_finish(0xFEu, 0x61u, 2u, 0u);
    CHECK(t832R5.stage == 1u);
    CHECK(t832Diag.sync_outstanding == 1u);
    T832Diag_fatalError(0x12345678u, 4u, 5u);
    CHECK(t832DiagFatal.magic == T832_FATAL_MAGIC);
    CHECK(t832DiagFatal.error_id == 0x12345678u);
    CHECK(t832DiagFatal.a0 == 4u && t832DiagFatal.a1 == 5u);
    T832Diag_fatalError(99u, 99u, 99u);
    CHECK(t832DiagFatal.error_id == 0x12345678u);
    memset((void *)&t832DiagFatal, 0, sizeof(t832DiagFatal));
    for (i = 0u; i < 16u; i++) stack[i] = 0xA000u + i;
    T832Diag_fatalException(stack, 0xFFFFFFFDu, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 9u, 10u, 11u);
    CHECK(t832DiagFatal.registers[0] == stack[8]);
    CHECK(t832DiagFatal.registers[4] == stack[0]);
    CHECK(t832DiagFatal.registers[15] == stack[14]);
    CHECK(t832DiagFatal.status[8] == 11u);
    CHECK(t832DiagFatal.exc_return == 0xFFFFFFFDu);
    CHECK(host_cs_depth == 0);
    puts("R5 real recorder/fatal/stale generation/blocked sampling PASS");
    return 0;
}
