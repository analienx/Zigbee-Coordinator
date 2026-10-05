/* Compile against R4 and R5 unchanged. No R5-only function/state access.
 * Named failure on the real reviewed R4 proves blocked-history loss. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "t832_host_sdk.h"
#include "ti/sysbios/runtime/Memory.h"
#define CODE_REVISION_NUMBER 8320001u
#define T832_BUILD_ID 0xA5A50001u
static uint32_t tick;
static int depth;
static uint16_t blocked_max;
uint32_t ClockP_getSystemTicks(void) { return tick; }
uint32_t ClockP_getSystemTickPeriod(void) { return 1000u; }
uint32_t HostCs_enter(void) { return ++depth; }
void HostCs_leave(uint32_t key) { (void)key; depth--; }
void HostHeap_getStats(Memory_Stats *s) { memset(s, 0, sizeof(*s)); }
#include "t832_diag_impl.inc"
IHeap_Handle Memory_defaultHeapInstance;
static uint8_t nibble(uint8_t c) { return c <= '9' ? c - '0' : c - 'A' + 10; }
void MT_BuildAndSendZToolResponse(uint8_t type, uint8_t id, uint8_t len, uint8_t *data)
{
    uint8_t raw[113], i, count;
    (void)type; (void)id;
    for (i = 0u; i < (len - 8u) / 2u; i++) raw[i] = nibble(data[8u + 2u * i]) * 16u + nibble(data[9u + 2u * i]);
    count = raw[32];
    for (i = 0u; i < count; i++) {
        uint8_t *r = &raw[33u + 20u * i];
        if (r[10] == 39u && r[12] == 1u) blocked_max = r[16] | ((uint16_t)r[17] << 8);
    }
}
int main(void)
{
    uint8_t status = 0u;
    T832Diag_init(9u);
    T832Diag_commandRx(0x21u, 2u);
    T832Diag_commandDispatch(0x21u, 2u);
    tick = 5000u; T832Diag_exportPoll();
    tick = 20000u; T832Diag_exportPoll();
    T832Diag_responseQueued(0x61u, 2u, 1u, &status);
    T832Diag_npiTxDequeue(0xFEu, 0x61u, 2u, 1u);
    T832Diag_uartTxStart(6u);
    T832Diag_uartTxFinished(6u);
    for (tick = 25000u; tick < 330000u; tick += 5000u) T832Diag_exportPoll();
    if (blocked_max < 15000u) { puts("R5-BLOCKED-HISTORY-LOST"); return 23; }
    puts("R5-BLOCKED-HISTORY-PRESERVED");
    return 0;
}
