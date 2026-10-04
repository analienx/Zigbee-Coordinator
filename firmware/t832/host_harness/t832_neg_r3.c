/* T832-DIAG-R3 negative control probe (B01/B02 only).
 *
 * Compiled ONLY by the negative-control CI job against the pre-fix
 * t832_diag_impl.inc overlaid from reviewed SHA 8dd181b (see workflow).
 * It asserts the POST-FIX semantics, so it must FAIL on the pre-fix tree
 * (the job inverts the exit status): B01 header-match release removes the
 * wrong frame, and B02 sequence-only retirement discards a coalesced
 * occurrence. Uses the OLD popPeeked(sel, seq) signature deliberately —
 * this file pins the pre-fix API and is never built against fixed code.
 *
 * B03 has no probe here: the split-transaction race needs true
 * concurrency; single-section atomicity is by construction plus reviewer
 * section analysis (see ledger).
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "t832_host_sdk.h"
#include "ti/sysbios/runtime/Memory.h"

#define CODE_REVISION_NUMBER 8320001u
#define T832_BUILD_ID 0xA5A50001u

static uint32_t host_tick;
static int host_cs_depth;

uint32_t ClockP_getSystemTicks(void) { return host_tick; }
uint32_t ClockP_getSystemTickPeriod(void) { return 1000u; }

uint32_t HostCs_enter(void) { return (uint32_t)(++host_cs_depth); }
void HostCs_leave(uint32_t key) { (void)key; host_cs_depth--; }

void HostHeap_getStats(Memory_Stats *stats)
{
  stats->totalSize = 6144u;
  stats->totalFreeSize = 4096u;
  stats->largestFreeSize = 2048u;
}

#include "t832_diag_impl.inc"

IHeap_Handle Memory_defaultHeapInstance = 0;

void MT_BuildAndSendZToolResponse(uint8_t cmdType, uint8_t cmdId,
                                  uint8_t dataLen, uint8_t *dataPtr)
{
  (void)cmdType; (void)cmdId; (void)dataLen; (void)dataPtr;
}

static int failures;

#define CHECK(cond) do { \
    if (!(cond)) { \
      printf("NEG-FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
      failures++; \
    } \
  } while (0)

/* B01 pre-fix shape: A queued, B refused with the identical header. The
 * pre-fix txRelease removes A's descriptor (count 0); post-fix semantics
 * require it to survive (count 1). */
static void neg_b01_unowned_refusal(void)
{
  uint8_t payload[2] = {1, 2};
  host_tick = 0u;
  host_cs_depth = 0;
  T832Diag_init(9u);
  T832Diag_responseQueued(0x41u, 0x50u, 2u, payload);
  CHECK(t832Diag.normal_pending == 1u);
  CHECK(t832Diag.txq_count == 1u);
  T832Diag_npiTxRefused(2u, 0x41u, 0x50u, 2u);
  CHECK(t832Diag.txq_count == 1u);
  CHECK(t832Diag.normal_pending == 0u);
  CHECK(t832Diag.tx_uncertain_n == 1u);
}

/* B02 pre-fix shape: stage a critical record, coalesce an identical fault
 * between staging and retirement. The pre-fix sequence-only pop retires
 * both occurrences (count 0); post-fix semantics require the coalesced
 * entry to survive (count 1) with an explicit loss report. */
static void neg_b02_staged_coalesce(void)
{
  T832DiagRecord staged_copy;
  uint8_t sel;
  host_tick = 0u;
  host_cs_depth = 0;
  T832Diag_init(9u);
  T832Diag_npiTrap(300u, 100u);
  CHECK(t832Diag.critical_count == 1u);
  sel = T832Diag_peekAt(0u, 0u, &staged_copy);
  CHECK(sel == 1u);
  T832Diag_npiTrap(300u, 100u);
  T832Diag_popPeeked(sel, staged_copy.sequence);
  CHECK(t832Diag.critical_count == 1u);
}

int main(void)
{
  neg_b01_unowned_refusal();
  neg_b02_staged_coalesce();
  if (failures) {
    printf("NEG-RESULT: %d defect(s) reproduced on pre-fix tree\n", failures);
    return 1;
  }
  printf("NEG-RESULT: unexpectedly clean on pre-fix tree\n");
  return 0;
}
