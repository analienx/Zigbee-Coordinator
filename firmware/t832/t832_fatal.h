#ifndef T832_FATAL_H
#define T832_FATAL_H
#include <stdint.h>
/* RAM-only first-fatal latch. SWD symbol: t832DiagFatal. No retention claim.
 * Commit marker is stored last; nested exceptions refuse an in-progress latch.
 * Timestamp/progress are cached at the last MT sample, not read in a fault. */
#define T832_FATAL_MAGIC 0xF8320005u
typedef struct {
    uint32_t magic, writing, kind, build_id, sampled_ms;
    uint32_t error_id, a0, a1, thread_type, thread_handle;
    uint32_t registers[17]; /* r0-r12, interrupted SP, LR, PC, PSR */
    uint32_t exc_return, status[9]; /* ICSR, MMFSR, BFSR, UFSR, HFSR, DFSR, MMAR, BFAR, AFSR */
    uint32_t command, generation, stage, mt_age, npi_age, zstack_age;
} T832FatalLatch;
extern volatile T832FatalLatch t832DiagFatal;
void T832Diag_fatalError(uintptr_t id, uintptr_t a0, uintptr_t a1);
void T832Diag_fatalException(const unsigned int *stack, unsigned int lr,
    uint32_t thread_type, uint32_t icsr, uint32_t mmfsr, uint32_t bfsr,
    uint32_t ufsr, uint32_t hfsr, uint32_t dfsr, uint32_t mmar,
    uint32_t bfar, uint32_t afsr);
#endif
