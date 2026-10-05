/* T832-DIAG-R0 host harness: ti/sysbios/runtime/Memory.h stub.
 *
 * Mirrors the small surface of the real SysBIOS header used by the recorder
 * (pinned SDK 8.32.00.07 kernel/tirtos7/packages/ti/sysbios/runtime/Memory.h):
 * IHeap_Handle (pointer to struct IHeap_Object), Memory_Stats (three
 * size_t fields), Memory_getStats over the default heap instance. Backed by
 * controllable host variables in t832_diag_host_test.c.
 */
#ifndef T832_STUB_SYSBIOS_MEMORY_H
#define T832_STUB_SYSBIOS_MEMORY_H

#include <stddef.h>

typedef struct IHeap_Object {
  int unused;
} IHeap_Object, *IHeap_Handle;

typedef struct {
  size_t totalSize;
  size_t totalFreeSize;
  size_t largestFreeSize;
} Memory_Stats;

void HostHeap_getStats(Memory_Stats *stats);

static inline void Memory_getStats(IHeap_Handle heap, Memory_Stats *stats)
{
  (void)heap;
  HostHeap_getStats(stats);
}

extern IHeap_Handle Memory_defaultHeapInstance;

#endif
