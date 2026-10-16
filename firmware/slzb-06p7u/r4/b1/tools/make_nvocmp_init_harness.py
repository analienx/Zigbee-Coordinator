"""Generate a host-compiled test of the EXACT patched NVOCMP_initNvApi body.

Synthetic NVS / mutex / RTOS boundaries only. Not a test of TI's full page
scanner, security restoration, MAC ROM or real flash. Extraction fails closed
on multiple/missing signatures, missing B1 admission or pre-division guard.
"""
from pathlib import Path
import argparse

ANCHOR = "static uint8_t NVOCMP_initNvApi(void *param)"

PREAMBLE = r"""
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "b1_admission.h"
#include "b1_management.h"

#define NVINTF_NOTREADY 1u
#define NVINTF_SUCCESS 0u
#define NVINTF_FAILURE 2u
#define NVOCMP_NVS_INDEX 0u
#define NVOCMP_NVPAGES 2u
#define FLASH_PAGE_SIZE 8192u
#define NVOCMP_NULLPAGE 0xFFu
#define NVOCMP_NVSIZE NVOCMP_size
#define NVOCMP_ALERT(c,m) do {} while(0);
#define NVOCMP_EXCEPTION(pg,err) do {} while(0);
#define NVOCMP_ASSERT(c,m) do {} while(0);

typedef void *NVS_Handle;
typedef void *GateMutexPri_Handle;
typedef struct { uint32_t dummy; } GateMutexPri_Params;
typedef struct {
    void *regionBase;
    size_t regionSize;
    size_t sectorSize;
} NVS_Attrs;
typedef struct {
    uint8_t compactInfo[16];
    uint8_t nvSize;
    uint8_t actPage;
    uint8_t forceCompact;
    uint16_t actOffset;
} NVOCMP_nvHandle_t;
typedef struct { uint8_t dummy; } NVOCMP_compactInfo_t;
static uint8_t NVOCMP_failF = NVINTF_NOTREADY;
static uint8_t NVOCMP_failW;
static uint8_t b1_nv_initializing;
static uint8_t NVOCMP_size;
static NVOCMP_nvHandle_t NVOCMP_nvHandle;
static NVS_Attrs NVOCMP_nvsAttrs;
static NVS_Handle NVOCMP_nvsHandle;
#ifdef NVOCMP_POSIX_SEM
typedef int sem_t;
static sem_t NVOCMP_gPosixSem;
#elif defined(NVOCMP_POSIX_MUTEX)
typedef struct {int type;} pthread_mutexattr_t;
typedef int pthread_mutex_t;
static pthread_mutex_t NVOCMP_gPosixMutex;
#define PTHREAD_MUTEX_RECURSIVE 1
#else
static GateMutexPri_Handle NVOCMP_gMutexPri;
#endif
static uint8_t synthetic_nv[B1_NV2_REGION_SIZE];
static NVS_Attrs stub_attrs;
static bool stub_open_null, stub_mutex_null;
static uint32_t stub_read_fail_off;
static uint32_t read_calls, getattrs_calls, init_calls, write_calls, erase_calls;
static uint32_t open_calls, gate_calls, nvs_init_calls;
static uint8_t mgmt_reason, mgmt_probe;
static uint32_t mgmt_candidate;
void b1_management_hold_nv(uint8_t reason)
{ if (mgmt_reason == 0u) mgmt_reason = reason; }
void b1_management_note_nv_probe(uint8_t code) { mgmt_probe = code; }
void b1_management_note_nv_candidate(void) { ++mgmt_candidate; }

#ifdef NVOCMP_POSIX_SEM
static int sem_init(sem_t *s,int shared,unsigned value)
{(void)s;(void)shared;(void)value;++gate_calls;return stub_mutex_null?-1:0;}
#elif defined(NVOCMP_POSIX_MUTEX)
static int pthread_mutexattr_init(pthread_mutexattr_t *a)
{a->type=0;return 0;}
static int pthread_mutex_init(pthread_mutex_t *m,pthread_mutexattr_t *a)
{(void)m;(void)a;++gate_calls;return stub_mutex_null?-1:0;}
#else
static void GateMutexPri_Params_init(GateMutexPri_Params *p)
{
    p->dummy = 0;
}
static GateMutexPri_Handle GateMutexPri_create(GateMutexPri_Params *p, void *unused)
{
    (void)p; (void)unused;
    ++gate_calls;
    return stub_mutex_null ? NULL : (void *)(uintptr_t)1;
}
#endif
static void NVS_init(void)
{
    ++nvs_init_calls;
}
static NVS_Handle NVS_open(unsigned index, void *p)
{
    (void)p;
    assert(index == 0);
    ++open_calls;
    return stub_open_null ? NULL : (void *)(uintptr_t)1;
}
static void NVS_getAttrs(NVS_Handle handle, NVS_Attrs *a)
{
    ++getattrs_calls;
    assert(handle != NULL);
    *a = stub_attrs;
}
static int_fast16_t NVS_read(NVS_Handle handle, uint32_t offset,
                             void *dst, size_t size)
{
    ++read_calls;
    assert(handle != NULL);
    assert(offset + size <= sizeof(synthetic_nv));
    assert(offset + size >= offset);
    if (offset == stub_read_fail_off) return -9;
    memcpy(dst, synthetic_nv + offset, size);
    return 0;
}
static int_fast16_t b1_nv_nvs_read(void *opaque, uint32_t offset,
                                   uint8_t *data, uint32_t length)
{
    return NVS_read((NVS_Handle)opaque, offset, data, length);
}
static void NVOCMP_initNv(NVOCMP_nvHandle_t *handle)
{
    (void)handle;
    ++init_calls;
}
"""

MAIN = r"""
static void reset_state(void)
{
    memset(synthetic_nv, 0xFF, sizeof(synthetic_nv));
    NVOCMP_failF = NVINTF_NOTREADY;
    NVOCMP_failW = 0;
    NVOCMP_size = 0;
    memset(&NVOCMP_nvHandle, 0, sizeof(NVOCMP_nvHandle));
    stub_attrs.regionBase = (void *)(uintptr_t)0xAA000u;
    stub_attrs.sectorSize = B1_NV2_PAGE_SIZE;
    stub_attrs.regionSize = B1_NV2_REGION_SIZE;
    stub_open_null = stub_mutex_null = false;
    stub_read_fail_off = UINT32_MAX;
    read_calls = getattrs_calls = init_calls = write_calls = erase_calls = 0;
    open_calls = gate_calls = nvs_init_calls = 0;
    mgmt_reason = mgmt_probe = 0u; mgmt_candidate = 0u;
}
static void populate(void)
{
    const uint32_t p = B1_NV2_PAGE_SIZE;
    synthetic_nv[0] = 0x7C;
    synthetic_nv[1] = 1;
    synthetic_nv[2] = 0x0F;
    synthetic_nv[3] = 0x96;
    synthetic_nv[7] = synthetic_nv[11] = synthetic_nv[15] = 0x96;
    synthetic_nv[p] = 0xFE;
    synthetic_nv[p+1] = 2;
    synthetic_nv[p+2] = 0x0F;
    synthetic_nv[p+3] = 0x96;
    synthetic_nv[p+7] = synthetic_nv[p+11] = synthetic_nv[p+15] = 0x96;
}
static void no_mutation(void)
{
    assert(!write_calls && !erase_calls);
    assert(read_calls <= B1_NV2_MAX_READS);
}
int main(void)
{
    uint8_t code;

    /* N02 candidate-control: invokes actual donor entry after preflight. */
    reset_state(); populate();
    code = NVOCMP_initNvApi(NULL);
    assert(code == NVINTF_SUCCESS && init_calls == 1 && read_calls == 512);
    no_mutation();

    /* N01 unauthorized blank: fails BEFORE any donor initialization. */
    reset_state();
    assert(NVOCMP_initNvApi(NULL) == NVINTF_FAILURE && init_calls == 0);
    no_mutation();

    /* N03 index/base/sector/region. Zero-size is the important original
     * division-by-zero mutant (must return failure before any division). */
    reset_state(); populate(); stub_attrs.sectorSize = 0;
    assert(NVOCMP_initNvApi(NULL) == NVINTF_FAILURE);
    assert(read_calls == 0 && init_calls == 0);
    no_mutation();

    reset_state(); populate(); stub_attrs.regionBase = (void *)(uintptr_t)0xAE000u;
    assert(NVOCMP_initNvApi(NULL) == NVINTF_FAILURE);
    assert(read_calls == 0 && init_calls == 0);
    no_mutation();

    reset_state(); populate(); stub_attrs.regionSize = 0x6000;
    assert(NVOCMP_initNvApi(NULL) == NVINTF_FAILURE);
    assert(read_calls == 0 && init_calls == 0);
    no_mutation();

    reset_state(); populate(); stub_attrs.sectorSize = 0x1000;
    assert(NVOCMP_initNvApi(NULL) == NVINTF_FAILURE);
    assert(read_calls == 0 && init_calls == 0);
    no_mutation();

    /* N04: must never invoke getAttrs(NULL). */
    reset_state(); populate(); stub_open_null = true;
    assert(NVOCMP_initNvApi(NULL) == NVINTF_FAILURE);
    assert(getattrs_calls == 0 && read_calls == 0 && init_calls == 0);
    no_mutation();

    /* N08: mutex allocation failure prevents any NVS operation. */
    reset_state(); populate(); stub_mutex_null = true;
    assert(NVOCMP_initNvApi(NULL) == NVINTF_FAILURE);
    assert(nvs_init_calls == 0 && open_calls == 0 && init_calls == 0);
    no_mutation();

    /* N05: backend error cannot masquerade as blank bytes. */
    reset_state(); populate(); stub_read_fail_off = 64;
    assert(NVOCMP_initNvApi(NULL) == NVINTF_FAILURE);
    assert(init_calls == 0);
    no_mutation();

    /* N18/26: a sticky NV boot failure never becomes READY on retry
     * solely because later synthetic flash becomes readable. */
    reset_state(); stub_read_fail_off = 64; populate();
    assert(NVOCMP_initNvApi(NULL) == NVINTF_FAILURE);
    stub_read_fail_off = UINT32_MAX;
    assert(NVOCMP_initNvApi(NULL) == NVINTF_FAILURE);
    assert(init_calls == 0);
    no_mutation();

    puts("B1_ACTUAL_NVOCMP_INIT_FUNCTION_FAULT_MATRIX_SYNTHETIC_PASS");
    return 0;
}
"""


def extract(text: str) -> str:
    marker = ANCHOR + "\n{"
    if text.count(marker) != 1:
        raise RuntimeError("NVOCMP_INIT_COMPILED_BODY_NOT_UNIQUE")
    start = text.index(marker)
    opening = start + len(ANCHOR) + 1
    depth = 0
    for i in range(opening, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                body = text[start:i + 1]
                for invariant in ("b1_nv_probe(", "B1_NV2_PAGE_SIZE",
                                  "NVOCMP_nvsAttrs.regionBase",
                                  "if (NVOCMP_nvsHandle == NULL)",
                                  "NVOCMP_gMutexPri == NULL"):
                    if invariant not in body:
                        raise RuntimeError("B1_NVS_GUARD_NOT_LINKED " + invariant)
                return body
    raise RuntimeError("NVOCMP_FUNCTION_UNTERMINATED")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--rtos", choices=("priority", "sem", "posix"), default="priority")
    a = p.parse_args()
    source = a.source.read_text(encoding="utf-8")
    define = {"priority": "", "sem": "#define NVOCMP_POSIX_SEM 1\n",
              "posix": "#define NVOCMP_POSIX_MUTEX 1\n"}[a.rtos]
    a.output.write_text(define + PREAMBLE + extract(source) + MAIN, encoding="utf-8")
    print("B1_PINNED_NVOCMP_INIT_COMPILED_FUNCTION_EXTRACTED")


if __name__ == "__main__":
    main()
