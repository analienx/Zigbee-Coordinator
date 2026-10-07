#ifndef T832_R6_NV_PROBE_H
#define T832_R6_NV_PROBE_H
#include <stdint.h>
/* Fixed public metadata only. Never contains item IDs, payloads or keys. */
typedef struct {
    uint32_t sequence, requests, compactions, compact_failures;
    uint16_t requested, status, first_failure, first_failure_requested, stage, init_action;
    uint16_t pages, head, tail, active, active_offset, ready;
    uint16_t offsets[NVOCMP_NVPAGES];
    uint8_t states[NVOCMP_NVPAGES];
    uint8_t rej_status, rej_page, rej_site, rej_raw;
} T832R6NvSnapshot;
extern volatile T832R6NvSnapshot t832R6Nv;
void T832R6Nv_capture(uint16_t stage,uint16_t requested,uint16_t status);
#endif
