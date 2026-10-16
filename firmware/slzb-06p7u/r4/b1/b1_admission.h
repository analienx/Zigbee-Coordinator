#ifndef R4_B1_NV_ADMISSION_H
#define R4_B1_NV_ADMISSION_H
/* B1 read-only, bounded NV2 preflight. This is NOT an NV/security validity proof. */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define B1_NV2_PAGE_SIZE 8192u
#define B1_NV2_PAGE_COUNT 2u
#define B1_NV2_REGION_SIZE (B1_NV2_PAGE_SIZE * B1_NV2_PAGE_COUNT)

typedef int_fast16_t (*b1_nv_read_fn)(void *ctx, uint32_t offset,
                                     uint8_t *dst, uint32_t length);
typedef enum {
    B1_NV_HOLD_NO_READER = 1,
    B1_NV_HOLD_READ_FAILED = 2,
    B1_NV_HOLD_UNKNOWN_LAYOUT = 3,
    B1_NV_HOLD_MIXED_LAYOUT = 4,
    B1_NV_HOLD_FACTORY_NOT_AUTHORIZED = 5,
    B1_NV_FACTORY_AUTHORIZED = 6,
    B1_NV2_HEADER_CANDIDATE = 7
} b1_nv_probe_code;
typedef struct {
    b1_nv_probe_code code;
    uint32_t first_fault_offset;
    uint16_t reads;
    uint8_t blank_pages;
    uint8_t candidate_pages;
} b1_nv_probe_result;

b1_nv_probe_result b1_nv_probe(b1_nv_read_fn reader, void *ctx,
                               bool factory_new_authorized);
#endif
