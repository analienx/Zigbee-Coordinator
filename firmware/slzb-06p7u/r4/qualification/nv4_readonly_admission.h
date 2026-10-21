/* Read-only strict stock NV4 structure admission. NOT a Zigbee startup gate. */
#ifndef R4_P7U_NV4_READONLY_ADMISSION_H
#define R4_P7U_NV4_READONLY_ADMISSION_H
#include <stdint.h>

#define R4_NV4_PAGE_SIZE 8192u
#define R4_NV4_PAGES 4u
#define R4_NV4_REGION_SIZE (R4_NV4_PAGE_SIZE * R4_NV4_PAGES)

typedef int (*r4_nv4_read)(void *context, uint32_t offset, uint8_t *to,
                           uint32_t length);
typedef enum {
    R4_NV4_BAD_READER = 1, R4_NV4_READ_FAILURE = 2,
    R4_NV4_BAD_PAGE_HEADER = 3, R4_NV4_UNSAFE_PAGE_STATES = 4,
    R4_NV4_BAD_ITEM = 5, R4_NV4_BAD_CRC = 6,
    R4_NV4_SCAN_LIMIT = 7, R4_NV4_READONLY_STRUCTURE_ACCEPTED = 8,
    R4_NV4_DUPLICATE_ACTIVE_ID = 9, R4_NV4_INVALID_STATUS = 10,
    R4_NV4_NO_ZSTACK_RECORDS = 11,
    /* Read-only authorization to invoke PINNED TI init recovery, NOT a
     * permission to form a Zigbee network or erase the original source. */
    R4_NV4_RECOVER_COMPACT_CANDIDATE = 12,
    R4_NV4_RECOVER_ERASE_CANDIDATE = 13
} r4_nv4_code;
/* Observations only: neither candidate authorizes formation, RF or flash. */
typedef enum {
    R4_NV4_STATE_UNKNOWN_HOLD = 0,
    R4_NV4_STATE_UNCOMMISSIONED_CANDIDATE = 1,
    R4_NV4_STATE_FORMED_CANDIDATE = 2
} r4_nv4_semantic_state;
typedef struct {
    r4_nv4_code code;
    uint32_t reads;
    uint32_t records;
    uint32_t active_records;
    uint32_t fault_offset;
    r4_nv4_semantic_state semantic_state;
    /* Diagnostic bits: BDB seen/on-network, role seen/coordinator, NIB seen,
     * startup seen/safe, malformed marker. No payload bytes are exposed. */
    uint32_t semantic_flags;
} r4_nv4_result;

r4_nv4_result r4_nv4_admit(r4_nv4_read reader, void *context);
#endif
