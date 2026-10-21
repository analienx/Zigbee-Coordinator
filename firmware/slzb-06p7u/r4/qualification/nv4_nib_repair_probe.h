/* Pre-Zigbee, read-only qualification of a single deleted original NIB.
 * This is a candidate only. Flash writes are exclusively in the pinned TI
 * NVOCMP caller, after a successful normal-resume initialization.
 */
#ifndef R4_NV4_NIB_REPAIR_PROBE_H
#define R4_NV4_NIB_REPAIR_PROBE_H
#include <stdint.h>
#include "nv4_readonly_admission.h"

#define R4_RECOVER_NIB_LENGTH 116u
#define R4_RECOVER_NIB_EPAN_OFFSET 57u
#define R4_RECOVER_STARTUP_OPTION 0x0003u
#define R4_RECOVER_NIB_ID 0x0021u

typedef struct {
    uint32_t nib_payload_offset;
    uint8_t startup_value;
    uint8_t eligible;
} r4_nv4_nib_candidate;

/* Only records original NIB and exact retained active security prerequisites.
 * Writes NOTHING; copies the CRC-verified original NIB into caller buffer.
 * No secret data is included in the result or any log.
 */
int r4_nv4_probe_nib(r4_nv4_read reader, void *context,
                     r4_nv4_nib_candidate *result,
                     uint8_t nib_out[R4_RECOVER_NIB_LENGTH]);
#endif
