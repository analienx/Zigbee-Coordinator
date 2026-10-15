/* Temporary P7U startup instrumentation. Never link into a release candidate. */
#ifndef P7_BOOTDIAG_H
#define P7_BOOTDIAG_H
#include <stdint.h>
#define P7_BD_STACK_BYTES 4096u
#define P7_BD_OLD_STACK_BYTES 1024u
#define P7_BD_POLL_LIMIT 100000u
enum p7_bd_stage {
    P7BD_BOARD = 1, P7BD_BEFORE_NV, P7BD_NV_RESULT, P7BD_NV_FAILURE,
    P7BD_BEFORE_BIOS, P7BD_STACK_ENTER, P7BD_CRYPTO, P7BD_MAC,
    P7BD_ZG, P7BD_SERVICES, P7BD_STACK_READY, P7BD_HANDOFF,
    P7BD_NPI_OPEN, P7BD_ASSERT
};
void p7_bootdiag_begin(void);
void p7_bootdiag_stage(uint8_t stage, uint16_t arg, uint16_t value);
void p7_bootdiag_arm_stack(void);
void p7_bootdiag_nv_result(uint8_t status);
int p7_bootdiag_handoff(void);
int p7_bootdiag_npi_opened(void *handle);
#endif
