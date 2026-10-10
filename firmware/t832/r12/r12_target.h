/* R12 target integration, source-level candidate only. Never flash before AUX
 * memory ownership, boot clock and real SLZB PIN_RESET retention qualification.
 * This file is included once from MT debug translation unit.
 */
#ifndef T832_R12_TARGET_H_
#define T832_R12_TARGET_H_
#include <stdint.h>
#define T832_R12_VERSION 8320062u
#define T832_R12_ATTEMPT_ID 0xA0120001u
#define T832_R12_BOOT_EPOCH 0x20261010u
#define T832_R12_AUX_WINDOW 0x400E0FB0u /* CANDIDATE only: unproven ownership */
void T832R12_boot(uint32_t reset_cause);
void T832R12_mark(uint16_t site, uint8_t phase, uint32_t context);
#endif
