/* Offline-only boot-before-overwrite copy and export contract.
 * No physical RAM address, UART/MT, NV, reset or target hardware access.
 */
#ifndef T832_R12_AUX_BOOT_H_
#define T832_R12_AUX_BOOT_H_

#include "r12_aux_trace.h"
#include <stdint.h>

#define R12_AUX_EXPORT_WORDS 10u
#define R12_AUX_EXPORT_MAGIC UINT32_C(0x52313245)

typedef struct {
    R12AuxStatus status;
    R12AuxRecord retained;
    uint32_t current_reset_cause;
    uint32_t captured;
} R12AuxBootCopy;

/* Caller must ensure AUX clock and domain are on before calling. */
R12AuxStatus R12Aux_captureBeforeOverwrite(
    const volatile uint32_t *verified_window,
    uint32_t expected_build, uint32_t current_reset_cause,
    R12AuxBootCopy *dest);

/* Produce 10 fixed-width non-secret words for a FUTURE MT exporter.
 * The output is not a ZNP frame and no I/O is performed by this function.
 */
R12AuxStatus R12Aux_asExportWords(
    const R12AuxBootCopy *copy, uint32_t out[R12_AUX_EXPORT_WORDS]);

#endif
