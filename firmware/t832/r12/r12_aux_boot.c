#include "r12_aux_boot.h"

R12AuxStatus R12Aux_captureBeforeOverwrite(
    const volatile uint32_t *verified_window,
    uint32_t expected_build, uint32_t current_reset_cause,
    R12AuxBootCopy *dest)
{
    R12AuxRecord found;
    R12AuxStatus status;
    if (verified_window == 0 || dest == 0 || expected_build == 0u) {
        return R12_AUX_BAD_ARGUMENT;
    }
    /* Always initialize ordinary RAM; never modify the retained AUX slot. */
    dest->status = R12_AUX_EMPTY;
    dest->captured = 0u;
    dest->current_reset_cause = current_reset_cause;
    status = R12Aux_readLatest(verified_window, expected_build, &found);
    dest->status = status;
    if (status == R12_AUX_OK) {
        dest->retained = found;
        dest->captured = 1u;
    }
    return status;
}

R12AuxStatus R12Aux_asExportWords(
    const R12AuxBootCopy *copy, uint32_t out[R12_AUX_EXPORT_WORDS])
{
    unsigned int i;
    if (copy == 0 || out == 0) {
        return R12_AUX_BAD_ARGUMENT;
    }
    if (copy->status != R12_AUX_OK || copy->captured != 1u) {
        return copy->status == R12_AUX_OK
            ? R12_AUX_BAD_ARGUMENT : copy->status;
    }
    /* Exact 10-word, little-endian serialization contract.
     * These are RECORD METADATA, never NIB/security keys or device IDs.
     */
    for (i = 0u; i < R12_AUX_EXPORT_WORDS; ++i) {
        out[i] = 0u;
    }
    out[0] = R12_AUX_EXPORT_MAGIC;
    out[1] = copy->retained.build;
    out[2] = copy->retained.attempt;
    out[3] = copy->retained.boot_epoch;
    out[4] = copy->retained.sequence;
    out[5] = (uint32_t)copy->retained.milestone
             | ((uint32_t)copy->retained.phase << 16u)
             | ((uint32_t)copy->retained.flags << 24u);
    out[6] = copy->retained.context;
    out[7] = copy->current_reset_cause;
    out[8] = (uint32_t)copy->retained.slot;
    out[9] = R12_AUX_LAYOUT_VERSION;
    return R12_AUX_OK;
}
