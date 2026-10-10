/* R12, one translation unit hosted within existing mt_debug.c.
 * This source is NOT an AUX ownership/reset proof. No flash/NV/UART outside
 * already-existing bounded T832R11_sendGroup used by MT poll.
 */
#include "r12_target.h"
#include "r12_aux_trace.c"
#include "r12_aux_boot.c"
static R12AuxBootCopy t832R12Previous = {0};
static uint8_t t832R12WriteEnabled = 0u;
static uint32_t t832R12LastExport = 0u;

static volatile uint32_t *T832R12_window(void)
{
    return (volatile uint32_t *)(uintptr_t)T832_R12_AUX_WINDOW;
}

/* Called strictly after Board_initGeneral and BEFORE main initNV hooks.
 * A foreign/torn existing record is never overwritten. When the previous
 * attempt is present, export it and do NOT record this second boot.
 */
void T832R12_boot(uint32_t reset_cause)
{
    t832R12WriteEnabled = 0u;
    t832R12Previous.captured = 0u;
    t832R12Previous.status = R12Aux_captureBeforeOverwrite(
        T832R12_window(), T832_R12_VERSION, reset_cause, &t832R12Previous);
    if (t832R12Previous.status == R12_AUX_EMPTY ||
        t832R12Previous.status == R12_AUX_TORN) {
        /* On the first qualified R12 boot, the AUX window may still contain
         * unrelated bytes from an earlier firmware. Never format if either
         * R12 magic is present: that could erase a damaged crash record.
         * The physical window exclusivity gate MUST pass before flashing.
         */
        if (R12Aux_initializeVirgin(T832R12_window(),
                                    T832_R12_VERSION) == R12_AUX_OK) {
            t832R12Previous.status = R12_AUX_EMPTY;
            t832R12WriteEnabled = 1u;
        }
    }
}

void T832R12_mark(uint16_t site, uint8_t phase, uint32_t context)
{
    R12AuxRecord receipt;
    if (!t832R12WriteEnabled) return;
    if (R12Aux_commit(T832R12_window(), T832_R12_VERSION,
        T832_R12_ATTEMPT_ID, T832_R12_BOOT_EPOCH,
        site, phase, 0u, context, &receipt) != R12_AUX_OK) {
        t832R12WriteEnabled = 0u;  /* fail closed; never perturb Zigbee path */
    }
}

/* Invoked only from the existing MT export poll AFTER it has passed all
 * transport/busy checks; it cannot make a blocked synchronous MT task run.
 * The retained snapshot is available on a subsequent radio-only reset.
 * Event kind 54 is private R12_RETENTION_V1, four R11-compatible records.
 * Suppress first/repeat updates unless MT accepted the diagnostic frame.
 */
static uint8_t T832R12_tryExport(uint64_t now64, uint32_t now)
{
    T832DiagRecord recs[4] = {{0}};
    uint32_t attempt, epoch, seq;
    uint16_t sitephase, reset_flags;
    if (t832R12Previous.captured != 1u ||
        t832R12Previous.status != R12_AUX_OK) return 0u;
    if (t832R12LastExport &&
        (uint32_t)(now-t832R12LastExport) < 60000u) return 0u;

    attempt = t832R12Previous.retained.attempt;
    epoch = t832R12Previous.retained.boot_epoch;
    seq = t832R12Previous.retained.sequence;
    sitephase = (uint16_t)(
         (t832R12Previous.retained.milestone & 0xffu)
         | ((uint16_t)t832R12Previous.retained.phase << 8u));
    reset_flags = (uint16_t)(
         (t832R12Previous.current_reset_cause & 0xffu)
         | ((uint16_t)t832R12Previous.retained.flags << 8u));
    recs[0].a=0x1000u;
    recs[0].b=(uint16_t)attempt;
    recs[0].c=(uint16_t)(attempt>>16u);
    recs[1].a=0x1001u;
    recs[1].b=(uint16_t)epoch;
    recs[1].c=(uint16_t)(epoch>>16u);
    recs[2].a=0x1002u;
    recs[2].b=(uint16_t)seq;
    recs[2].c=(uint16_t)(seq>>16u);
    recs[3].a=0x1003u;
    recs[3].b=sitephase;
    recs[3].c=reset_flags;
    if (T832R11_sendGroup(54u,recs,now,now64)) {
        t832R12LastExport = now ? now : 1u;
    }
    return 1u;
}
