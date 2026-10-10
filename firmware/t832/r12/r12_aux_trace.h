/*
 * R12 AUX journal prototype — HOST/SOURCE QUALIFICATION ONLY.
 *
 * No MMIO base address, radio API, NV, UART, heap or reset operation.
 * A verified caller must supply a separately proven, exclusively-owned
 * 80-byte AUX RAM window. See T832_R12_AUX_POSTRESET_TRACE_ADR.md.
 *
 * Deliberately NOT wired into production firmware until ownership, clocks,
 * reset-retention and boot-before-overwrite have passed their gates.
 */
#ifndef T832_R12_AUX_TRACE_H_
#define T832_R12_AUX_TRACE_H_

#include <stddef.h>
#include <stdint.h>

#define R12_AUX_MAGIC             UINT32_C(0x52313241)
#define R12_AUX_COMMIT            UINT32_C(0xA12C04E5)
#define R12_AUX_LAYOUT_VERSION    UINT32_C(1)
#define R12_AUX_SLOT_WORDS        10u
#define R12_AUX_SLOT_BYTES        40u
#define R12_AUX_NUM_SLOTS         2u
#define R12_AUX_WINDOW_WORDS      20u
#define R12_AUX_WINDOW_BYTES      80u
#define R12_AUX_VERSION_SIZE      UINT32_C(0x00280001)

typedef struct {
    uint32_t build;
    uint32_t attempt;
    uint32_t boot_epoch;
    uint32_t sequence;
    uint16_t milestone;
    uint8_t phase;
    uint8_t flags;
    uint32_t context;
    uint8_t slot;
} R12AuxRecord;

typedef enum {
    R12_AUX_OK = 0,
    R12_AUX_EMPTY = 1,
    R12_AUX_TORN = 2,
    R12_AUX_BAD_ARGUMENT = 3,
    R12_AUX_FOREIGN_BUILD = 4,
    R12_AUX_VERIFY_FAILED = 5,
    R12_AUX_AMBIGUOUS_SEQUENCE = 6,
    R12_AUX_UNACKNOWLEDGED_EPOCH = 7
} R12AuxStatus;

/* First qualified R12 boot only: formats an unrecognized AUX window only
 * when neither slot contains R12 magic. Any old R12 marker or foreign
 * coherent record is preserved. Requires independent physical ownership.
 */
R12AuxStatus R12Aux_initializeVirgin(volatile uint32_t *window,
                                      uint32_t expected_build);

/* Must be called before any R12 hooks overwrite the previous boot's slots. */
R12AuxStatus R12Aux_readLatest(const volatile uint32_t *window,
                               uint32_t expected_build,
                               R12AuxRecord *out);

/* Pure bounded writer: no I/O other than supplied 80-byte volatile window. */
R12AuxStatus R12Aux_commit(volatile uint32_t *window,
                           uint32_t expected_build,
                           uint32_t attempt,
                           uint32_t boot_epoch,
                           uint16_t milestone,
                           uint8_t phase,
                           uint8_t flags,
                           uint32_t context,
                           R12AuxRecord *committed_out);

/* Validates pre-commit bytes; all arithmetic is deterministic and bounded. */
uint32_t R12Aux_checksumWords(const uint32_t *words, size_t count);

#endif
