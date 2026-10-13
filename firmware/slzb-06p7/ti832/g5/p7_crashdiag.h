/* P7-only bounded in-RAM flight recorder (G5 crash-diagnostic slice).
 * NOT_FLASHABLE. Invariants: fixed static storage, zero allocation
 * (incl. ISR path), no keys/addresses/PAN/IEEE/payloads in events,
 * no NV/CCFG writes.
 *
 * Writer-ownership protocol (CR1, Cortex-M4 / TI-RTOS7 semantics):
 * a single writer owns the ring at a time. Ownership is claimed with
 * one atomic exchange (LDREX/STREX on Cortex-M4 via C11 atomics;
 * on-target this maps to the same single-owner discipline a short
 * PRIMASK/Hwi_disable test-and-set would provide -- the claim and
 * release are the only critical points, interrupts stay enabled for
 * the bounded write itself). A task writer that finds the ring owned
 * (nested/preempted attempt) drops its event and bumps the contention
 * counter instead of interleaving. An ISR writer never waits and
 * never preempts an owner: it makes one exchange attempt, and on
 * contention drops + counts. A higher-priority ISR preempting a
 * lower ISR writer therefore also drops. The snapshot reader keeps
 * the seqlock discipline (write_seq odd while owned/mutating), retries
 * bounded times and returns 0 when unstable: no torn CRC-valid data.
 * This is a source/host-proven protocol, NOT hardware qualification:
 * no Hwi priority or PRIMASK behaviour is claimed as board-verified.
 *
 * Integrity (CR2): the record path is O(1). Each record folds only
 * its own 12-byte event plus a few state words into a rolling fold
 * (bounded small constant, no ring scan). The full retained-ring CRC
 * is computed only by p7_diag_seal_retained() (explicit, task context
 * only) and verified once at boot by p7_diag_init_preserving(). Any
 * record after a seal invalidates the seal, so unsealed or post-seal
 * history falls back to a clean init on the next preserving boot.
 *
 * Wire format: schema 1, unchanged layout. Event kinds 17-22 extend
 * the original 1-16 without changing the frame; decoders must accept
 * the extended set (p7_diag_decode.py does).
 * MT SYS vendor endpoint: candidate 0xF0, endpoint DISABLED until the
 * pinned-SDK grep plus the pinned Herdsman SYS-handler check at exact
 * SHAs are reviewed by a human. */
#ifndef P7_CRASHDIAG_H
#define P7_CRASHDIAG_H
#include <stdint.h>
#include <stddef.h>
#define P7_DIAG_SCHEMA 1u
#define P7_DIAG_RING 64u
#define P7_DIAG_HDR 28u
#define P7_DIAG_MT_CMD_CANDIDATE 0xF0u
#define P7_DIAG_MT_ENDPOINT_ENABLED 0 /* gated disabled */
#define P7_DIAG_SNAPSHOT_EVENTS 8u /* bounded: fits one MT SRSP payload */
enum p7_diag_kind {
  P7D_BOOT_ENTER=1, P7D_NV_READ_BEGIN=2, P7D_NV_RESTORED=3, P7D_NV_NEW=4,
  P7D_NV_AMBIGUOUS=5, P7D_ZDO_INIT_ENTER=6, P7D_ZDO_INIT_EXIT=7,
  P7D_DEV_STATE=8, P7D_MT_RX=9, P7D_SRSP_QUEUED=10, P7D_UART_ACCEPTED=11,
  P7D_UART_TX_FINISHED=12, P7D_UART_REJECTED=13, P7D_QUEUE_DEPTH=14,
  P7D_FAULT=15, P7D_RESET_SOURCE=16,
  P7D_ZDO_DISPATCH=17, P7D_NPI_Q_ACCEPT=18, P7D_NPI_Q_REJECT=19,
  P7D_PARSE_ERR=20, P7D_FCS_ERR=21, P7D_OVERFLOW=22
};
enum p7_diag_nv { P7D_NVSTATE_UNKNOWN=0, P7D_NVSTATE_RESTORED=1, P7D_NVSTATE_NEW=2, P7D_NVSTATE_AMBIGUOUS=3 };
typedef struct { uint32_t seq; uint32_t tick; uint16_t kind; uint16_t arg; } p7_diag_event_t; /* 12 B, numeric only */
typedef struct {
  uint32_t boot_generation; uint32_t dropped; uint32_t total;
  uint16_t head; uint16_t count; uint8_t nv_state; uint8_t reset_source_known;
  uint8_t reset_source; uint8_t reserved;
} p7_diag_state_t;
void p7_diag_init(uint32_t boot_generation, uint8_t reset_source, uint8_t reset_known);
/* Boot-time preservation: requires retained_valid from a separately
 * gated noinit-section check AND a valid seal (p7_diag_seal_retained
 * with no record since). Corrupt, unsealed or post-seal-modified
 * retained RAM falls back to p7_diag_init. Retention on this board
 * is UNPROVEN; this never claims retention happened. */
void p7_diag_init_preserving(uint32_t boot_generation, uint8_t reset_source, uint8_t reset_known, uint8_t retained_valid);
/* Explicit task-context seal of the retained ring (full CRC). ISR
 * callers must never call this. Records after sealing invalidate it. */
void p7_diag_seal_retained(void);
void p7_diag_record(uint16_t kind, uint16_t arg, uint32_t tick); /* task context; drops+counts on writer contention */
void p7_diag_record_isr(uint16_t kind, uint16_t arg, uint32_t tick); /* no alloc/block/print/wait; drops+counts on contention */
size_t p7_diag_snapshot(uint8_t *out, size_t cap);
uint16_t p7_diag_crc16(const uint8_t *data, size_t len);
extern volatile p7_diag_state_t p7_diag_state;
extern p7_diag_event_t p7_diag_ring[P7_DIAG_RING];
/* Writer-contention drops (nested task attempts + ISR attempts).
 * Mirrored into snapshot bytes 24-27 for wire compatibility. */
extern volatile uint32_t p7_diag_contention_dropped;
/* Host test hook (NULL on target): invoked once mid-write, after the
 * first event field is stored and while writer ownership is held, so
 * tests can inject a nested task record + an ISR record attempt. */
extern void (*p7_diag_preempt_hook)(void);
#endif
