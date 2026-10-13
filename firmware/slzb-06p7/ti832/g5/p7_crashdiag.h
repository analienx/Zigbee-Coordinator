/* P7-only bounded in-RAM flight recorder (G5 crash-diagnostic slice 1).
 * Source-only prototype: NOT_FLASHABLE, not wired into any CCS build yet.
 * Invariants: fixed static storage, zero allocation (incl. ISR path),
 * no keys/addresses/PAN/IEEE/payloads in events, no NV/CCFG writes.
 * MT SYS vendor endpoint: candidate 0xF0, collision check UNKNOWN against
 * pinned TI mt_sys.c (not vendored in this repo; parity F13 documents the
 * P10 CAP192 use of 0xF0, which does NOT prove P7 vanilla availability).
 * Endpoint therefore gated DISABLED until the G5 CI SDK grep passes. */
#ifndef P7_CRASHDIAG_H
#define P7_CRASHDIAG_H
#include <stdint.h>
#include <stddef.h>
#define P7_DIAG_SCHEMA 1u
#define P7_DIAG_RING 64u
#define P7_DIAG_MT_CMD_CANDIDATE 0xF0u
#define P7_DIAG_MT_ENDPOINT_ENABLED 0 /* UNKNOWN collision -> disabled */
#define P7_DIAG_SNAPSHOT_EVENTS 8u /* bounded: fits one MT SRSP payload */
enum p7_diag_kind {
  P7D_BOOT_ENTER=1, P7D_NV_READ_BEGIN=2, P7D_NV_RESTORED=3, P7D_NV_NEW=4,
  P7D_NV_AMBIGUOUS=5, P7D_ZDO_INIT_ENTER=6, P7D_ZDO_INIT_EXIT=7,
  P7D_DEV_STATE=8, P7D_MT_RX=9, P7D_SRSP_QUEUED=10, P7D_UART_ACCEPTED=11,
  P7D_UART_TX_FINISHED=12, P7D_UART_REJECTED=13, P7D_QUEUE_DEPTH=14,
  P7D_FAULT=15, P7D_RESET_SOURCE=16
};
enum p7_diag_nv { P7D_NVSTATE_UNKNOWN=0, P7D_NVSTATE_RESTORED=1, P7D_NVSTATE_NEW=2, P7D_NVSTATE_AMBIGUOUS=3 };
typedef struct { uint32_t seq; uint32_t tick; uint16_t kind; uint16_t arg; } p7_diag_event_t; /* 12 B, numeric only */
typedef struct {
  uint32_t boot_generation; uint32_t dropped; uint32_t total;
  uint16_t head; uint16_t count; uint8_t nv_state; uint8_t reset_source_known;
  uint8_t reset_source; uint8_t reserved;
} p7_diag_state_t;
void p7_diag_init(uint32_t boot_generation, uint8_t reset_source, uint8_t reset_known);
void p7_diag_record(uint16_t kind, uint16_t arg, uint32_t tick); /* task context */
void p7_diag_record_isr(uint16_t kind, uint16_t arg, uint32_t tick); /* no alloc/block/print */
/* Bounded snapshot: header 16 B + up to P7_DIAG_SNAPSHOT_EVENTS*12 B = 112 B.
 * Returns bytes written, 0 if out too small. CRC16-CCITT over payload. */
size_t p7_diag_snapshot(uint8_t *out, size_t cap);
uint16_t p7_diag_crc16(const uint8_t *data, size_t len);
extern volatile p7_diag_state_t p7_diag_state;
extern p7_diag_event_t p7_diag_ring[P7_DIAG_RING];
#endif
