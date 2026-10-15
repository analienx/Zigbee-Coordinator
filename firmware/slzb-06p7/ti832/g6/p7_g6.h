/* Offline CC2652P7 reference candidate only; NOT FLASHABLE. */
#ifndef P7_G6_H
#define P7_G6_H
#include "p7_crashdiag.h"
#define P7_G6_CMD 0xF0u
#define P7_G6_VERSION 1u
#define P7_G6_HEALTH_VERSION 2u
#define P7_G6_MT_ENDPOINT_ENABLED 1 /* G6 overlay installs the SYS handler */
#define P7_G6_HDR 16u
#define P7_G6_SRSP_SEND_ATTEMPTED 24u
#define P7_G6_MAX (P7_G6_HDR + P7_DIAG_HDR + 12u * P7_DIAG_SNAPSHOT_EVENTS + 4u)
#define P7_G6_HEALTH_COUNTERS 16u
#define P7_G6_HEALTH_BYTES 100u
enum { P7_G6_OK=0, P7_G6_LENGTH=1, P7_G6_VERSION_ERR=2,
       P7_G6_OPERATION=3, P7_G6_BUSY=4, P7_G6_TYPE=5 };
uint32_t p7_g6_now(void);
uint32_t p7_g6_period_us(void);
/* Implemented beside the G5 writer: sample the clock AFTER claiming ownership.
 * The task and ISR use the same bounded try-claim, dropping on contention. */
void p7_g6_record(uint16_t kind, uint16_t arg);
/* Same recorder ownership guard. Counts saturate per boot; contention drops
 * are exported separately. No allocations, reset, NV reads/writes or secrets. */
size_t p7_g6_health_snapshot(uint8_t *out, size_t capacity);
/* Task context only. Fixed maximum of eight events, bounded snapshot retries.
 * Request [1,0]: legacy snapshot. [2,0]: bounded counters + RAM concentrator
 * values. [2,1]: length-prefixed form of that same reply, for the existing
 * Herdsman owner's public length+BUFFER parser. No NV/reset/write/seal. */
size_t p7_g6_response(const uint8_t *request, size_t length, int sreq,
                      uint8_t *out, size_t capacity);
/* ISR sets; NPI task clears after dropping buffered bytes and resetting parser.
 * No partial-frame free or parser-state mutation in interrupt context. */
extern volatile uint8_t p7_g6_rx_resync;
#endif
