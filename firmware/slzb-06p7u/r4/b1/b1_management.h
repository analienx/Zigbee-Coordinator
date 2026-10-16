#ifndef R4_B1_MANAGEMENT_H
#define R4_B1_MANAGEMENT_H
#include <stdint.h>

/* Separate from F0/P10 V2 and proposed R4D3. No key/counter bytes. */
#define B1_STATUS_COMMAND 0xF1u
#define B1_STATUS_QUERY_SIZE 8u
#define B1_STATUS_REPLY_SIZE 24u
#define B1_ERROR_NV_BACKEND 0x20u
#define B1_ERROR_NV_INIT 0x21u
#define B1_ERROR_NV_MUTEX 0x22u
#define B1_ERROR_NV_OPEN 0x23u
#define B1_ERROR_NV_GEOMETRY 0x24u
#define B1_ERROR_NV_API 0x25u
#define B1_ERROR_SECURITY_RESTORE 0x40u
#define B1_ERROR_NPI_QUEUE 0x60u
#define B1_ERROR_NPI_SEMAPHORE 0x61u
#define B1_ERROR_NPI_REGISTER 0x62u
#define B1_ERROR_UART_OPEN 0x63u
#define B1_ERROR_UART_READ 0x64u
#define B1_ERROR_MT_NOT_REGISTERED 0x65u
#define B1_ERROR_NPI_RX_OVERFLOW 0x66u

enum {
    B1_STAGE_PRE_BOOT = 0,
    B1_STAGE_NV_HEADER_CANDIDATE = 1,
    B1_STAGE_HOLD_NV = 2,
    B1_STAGE_HOLD_SECURITY = 3,
    B1_STAGE_HOLD_TRANSPORT = 4
};
enum {
    B1_FLAG_MT_HANDLER_REACHED = 1u,
    B1_FLAG_NV_HEADER_CANDIDATE = 2u,
    B1_FLAG_HOLD_NV = 4u,
    B1_FLAG_HOLD_SECURITY = 8u,
    B1_FLAG_HOLD_TRANSPORT = 16u,
    B1_FLAG_UART_OPENED = 32u,
    B1_FLAG_NPI_INITIALIZED = 64u,
    B1_FLAG_MT_REGISTERED = 128u
};
enum {
    B1_MT_CONTINUE = 0,
    B1_MT_STATUS = 1,
    B1_MT_REJECT = 2,
    B1_MT_DROP = 3
};

void b1_management_hold_nv(uint8_t reason);
void b1_security_runtime_hold_latch(void);
int b1_management_get_hold_active(void);
void b1_management_note_nv_candidate(void);
void b1_management_note_nv_probe(uint8_t code);
void b1_management_transport_failed(uint8_t reason);
void b1_management_note_uart_opened(void);
void b1_management_note_npi_initialized(void);
int b1_management_npi_initialized(void);
/* Transport corruption is distinct from legitimate NV/security HOLD. */
int b1_management_transport_unavailable(void);
void b1_management_note_mt_registered(void);
int b1_management_mt_registered(void);
/* Called only at the real MT_ProcessIncoming dispatch boundary. The flag
 * proves dispatch execution, not successful UART transmission or host receipt. */
uint8_t b1_management_mt_filter(const uint8_t *frame,
                              uint8_t reply[B1_STATUS_REPLY_SIZE],
                              uint8_t *rpc_error);
#endif
