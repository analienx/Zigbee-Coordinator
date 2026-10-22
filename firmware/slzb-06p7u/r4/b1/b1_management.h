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
#define B1_ERROR_UART_WRITE 0x67u
#define B1_ERROR_STARTUP_TX_TIMEOUT 0x68u
#define B1_ERROR_EVENT_POST 0x69u
#define B1_ERROR_RESUME_MODE 0x6Au
#define B1_ERROR_RESUME_REJECTED 0x6Bu
#define B1_ERROR_CONFIRMATION 0x6Cu
#define B1_ERROR_BDB_UNEXPECTED 0x6Du
#define B1_EVIDENCE_REPLY_SIZE 128u
#define B1_MILESTONES 24u
enum {
    B1_M_RETAINED_DISPATCH = 0, B1_M_BDB_ENTRY = 1,
    B1_M_BDB_BRANCH = 2, B1_M_ZDO_INIT_ENTRY = 3,
    B1_M_ZDO_INIT_RESULT = 4, B1_M_NWK_INIT_ENTRY = 5,
    B1_M_INIT_POST = 6, B1_M_BDB_RETURN = 7,
    B1_M_INIT_DISPATCH = 8, B1_M_STARTDEV_ENTRY = 9,
    B1_M_RESUME_ENTRY = 10, B1_M_RESUME_RESULT = 11,
    B1_M_STARTDEV_RETURN = 12, B1_M_FORMATION_CNF = 13,
    B1_M_ROUTER_CNF = 14, B1_M_START_POST = 15,
    B1_M_START_POST_RESULT = 16, B1_M_START_DISPATCH = 17,
    B1_M_NETWORK_START_ENTRY = 18, B1_M_COORDINATOR = 19,
    B1_M_MARKER_ENTRY = 20, B1_M_MARKER_RESULT = 21,
    B1_M_READY = 22, B1_M_FAILED = 23
};
enum {
    B1_C_INIT_POST = 0, B1_C_INIT_DISPATCH = 1,
    B1_C_START_POST = 2, B1_C_START_DISPATCH = 3,
    B1_C_STARTDEV = 4, B1_C_RESUME = 5,
    B1_C_CONFIRM = 6
};
#define B1_STARTUP_REPLY_SIZE 32u
#define B1_STARTUP_TRACE_COMMAND 0xF3u

enum {
    B1_STARTUP_IDLE = 0, B1_STARTUP_WAIT_SRSP_TX = 1,
    B1_STARTUP_QUEUED = 2, B1_STARTUP_RUNNING = 3,
    B1_STARTUP_READY = 4, B1_STARTUP_FAILED = 5
};
enum {
    B1_PHASE_ADMITTED = 1, B1_PHASE_BDB = 2, B1_PHASE_GLOBALS = 3,
    B1_PHASE_CAPACITY = 4, B1_PHASE_NLME_INIT = 5,
    B1_PHASE_NLME_RESTORE = 6, B1_PHASE_NWK_RESERVE = 7,
    B1_PHASE_SECURITY = 8, B1_PHASE_SEC_ENTRIES = 9,
    B1_PHASE_SSP = 10, B1_PHASE_SEC_CONFIG = 11,
    B1_PHASE_NETWORK_INIT = 12, B1_PHASE_NETWORK_START = 13,
    B1_PHASE_COORDINATOR = 14, B1_PHASE_CONFIGURED = 15
};

enum {
    B1_STAGE_PRE_BOOT = 0,
    B1_STAGE_NV_HEADER_CANDIDATE = 1,
    B1_STAGE_HOLD_NV = 2,
    B1_STAGE_HOLD_SECURITY = 3,
    B1_STAGE_HOLD_TRANSPORT = 4,
    B1_STAGE_NETWORK_READY = 5
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
/* RF/persistence safety depends on NV or security HOLD, not a lost host UART.
 * Transport HOLD continues to gate only management/NPI visibility. */
int b1_management_nv_security_hold_active(void);
void b1_management_note_nv_candidate(void);
void b1_management_note_nv_probe(uint8_t code);
/* Read-only F1 detail query: preserve the raw NV4 result before B1 mapping. */
void b1_management_note_nv4(uint32_t code, uint32_t semantic, uint32_t reads,
                           uint32_t records, uint32_t active, uint32_t fault,
                           uint32_t semantic_flags);
void b1_management_transport_failed(uint8_t reason);
void b1_management_note_uart_opened(void);
void b1_management_note_npi_initialized(void);
int b1_management_npi_initialized(void);
/* Transport corruption is distinct from legitimate NV/security HOLD. */
int b1_management_transport_unavailable(void);
void b1_management_note_mt_registered(void);
int b1_management_mt_registered(void);
/* Attest readiness only from the TI ZDO coordinator transition and coherent
 * restored security / durable NWK frame counter. Never a timer or SYS_PING. */
void b1_management_note_zdo_state(uint8_t coordinator, uint8_t persisted_restore_ok);
int b1_management_network_ready(void);
/* Called only at the real MT_ProcessIncoming dispatch boundary. The flag
 * proves dispatch execution, not successful UART transmission or host receipt. */
uint8_t b1_management_mt_filter(const uint8_t *frame,
                              uint8_t reply[B1_STATUS_REPLY_SIZE],
                              uint8_t *rpc_error);
/* Shared per-boot startup admission; all helpers below are RAM-only. */
uint8_t b1_startup_state(void);
int b1_startup_admit(uint8_t response_subsystem, uint8_t response_command);
int b1_startup_begin(void);
void b1_startup_expire(void);
void b1_startup_fail(uint8_t reason);
void b1_startup_note_phase(uint8_t phase, uint8_t status, uint16_t index);
void b1_startup_note_nv(uint8_t stage, uint8_t op, uint16_t item,
                        uint16_t sub, uint8_t status);
int b1_startup_trace_armed(void);
uint8_t b1_startup_query(const uint8_t *frame,
                        uint8_t reply[B1_STARTUP_REPLY_SIZE], uint8_t *error);
void b1_startup_snapshot(uint8_t reply[B1_STARTUP_REPLY_SIZE]);
void b1_startup_tx_submit(const uint8_t *frame, uint16_t length);
void b1_startup_tx_result(uint16_t length, int success);
void b1_startup_tx_accepted(uint16_t length, int success);
void b1_startup_tx_eot(void);
/* Native stack-task hooks are defined by the pinned MT_ZDO overlay. */
void b1_startup_post_run(void);
int b1_startup_checkpoint(uint8_t phase);
void b1_startup_trace_tx_done(void);
void b1_startup_trace_expect(uint16_t sequence);
/* B1E1 v1: strictly RAM-only; monotonic milestones cannot be reset. */
void b1_evidence_milestone(uint8_t index, uint8_t first_status);
void b1_evidence_count(uint8_t counter);
void b1_evidence_dispatch(uint8_t service, uint32_t input);
void b1_evidence_dispatch_end(uint32_t returned);
void b1_evidence_bind_pending(uint32_t *event_word);
void b1_evidence_note_npi_wake(void);
void b1_evidence_note_zdapp_loop(uint32_t events);
void b1_evidence_set_status(uint8_t slot, uint8_t value);
void b1_evidence_snapshot(uint8_t out[B1_EVIDENCE_REPLY_SIZE]);
uint8_t b1_evidence_query(const uint8_t *frame,
                          uint8_t out[B1_EVIDENCE_REPLY_SIZE],
                          uint8_t *error);
int b1_retained_attempt_active(void);
int b1_retained_start_gate(uint8_t mode, uint8_t logical_type);
#endif
