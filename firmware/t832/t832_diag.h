#ifndef T832_DIAG_H
#define T832_DIAG_H

#include <stdint.h>

/* Wire schema 2: length-prefixed "T832D2:" + hex, batched records. */
#define T832_DIAG_SCHEMA_VERSION 2u
#define T832_DIAG_TICK_EVENT 0x4000u
/* Maximum diagnostic records carried in one DEBUG.msg frame. */
#define T832_DIAG_BATCH_MAX 4u
/* Boot-capture validity marker written by early startup before MT init. */
#define T832_DIAG_BOOT_MAGIC 0x8D1A6B3Cu
#define T832_DIAG_CAP_STARTUP       (1u << 0)
#define T832_DIAG_CAP_BDB           (1u << 1)
#define T832_DIAG_CAP_MT_PROGRESS   (1u << 2)
#define T832_DIAG_CAP_NPI_PROGRESS  (1u << 3)
#define T832_DIAG_CAP_RX_OVERFLOW   (1u << 4)
#define T832_DIAG_CAP_TX_FINISHED   (1u << 5)
#define T832_DIAG_CAP_COMMAND_PATH  (1u << 6)
#define T832_DIAG_CAP_SYNC_GATE     (1u << 7)
#define T832_DIAG_CAP_RX_HWM        (1u << 8)
#define T832_DIAG_CAP_QUEUE_APPROX  (1u << 9)
#define T832_DIAG_CAP_RESET_CAUSE   (1u << 10)
#define T832_DIAG_CAP_NETWORK_STATE (1u << 11)
#define T832_DIAG_CAP_AGG_COUNTERS  (1u << 12)
/* Bit 13 observes MT OSAL event-mask bits only; it is not task-state sampling. */
#define T832_DIAG_CAP_MT_EVENTS     (1u << 13)
#define T832_DIAG_CAP_NV_COMPACT    (1u << 14)
#define T832_DIAG_CAP_AF_AGE        (1u << 15)
#define T832_DIAG_CAP_ZSTACK_TASK   (1u << 16)
#define T832_DIAG_CAP_NPI_TASK      (1u << 17)
#define T832_DIAG_CAP_HEAP_STATS    (1u << 18)
#define T832_DIAG_CAP_TX_OWNERSHIP  (1u << 19)
#define T832_DIAG_CAP_AF_ACCEPT     (1u << 20)
#define T832_DIAG_CAP_BATCHED_V2    (1u << 21)

enum {
  T832_DIAG_EV_BOOT = 1,
  T832_DIAG_EV_MT_COMMAND_RX,
  T832_DIAG_EV_MT_COMMAND_DISPATCH,
  T832_DIAG_EV_MT_COMMAND_COMPLETE,
  T832_DIAG_EV_RESPONSE_QUEUED,
  T832_DIAG_EV_RESPONSE_ALLOC_FAIL,
  T832_DIAG_EV_NPI_RX_PROGRESS,
  T832_DIAG_EV_NPI_RX_OVERFLOW,
  T832_DIAG_EV_NPI_WRITE_REJECT,
  T832_DIAG_EV_NPI_TX_FINISHED,
  T832_DIAG_EV_TASK_SCHEDULE,
  T832_DIAG_EV_TASK_WORK,
  T832_DIAG_EV_STARTUP_ENTRY,
  T832_DIAG_EV_STARTUP_BDB_REQUEST,
  T832_DIAG_EV_STARTUP_BDB_RETURN,
  T832_DIAG_EV_STARTUP_SRSP_QUEUE,
  T832_DIAG_EV_BDB_DISPATCH,
  T832_DIAG_EV_BDB_RETURN,
  T832_DIAG_EV_HEALTH,
  T832_DIAG_EV_RESOURCE,
  T832_DIAG_EV_EXPORT_SKIP,
  T832_DIAG_EV_FIRST_FAULT,
  T832_DIAG_EV_RX_BUFFER_FULL,
  T832_DIAG_EV_NETWORK_STATE,
  T832_DIAG_EV_TRANSPORT_CONFIG,
  T832_DIAG_EV_TASK_EVENTS,
  T832_DIAG_EV_NV_EVENT,
  T832_DIAG_EV_AF_STATE,
  T832_DIAG_EV_NV_FAULT,
  T832_DIAG_EV_TX_MISMATCH,
  T832_DIAG_EV_SYNC_ABANDON,
  T832_DIAG_EV_AF_REJECT,
  T832_DIAG_EV_AF_ANOMALY,
  T832_DIAG_EV_DIAG_LOSS,
  T832_DIAG_EV_NPI_TRAP,
  T832_DIAG_EV_NPI_ALLOC_FAIL,
  T832_DIAG_EV_BOOT_CAPTURE_INVALID,
  T832_DIAG_EV_TIMING_APPROX
};

_Static_assert(T832_DIAG_EV_TIMING_APPROX <= 63u,
               "first-fault original-kind tag needs 6 flag bits");

/* Snapshot re-emit marker in record flags (bit 1); bit 0 stays critical. */
#define T832_DIAG_FLAG_SNAPSHOT 0x02u

enum {
  T832_DIAG_WORK_MT = 1,
  T832_DIAG_WORK_NPI = 2,
  T832_DIAG_WORK_ZSTACK = 3
};

/* TX frame classes for ownership correlation. */
enum {
  T832_DIAG_TXCLS_OTHER = 0,
  T832_DIAG_TXCLS_DIAG = 1,
  T832_DIAG_TXCLS_SYNC_SRSP = 2,
  T832_DIAG_TXCLS_NORMAL = 3,
  T832_DIAG_TXCLS_UNSOLICITED = 4
};

/* Early boot capture, called once from main() before driver/board init. */
void T832Diag_captureResetCauseEarly(uint32_t cause);
void T832Diag_init(uint8_t mtTaskId);
void T832Diag_taskScheduled(uint8_t taskId, uint32_t events);
void T832Diag_taskWork(uint8_t area, uint16_t detail);
void T832Diag_npiTaskWake(void);
void T832Diag_commandRx(uint8_t cmd0, uint8_t cmd1);
void T832Diag_commandDispatch(uint8_t cmd0, uint8_t cmd1);
void T832Diag_afDispatch(uint8_t cmd0, uint8_t cmd1, const uint8_t *frame, uint8_t frameLen);
void T832Diag_commandComplete(uint8_t cmd0, uint8_t cmd1, uint8_t status);
void T832Diag_responseQueued(uint8_t cmdType, uint8_t cmdId, uint8_t dataLen,
                             const uint8_t *payload);
void T832Diag_responseAllocFailed(uint8_t cmdType, uint8_t cmdId, uint16_t requested);
void T832Diag_npiTxQueuedOther(uint8_t cmd0, uint8_t cmd1, uint8_t dataLen);
void T832Diag_npiTxDequeue(uint8_t sof, uint8_t cmd0, uint8_t cmd1, uint8_t dataLen);
void T832Diag_npiTrap(uint16_t attempted, uint16_t available);
void T832Diag_npiAllocFailed(uint8_t site, uint16_t requested,
                             uint8_t cmd0, uint8_t cmd1, uint8_t len);
/* TX-path refusal inside NPITask_sendToHost / NPITask_processStackMsg.
 * stage: 1 frame NULL (sendToHost), 2 queue-record NULL (sendToHost),
 * 3 unsupported type (sendToHost), 4 frame NULL (processStackMsg),
 * 5 queue-record NULL (processStackMsg), 6 unsupported type (processStackMsg).
 * Site 1 of T832Diag_npiAllocFailed is the same TX path; site 2 is the
 * RX path (NPITask_sendBufToStack, ZStack RX) and never touches TX state. */
void T832Diag_npiTxRefused(uint8_t stage, uint8_t cmd0, uint8_t cmd1,
                           uint8_t len);
void T832Diag_uartConfigured(uint32_t baud, uint8_t flow);
void T832Diag_uartRx(uint16_t size, uint16_t occupancy);
void T832Diag_uartRxOverflow(uint16_t attempted, uint16_t occupancy);
void T832Diag_uartTxStart(uint16_t len);
void T832Diag_uartWriteRejected(uint16_t len, int16_t status);
void T832Diag_uartTxFinished(uint16_t len);
void T832Diag_startup(uint8_t stage, uint8_t cmd0, uint8_t cmd1);
void T832Diag_networkState(uint8_t onNetwork, uint8_t nwkState);
void T832Diag_bdb(uint8_t stage, uint16_t detail);
void T832Diag_rxBufferFull(void);
void T832Diag_nvEvent(uint8_t stage, uint16_t b, uint16_t c);
void T832Diag_nvInit(uint8_t action);
void T832Diag_exportPoll(void);

#endif
