/*
 * T832-DIAG-R0 recorder/exporter, schema 2.
 * Included once at the end of mt_debug.c so no project source-list change is needed.
 * Hot-path hooks: fixed writes only; no allocation, logging, flash, UART, or waits.
 * Heap sampling runs only in the 60 s RESOURCE tick (MT task context).
 * NPI_SREQRSP is not defined in the ZNP build (proven by linked-image audit),
 * so there is no NPI sync watchdog or sync queue in this image; the sync
 * lifecycle below is purely MT-side (SREQ rx -> SRSP dequeue -> SRSP TX finish).
 */
#include <stdint.h>
#include <string.h>
#include <ti/drivers/dpl/ClockP.h>
/* SysBIOS heap stats: ti/sysbios/runtime/Memory.h declares IHeap_Handle,
 * Memory_Stats and Memory_defaultHeapInstance. The same angle-bracket
 * kernel path style is already used by npi_task.c in this build, so this
 * resolves in mt_debug.c too (verified: the XDC variant of this header
 * resolves, and the sysbios package dir is the same include root). */
#include <ti/sysbios/runtime/Memory.h>
#include "t832_diag.h"
#include "mt_af.h"

#ifndef CODE_REVISION_NUMBER
#define CODE_REVISION_NUMBER 0u
#endif
#ifndef T832_BUILD_ID
#define T832_BUILD_ID ((uint32_t)CODE_REVISION_NUMBER)
#endif

#define T832_DIAG_CRITICAL_RECORDS 64u
#define T832_DIAG_ROUTINE_RECORDS 64u
#define T832_DIAG_EXPORT_MIN_MS 5000u
#define T832_DIAG_HEALTH_MS 10000u
#define T832_DIAG_RESOURCE_MS 60000u
#define T832_DIAG_PREFIX "T832D2:"
#define T832_DIAG_PREFIX_LEN 7u
#define T832_DIAG_NPI_SOF 0xFEu
#define T832_DIAG_TXQ_DEPTH 8u
#define T832_DIAG_AF_DEPTH 8u
#define T832_DIAG_FRAME_BIN_MAX 113u

typedef struct {
  uint32_t first_ms;
  uint32_t last_ms;
  uint16_t sequence;
  uint8_t kind;
  uint8_t flags;
  uint16_t a;
  uint16_t b;
  uint16_t c;
  uint16_t repeat_count;
} T832DiagRecord;

typedef struct {
  uint8_t cls;
  uint8_t cmd0;
  uint8_t cmd1;
  uint8_t len;
  uint16_t gen;
} T832DiagTxSlot;

typedef struct {
  uint8_t used;
  uint8_t src_ep;
  uint8_t trans_id;
  uint8_t origin;
  uint32_t ms;
  uint16_t gen;
} T832DiagAfSlot;

typedef struct {
  T832DiagRecord critical[T832_DIAG_CRITICAL_RECORDS];
  T832DiagRecord routine[T832_DIAG_ROUTINE_RECORDS];
  T832DiagRecord first_fault;
  T832DiagTxSlot txq[T832_DIAG_TXQ_DEPTH];
  T832DiagTxSlot inflight;
  T832DiagAfSlot af[T832_DIAG_AF_DEPTH];
  uint32_t last_tick;
  uint32_t tick_wraps;
  uint32_t tick_period_us;
  uint32_t export_sequence;
  uint32_t record_sequence;
  uint32_t capabilities;
  uint32_t last_export_ms;
  uint32_t last_health_ms;
  uint32_t last_resource_ms;
  uint32_t mt_sched_ms;
  uint32_t mt_work_ms;
  uint32_t npi_work_ms;
  uint32_t npi_task_ms;
  uint32_t npi_wake_count;
  uint32_t zstack_work_ms;
  uint32_t tx_start_ms;
  uint32_t oldest_pending_ms;
  uint32_t af_oldest_ms;
  uint32_t nv_start_ms;
  uint32_t mt_schedule_count;
  uint32_t mt_work_count;
  uint32_t npi_rx_count;
  uint32_t npi_tx_count;
  uint32_t rx_bytes;
  uint32_t tx_frames;
  uint32_t tx_diag_n;
  uint32_t tx_sync_n;
  uint32_t tx_normal_n;
  uint32_t tx_unsol_n;
  uint32_t tx_orphan_n;
  uint32_t tx_uncertain_n;
  uint32_t tx_overflow_n;
  uint32_t tx_untracked_n;
  uint32_t af_confirmed_n;
  uint32_t af_rejected_n;
  uint32_t export_lost;
  uint32_t last_health_schedule_count;
  uint32_t last_cmd_ms;
  uint32_t last_startup_ms;
  uint32_t first_fault_export_ms;
  uint32_t reset_cause;
  uint16_t critical_head;
  uint16_t critical_count;
  uint16_t routine_head;
  uint16_t routine_count;
  uint16_t critical_overwrite;
  uint16_t routine_overwrite;
  uint16_t export_skipped;
  uint16_t rx_high_water;
  uint16_t normal_pending;
  uint16_t normal_pending_max;
  uint16_t tx_age_max;
  uint16_t af_outstanding;
  uint16_t af_outstanding_max;
  uint16_t af_gen;
  uint16_t queue_gen;
  uint16_t sync_gen;
  uint16_t sync_seq;
  uint16_t af_unconfirmed_n;
  uint32_t af_accepted_n;
  uint32_t af_areq_n;
  uint16_t txq_head;
  uint16_t txq_count;
  uint16_t mt_last_events;
  uint16_t mt_sticky_events;
  uint16_t last_cmd;
  uint8_t mt_task_id;
  uint8_t last_startup_stage;
  uint8_t sync_outstanding;
  uint8_t response_queued;
  uint8_t diag_untracked;
  uint8_t zstack_work_valid;
  uint8_t early;
  uint8_t health_rr;
  uint8_t health_done;
  uint8_t diag_pending;
  uint8_t staged_count;
  uint8_t build_failed;
  uint8_t inflight_valid;
  uint8_t af_expect_valid;
  uint8_t af_expect_ep;
  uint8_t af_expect_trans;
  uint8_t transport_active;
  uint8_t first_fault_valid;
  uint8_t initialized;
  uint8_t res_ext_idx;
  uint8_t last_startup_cmd0;
  uint8_t last_startup_cmd1;
} T832DiagState;

_Static_assert(sizeof(T832DiagRecord) == 20u, "T832 diagnostic record must remain 20 bytes");
_Static_assert(sizeof(T832DiagState) <= 4096u, "T832 diagnostic static RAM budget exceeded");
_Static_assert(T832_DIAG_TXQ_DEPTH <= 16u, "TX ownership FIFO must stay bounded");
_Static_assert(T832_DIAG_AF_DEPTH <= 16u, "AF accept table must stay bounded");

/* Early boot capture, written once by main() before driver/board init. */
uint32_t t832DiagResetCauseEarly;
uint32_t t832DiagResetCauseMagic;
static T832DiagState t832Diag;

void T832Diag_captureResetCauseEarly(uint32_t cause)
{
  t832DiagResetCauseEarly = cause;
  t832DiagResetCauseMagic = (uint32_t)T832_DIAG_BOOT_MAGIC;
}

/* Lazily arm the recorder before the scheduler runs. NV init and recovery
 * hooks execute in main() before MT_TaskInit, so the first record request
 * initializes rings with an assumed 1 ms tick; MT init later absorbs (never
 * wipes) these early observations and marks their timing approximate. */
static void T832Diag_ensureEarly(void)
{
  if (t832Diag.initialized || t832Diag.early) return;
  memset(&t832Diag, 0, sizeof(t832Diag));
  t832Diag.tick_period_us = 1000u;
  t832Diag.early = 1u;
}

static uint64_t T832Diag_nowMs(void)
{
  uint32_t key;
  uint32_t tick;
  T832Diag_ensureEarly();
  key = OsalPort_enterCS();
  tick = ClockP_getSystemTicks();
  if (t832Diag.initialized && tick < t832Diag.last_tick) {
    t832Diag.tick_wraps++;
  }
  t832Diag.last_tick = tick;
  {
    uint64_t ext = (((uint64_t)t832Diag.tick_wraps) << 32) | tick;
    uint64_t ms = (ext * t832Diag.tick_period_us) / 1000u;
    OsalPort_leaveCS(key);
    return ms;
  }
}

static uint16_t T832Diag_sat16(uint32_t v)
{
  return v > 0xFFFFu ? 0xFFFFu : (uint16_t)v;
}

static uint8_t T832Diag_isCritical(uint8_t kind)
{
  return (kind == T832_DIAG_EV_NPI_RX_OVERFLOW ||
          kind == T832_DIAG_EV_NPI_WRITE_REJECT ||
          kind == T832_DIAG_EV_RESPONSE_ALLOC_FAIL ||
          kind == T832_DIAG_EV_FIRST_FAULT ||
          kind == T832_DIAG_EV_RX_BUFFER_FULL ||
          kind == T832_DIAG_EV_NV_FAULT ||
          kind == T832_DIAG_EV_NPI_TRAP);
}

static void T832Diag_record(uint8_t kind, uint16_t a, uint16_t b, uint16_t c)
{
  uint32_t ms = (uint32_t)T832Diag_nowMs();
  uint32_t key = OsalPort_enterCS();
  uint8_t critical = T832Diag_isCritical(kind);
  T832DiagRecord *ring = critical ? t832Diag.critical : t832Diag.routine;
  uint16_t cap = critical ? T832_DIAG_CRITICAL_RECORDS : T832_DIAG_ROUTINE_RECORDS;
  uint16_t *head = critical ? &t832Diag.critical_head : &t832Diag.routine_head;
  uint16_t *count = critical ? &t832Diag.critical_count : &t832Diag.routine_count;
  uint16_t *over = critical ? &t832Diag.critical_overwrite : &t832Diag.routine_overwrite;

  if (*count) {
    uint16_t last = (uint16_t)((*head + cap - 1u) % cap);
    T832DiagRecord *r = &ring[last];
    if (critical && r->kind == kind && r->a == a && r->b == b && r->c == c) {
      r->last_ms = ms;
      if (r->repeat_count != 0xFFFFu) r->repeat_count++;
      OsalPort_leaveCS(key);
      return;
    }
  }

  T832DiagRecord *r = &ring[*head];
  r->first_ms = ms;
  r->last_ms = ms;
  r->sequence = (uint16_t)(++t832Diag.record_sequence);
  r->kind = kind;
  r->flags = critical ? 1u : 0u;
  r->a = a;
  r->b = b;
  r->c = c;
  r->repeat_count = 1u;
  *head = (uint16_t)((*head + 1u) % cap);
  if (*count < cap) (*count)++; else (*over)++;

  if (critical && !t832Diag.first_fault_valid) {
    t832Diag.first_fault = *r;
    t832Diag.first_fault_valid = 1u;
  }
  OsalPort_leaveCS(key);
}

void T832Diag_init(uint8_t mtTaskId)
{
  uint8_t boot_valid = (t832DiagResetCauseMagic == (uint32_t)T832_DIAG_BOOT_MAGIC);
  uint32_t cause = boot_valid ? t832DiagResetCauseEarly : 0xFFFFFFFFu;
  /* Absorb, never wipe: NV init/recovery hooks in main() run before MT init
   * and their records (rings, first fault, sequence) survive here. Only a
   * cold recorder with no early observations is zeroed. */
  uint8_t had_early = (uint8_t)(t832Diag.early && !t832Diag.initialized);
  uint32_t pre_sched = t832Diag.record_sequence;
  if (!had_early) {
    memset(&t832Diag, 0, sizeof(t832Diag));
  }
  t832Diag.tick_period_us = ClockP_getSystemTickPeriod();
  if (!t832Diag.tick_period_us) t832Diag.tick_period_us = 1000u;
  t832Diag.mt_task_id = mtTaskId;
  t832Diag.capabilities =
      T832_DIAG_CAP_STARTUP | T832_DIAG_CAP_BDB |
      T832_DIAG_CAP_MT_PROGRESS | T832_DIAG_CAP_NPI_PROGRESS |
      T832_DIAG_CAP_RX_OVERFLOW | T832_DIAG_CAP_TX_FINISHED |
      T832_DIAG_CAP_COMMAND_PATH | T832_DIAG_CAP_SYNC_GATE |
      T832_DIAG_CAP_RX_HWM | T832_DIAG_CAP_QUEUE_APPROX |
      T832_DIAG_CAP_RESET_CAUSE | T832_DIAG_CAP_NETWORK_STATE |
      T832_DIAG_CAP_AGG_COUNTERS | T832_DIAG_CAP_MT_EVENTS |
      T832_DIAG_CAP_NV_COMPACT | T832_DIAG_CAP_AF_AGE |
      T832_DIAG_CAP_ZSTACK_TASK | T832_DIAG_CAP_NPI_TASK |
      T832_DIAG_CAP_HEAP_STATS | T832_DIAG_CAP_TX_OWNERSHIP |
      T832_DIAG_CAP_AF_ACCEPT | T832_DIAG_CAP_BATCHED_V2;
  t832Diag.reset_cause = cause;
  t832Diag.initialized = 1u;
  t832Diag.early = 0u;
  /* The memset above runs at MT init, after main() captured the cause. */
  T832Diag_record(T832_DIAG_EV_BOOT, (uint16_t)cause,
                  mtTaskId, boot_valid ? 1u : 0u);
  if (!boot_valid) {
    T832Diag_record(T832_DIAG_EV_BOOT_CAPTURE_INVALID, 0u, mtTaskId, 0u);
  }
  if (had_early && pre_sched) {
    /* Early records used the assumed 1 ms tick before the scheduler ran:
     * keep them, but mark their timing approximate with an honest count. */
    T832Diag_record(T832_DIAG_EV_TIMING_APPROX,
                    T832Diag_sat16(pre_sched), mtTaskId, 0u);
  }
}

void T832Diag_taskScheduled(uint8_t taskId, uint32_t events)
{
  t832Diag.mt_sched_ms = (uint32_t)T832Diag_nowMs();
  t832Diag.mt_schedule_count++;
  t832Diag.mt_last_events = (uint16_t)events;
  t832Diag.mt_sticky_events |= (uint16_t)events;
  (void)taskId;
}

void T832Diag_taskWork(uint8_t area, uint16_t detail)
{
  uint32_t now = (uint32_t)T832Diag_nowMs();
  if (area == T832_DIAG_WORK_MT) {
    t832Diag.mt_work_ms = now;
    t832Diag.mt_work_count++;
  } else if (area == T832_DIAG_WORK_NPI) {
    t832Diag.npi_work_ms = now;
  } else if (area == T832_DIAG_WORK_ZSTACK) {
    /* Genuine ZStack-task context (ZStackTaskProcessEvent): the only MT-side
     * caller was removed, so this timestamp is real stack-task progress. */
    t832Diag.zstack_work_ms = now;
    t832Diag.zstack_work_valid = 1u;
  }
  (void)detail;
}

void T832Diag_npiTaskWake(void)
{
  t832Diag.npi_task_ms = (uint32_t)T832Diag_nowMs();
  t832Diag.npi_wake_count++;
}

void T832Diag_commandRx(uint8_t cmd0, uint8_t cmd1)
{
  if ((cmd0 & MT_RPC_CMD_TYPE_MASK) == MT_RPC_CMD_SREQ) {
    if (t832Diag.sync_outstanding) {
      T832Diag_record(T832_DIAG_EV_SYNC_ABANDON, 1u, cmd0, cmd1);
    }
    /* A newer SREQ takes over suppression with a fresh generation. Only the
     * SRSP stamped with this generation may clear it (see responseQueued /
     * uartTxFinished); an older SRSP that finishes late is reported stale
     * and leaves suppression set. */
    if (t832Diag.sync_seq != 0xFFFFu) t832Diag.sync_seq++;
    else t832Diag.sync_seq = 1u;
    t832Diag.sync_gen = t832Diag.sync_seq;
    t832Diag.sync_outstanding = 1u;
    t832Diag.response_queued = 0u;
  }
  t832Diag.last_cmd = (uint16_t)(((uint16_t)cmd0 << 8) | cmd1);
  t832Diag.last_cmd_ms = (uint32_t)T832Diag_nowMs();
  T832Diag_record(T832_DIAG_EV_MT_COMMAND_RX, cmd0, cmd1, t832Diag.sync_outstanding);
}

static uint8_t T832Diag_isAfDataRequest(uint8_t cmd0, uint8_t cmd1)
{
  uint8_t type = (uint8_t)(cmd0 & MT_RPC_CMD_TYPE_MASK);
  if ((cmd0 & MT_RPC_SUBSYSTEM_MASK) != MT_RPC_SYS_AF) return 0u;
  if (type != MT_RPC_CMD_SREQ && type != MT_RPC_CMD_AREQ) return 0u;
  return (uint8_t)(cmd1 == MT_AF_DATA_REQUEST ||
                   cmd1 == MT_AF_DATA_REQUEST_EXT ||
                   cmd1 == MT_AF_DATA_REQUEST_SRCRTG);
}

/* Parse (srcEp, transID) from an AF DATA_REQUEST payload. Returns 1 on success.
 * Layouts verified against pinned mt_af.c: 0x01/0x03 share head offsets
 * (dstEp[2], srcEp[3], cluster[4..5], trans[6]); 0x02 EXT uses
 * (dstEp[9], panId[10..11], srcEp[12], cluster[13..14], trans[15]). */
static uint8_t T832Diag_afParse(const uint8_t *pl, uint8_t len, uint8_t cmd1,
                                uint8_t *srcEp, uint8_t *transId)
{
  if (cmd1 == MT_AF_DATA_REQUEST || cmd1 == MT_AF_DATA_REQUEST_SRCRTG) {
    if (len < 7u || pl == 0) return 0u;
    *srcEp = pl[3];
    *transId = pl[6];
    return 1u;
  }
  if (cmd1 == MT_AF_DATA_REQUEST_EXT) {
    if (len < 16u || pl == 0) return 0u;
    *srcEp = pl[12];
    *transId = pl[15];
    return 1u;
  }
  return 0u;
}

/* Oldest request time over the used entries, by largest unsigned age from
 * now so tick wrap cannot invert it; caller holds the section. */
static uint32_t T832Diag_afOldestLocked(uint32_t now)
{
  uint8_t i;
  uint32_t oldest = 0u;
  uint32_t oldest_age = 0u;
  uint8_t found = 0u;
  for (i = 0; i < T832_DIAG_AF_DEPTH; i++) {
    if (t832Diag.af[i].used) {
      uint32_t age = now - t832Diag.af[i].ms;
      if (!found || age > oldest_age) {
        oldest = t832Diag.af[i].ms;
        oldest_age = age;
        found = 1u;
      }
    }
  }
  return found ? oldest : 0u;
}

static void T832Diag_afInsert(uint8_t srcEp, uint8_t transId, uint8_t origin)
{
  uint32_t key = OsalPort_enterCS();
  uint32_t now = (uint32_t)T832Diag_nowMs();
  uint8_t i;
  uint8_t free = T832_DIAG_AF_DEPTH;
  uint8_t victim = 0u;
  uint32_t victim_age = 0u;
  for (i = 0; i < T832_DIAG_AF_DEPTH; i++) {
    if (t832Diag.af[i].used &&
        t832Diag.af[i].src_ep == srcEp &&
        t832Diag.af[i].trans_id == transId) {
      /* Reuse supersedes in place: refresh time/generation, keep one entry.
       * No phantom is left behind for the confirm to miss. */
      if (t832Diag.af[i].origin != origin) {
        if (origin == 2u) {
          if (t832Diag.af_unconfirmed_n != 0xFFFFu) t832Diag.af_unconfirmed_n++;
        } else if (t832Diag.af_unconfirmed_n) {
          t832Diag.af_unconfirmed_n--;
        }
        t832Diag.af[i].origin = origin;
      }
      t832Diag.af[i].ms = now;
      t832Diag.af[i].gen = ++t832Diag.af_gen;
      t832Diag.af_oldest_ms = T832Diag_afOldestLocked(now);
      OsalPort_leaveCS(key);
      T832Diag_record(T832_DIAG_EV_AF_ANOMALY, 5u, srcEp, transId);
      return;
    }
  }
  for (i = 0; i < T832_DIAG_AF_DEPTH; i++) {
    if (!t832Diag.af[i].used) { free = i; break; }
    /* Wrap-safe age: unsigned subtraction, largest age is evicted. */
    if ((uint32_t)(now - t832Diag.af[i].ms) >= victim_age) {
      victim_age = (uint32_t)(now - t832Diag.af[i].ms);
      victim = i;
    }
  }
  if (free == T832_DIAG_AF_DEPTH) {
    if (t832Diag.af[victim].origin == 2u && t832Diag.af_unconfirmed_n) {
      t832Diag.af_unconfirmed_n--;
    }
    OsalPort_leaveCS(key);
    T832Diag_record(T832_DIAG_EV_AF_ANOMALY, 4u,
                    t832Diag.af[victim].src_ep, t832Diag.af[victim].trans_id);
    key = OsalPort_enterCS();
    free = victim;
    if (t832Diag.af_outstanding) t832Diag.af_outstanding--;
  }
  t832Diag.af[free].used = 1u;
  t832Diag.af[free].src_ep = srcEp;
  t832Diag.af[free].trans_id = transId;
  t832Diag.af[free].origin = origin;
  t832Diag.af[free].ms = now;
  t832Diag.af[free].gen = ++t832Diag.af_gen;
  if (origin == 1u) {
    if (t832Diag.af_accepted_n != 0xFFFFFFFFu) t832Diag.af_accepted_n++;
  } else {
    if (t832Diag.af_areq_n != 0xFFFFFFFFu) t832Diag.af_areq_n++;
    if (t832Diag.af_unconfirmed_n != 0xFFFFu) t832Diag.af_unconfirmed_n++;
  }
  if (!t832Diag.af_outstanding) {
    t832Diag.af_oldest_ms = t832Diag.af[free].ms;
  }
  if (t832Diag.af_outstanding != 0xFFFFu) t832Diag.af_outstanding++;
  if (t832Diag.af_outstanding > t832Diag.af_outstanding_max) {
    t832Diag.af_outstanding_max = t832Diag.af_outstanding;
  }
  OsalPort_leaveCS(key);
}

static void T832Diag_afRemove(uint8_t idx)
{
  uint32_t key = OsalPort_enterCS();
  uint32_t now = (uint32_t)T832Diag_nowMs();
  if (t832Diag.af[idx].origin == 2u && t832Diag.af_unconfirmed_n) {
    t832Diag.af_unconfirmed_n--;
  }
  t832Diag.af[idx].used = 0u;
  if (t832Diag.af_outstanding) {
    t832Diag.af_outstanding--;
  }
  /* Recompute from the survivors: the age must track the oldest remaining
   * request, never a completed one. */
  t832Diag.af_oldest_ms = T832Diag_afOldestLocked(now);
  OsalPort_leaveCS(key);
}

void T832Diag_afDispatch(uint8_t cmd0, uint8_t cmd1, const uint8_t *frame, uint8_t frameLen)
{
  uint8_t srcEp = 0u;
  uint8_t transId = 0u;
  uint8_t type;
  if (!T832Diag_isAfDataRequest(cmd0, cmd1)) return;
  if (frameLen < MT_RPC_FRAME_HDR_SZ) return;
  type = (uint8_t)(cmd0 & MT_RPC_CMD_TYPE_MASK);
  if (!T832Diag_afParse(frame + MT_RPC_FRAME_HDR_SZ,
                        (uint8_t)(frameLen - MT_RPC_FRAME_HDR_SZ),
                        cmd1, &srcEp, &transId)) {
    T832Diag_record(T832_DIAG_EV_AF_ANOMALY, 7u, cmd0, cmd1);
    return;
  }
  if (type == MT_RPC_CMD_SREQ) {
    t832Diag.af_expect_valid = 1u;
    t832Diag.af_expect_ep = srcEp;
    t832Diag.af_expect_trans = transId;
  } else {
    /* AREQ requests carry no SRSP status; tracked as unconfirmed acceptance. */
    T832Diag_afInsert(srcEp, transId, 2u);
  }
}

static void T832Diag_afSrspResult(uint8_t status)
{
  if (!t832Diag.af_expect_valid) {
    T832Diag_record(T832_DIAG_EV_AF_ANOMALY, 6u, 0u, status);
    return;
  }
  t832Diag.af_expect_valid = 0u;
  if (status == 0u) {
    T832Diag_afInsert(t832Diag.af_expect_ep, t832Diag.af_expect_trans, 1u);
  } else {
    if (t832Diag.af_rejected_n != 0xFFFFFFFFu) t832Diag.af_rejected_n++;
    T832Diag_record(T832_DIAG_EV_AF_REJECT,
                    t832Diag.af_expect_ep, t832Diag.af_expect_trans, status);
  }
}

static void T832Diag_afConfirm(uint8_t status, uint8_t ep, uint8_t transId)
{
  uint8_t i;
  for (i = 0; i < T832_DIAG_AF_DEPTH; i++) {
    if (t832Diag.af[i].used &&
        t832Diag.af[i].src_ep == ep &&
        t832Diag.af[i].trans_id == transId) {
      T832Diag_afRemove(i);
      if (status == 0u) {
        if (t832Diag.af_confirmed_n != 0xFFFFFFFFu) t832Diag.af_confirmed_n++;
      } else {
        /* Failed delivery keeps its raw status: a reject, not a confirm. */
        if (t832Diag.af_rejected_n != 0xFFFFFFFFu) t832Diag.af_rejected_n++;
        T832Diag_record(T832_DIAG_EV_AF_REJECT, ep, transId, status);
      }
      return;
    }
  }
  T832Diag_record(T832_DIAG_EV_AF_ANOMALY, 1u, ep, transId);
}

void T832Diag_commandDispatch(uint8_t cmd0, uint8_t cmd1)
{
  T832Diag_record(T832_DIAG_EV_MT_COMMAND_DISPATCH, cmd0, cmd1, 0u);
}

void T832Diag_commandComplete(uint8_t cmd0, uint8_t cmd1, uint8_t status)
{
  /* AF acceptance comes only from the SRSP payload / confirm path, never
   * from the RPC handler return, so completion only records the stage. */
  T832Diag_record(T832_DIAG_EV_MT_COMMAND_COMPLETE, cmd0, cmd1, status);
}

static uint8_t T832Diag_isDiagFrame(uint8_t cmdType, uint8_t cmdId)
{
  return (uint8_t)(((cmdType & MT_RPC_SUBSYSTEM_MASK) == MT_RPC_SYS_DBG) &&
                   ((cmdType & MT_RPC_CMD_TYPE_MASK) == MT_RPC_CMD_AREQ) &&
                   (cmdId == MT_DEBUG_MSG));
}

/* Ownership push. Returns 1 when the descriptor was stored, 0 when the
 * 8-slot shadow FIFO is full. A refused frame stays in the real NPI queue
 * (which this recorder never alters); its later wire completion arrives
 * without a descriptor and is counted explicitly untracked. The oldest
 * tracked descriptor is never evicted, so pending always equals the number
 * of stored descriptors and no ghost count can accumulate. */
static uint8_t T832Diag_txPush(uint8_t cls, uint8_t cmd0, uint8_t cmd1, uint8_t len)
{
  uint32_t key = OsalPort_enterCS();
  uint16_t slot;
  uint8_t stored;
  if (t832Diag.txq_count >= T832_DIAG_TXQ_DEPTH) {
    OsalPort_leaveCS(key);
    if (t832Diag.tx_overflow_n != 0xFFFFFFFFu) t832Diag.tx_overflow_n++;
    T832Diag_record(T832_DIAG_EV_TX_MISMATCH, 5u, cmd0, cmd1);
    return 0u;
  }
  slot = (uint16_t)((t832Diag.txq_head + t832Diag.txq_count) % T832_DIAG_TXQ_DEPTH);
  t832Diag.txq_count++;
  t832Diag.txq[slot].cls = cls;
  t832Diag.txq[slot].cmd0 = cmd0;
  t832Diag.txq[slot].cmd1 = cmd1;
  t832Diag.txq[slot].len = len;
  t832Diag.txq[slot].gen = ++t832Diag.queue_gen;
  stored = 1u;
  OsalPort_leaveCS(key);
  return stored;
}

static void T832Diag_pendingInc(void)
{
  uint32_t key = OsalPort_enterCS();
  if (t832Diag.normal_pending == 0u) {
    t832Diag.oldest_pending_ms = (uint32_t)T832Diag_nowMs();
  }
  if (t832Diag.normal_pending != 0xFFFFu) t832Diag.normal_pending++;
  if (t832Diag.normal_pending > t832Diag.normal_pending_max) {
    t832Diag.normal_pending_max = t832Diag.normal_pending;
  }
  OsalPort_leaveCS(key);
}

/* Release one owned descriptor without inventing delivery. Returns 1 when a
 * matching descriptor was removed (pending decremented, loss counted), 0
 * when the frame was never tracked. */
static uint8_t T832Diag_txRelease(uint8_t cmd0, uint8_t cmd1, uint8_t len,
                                  uint8_t reason)
{
  uint32_t key = OsalPort_enterCS();
  uint16_t i;
  for (i = 0u; i < t832Diag.txq_count; i++) {
    uint16_t slot = (uint16_t)((t832Diag.txq_head + i) % T832_DIAG_TXQ_DEPTH);
    if (t832Diag.txq[slot].cmd0 == cmd0 &&
        t832Diag.txq[slot].cmd1 == cmd1 &&
        t832Diag.txq[slot].len == len) {
      uint16_t j;
      uint8_t cls = t832Diag.txq[slot].cls;
      for (j = i; j + 1u < t832Diag.txq_count; j++) {
        uint16_t dst = (uint16_t)((t832Diag.txq_head + j) % T832_DIAG_TXQ_DEPTH);
        uint16_t src = (uint16_t)((t832Diag.txq_head + j + 1u) % T832_DIAG_TXQ_DEPTH);
        t832Diag.txq[dst] = t832Diag.txq[src];
      }
      t832Diag.txq_count--;
      if (cls == T832_DIAG_TXCLS_SYNC_SRSP ||
          cls == T832_DIAG_TXCLS_NORMAL) {
        if (t832Diag.normal_pending) {
          t832Diag.normal_pending--;
          if (!t832Diag.normal_pending) t832Diag.oldest_pending_ms = 0u;
        }
      }
      OsalPort_leaveCS(key);
      if (reason == 1u) {
        if (t832Diag.tx_orphan_n != 0xFFFFFFFFu) t832Diag.tx_orphan_n++;
      } else {
        if (t832Diag.tx_uncertain_n != 0xFFFFFFFFu) t832Diag.tx_uncertain_n++;
      }
      T832Diag_record(T832_DIAG_EV_TX_MISMATCH,
                      reason == 1u ? 12u : 13u, cmd0, cmd1);
      return 1u;
    }
  }
  OsalPort_leaveCS(key);
  return 0u;
}

void T832Diag_responseQueued(uint8_t cmdType, uint8_t cmdId, uint8_t dataLen,
                             const uint8_t *payload)
{
  uint8_t isSrsp = (uint8_t)(((cmdType & MT_RPC_CMD_TYPE_MASK) == MT_RPC_CMD_SRSP));
  if (T832Diag_isDiagFrame(cmdType, cmdId)) {
    if (t832Diag.diag_pending) {
      T832Diag_record(T832_DIAG_EV_TX_MISMATCH, 6u, cmdType, cmdId);
    }
    t832Diag.diag_pending = 1u;
    if (!T832Diag_txPush(T832_DIAG_TXCLS_DIAG, cmdType, cmdId, dataLen)) {
      /* Shadow full: the real frame still flies untracked. Flag it so its
       * untracked wire completion can release diag_pending exactly once. */
      t832Diag.diag_untracked = 1u;
    }
    return;
  }
  if (isSrsp) {
    t832Diag.response_queued = 1u;
    if (T832Diag_txPush(T832_DIAG_TXCLS_SYNC_SRSP, cmdType, cmdId, dataLen)) {
      /* Stamp the current SREQ generation on this SRSP: only the completion
       * carrying it may clear suppression (see uartTxFinished). */
      uint32_t key = OsalPort_enterCS();
      uint16_t slot = (uint16_t)((t832Diag.txq_head + t832Diag.txq_count - 1u) %
                                 T832_DIAG_TXQ_DEPTH);
      t832Diag.txq[slot].gen = t832Diag.sync_gen;
      OsalPort_leaveCS(key);
      T832Diag_pendingInc();
    }
    if (((cmdType & MT_RPC_SUBSYSTEM_MASK) == MT_RPC_SYS_AF) &&
        (cmdId == MT_AF_DATA_REQUEST || cmdId == MT_AF_DATA_REQUEST_EXT ||
         cmdId == MT_AF_DATA_REQUEST_SRCRTG) &&
        dataLen >= 1u && payload != 0) {
      T832Diag_afSrspResult(payload[0]);
    }
    T832Diag_record(T832_DIAG_EV_RESPONSE_QUEUED, cmdType, cmdId, dataLen);
    return;
  }
  if (((cmdType & MT_RPC_CMD_TYPE_MASK) == MT_RPC_CMD_AREQ) &&
      ((cmdType & MT_RPC_SUBSYSTEM_MASK) == MT_RPC_SYS_AF) &&
      cmdId == MT_AF_DATA_CONFIRM && dataLen >= 3u && payload != 0) {
    T832Diag_afConfirm(payload[0], payload[1], payload[2]);
  }
  if (T832Diag_txPush(T832_DIAG_TXCLS_NORMAL, cmdType, cmdId, dataLen)) {
    T832Diag_pendingInc();
  }
}

void T832Diag_responseAllocFailed(uint8_t cmdType, uint8_t cmdId, uint16_t requested)
{
  if (T832Diag_isDiagFrame(cmdType, cmdId)) {
    /* Our own telemetry build failed: flag for the exporter, never a fault. */
    t832Diag.build_failed = 1u;
    return;
  }
  T832Diag_record(T832_DIAG_EV_RESPONSE_ALLOC_FAIL, cmdType, cmdId, requested);
}

void T832Diag_npiTxQueuedOther(uint8_t cmd0, uint8_t cmd1, uint8_t dataLen)
{
  if (T832Diag_txPush(T832_DIAG_TXCLS_NORMAL, cmd0, cmd1, dataLen)) {
    T832Diag_pendingInc();
  }
}

/* Release a displaced in-flight descriptor without inventing delivery.
 * Caller holds the diagnostic critical section. */
static void T832Diag_inflightDisplacedLocked(void)
{
  uint8_t cls = t832Diag.inflight.cls;
  if (cls == T832_DIAG_TXCLS_SYNC_SRSP || cls == T832_DIAG_TXCLS_NORMAL) {
    if (t832Diag.normal_pending) {
      t832Diag.normal_pending--;
      if (!t832Diag.normal_pending) t832Diag.oldest_pending_ms = 0u;
    }
    if (t832Diag.tx_uncertain_n != 0xFFFFFFFFu) t832Diag.tx_uncertain_n++;
  } else if (cls == T832_DIAG_TXCLS_DIAG) {
    t832Diag.diag_pending = 0u;
    t832Diag.diag_untracked = 1u;
    if (t832Diag.export_lost != 0xFFFFFFFFu) t832Diag.export_lost++;
  }
  t832Diag.inflight_valid = 0u;
}

/* Dequeue ownership: the framed UART buffer is [SOF,LEN,CMD0,CMD1,...].
 * The SOF check keeps the framed-layout assumption falsifiable at runtime.
 * Matching rule: the head descriptor normally owns the wire frame. When it
 * does not, older descriptors are retired one by one as unknown-outcome
 * (their frames presumably completed unseen) until the matching descriptor
 * becomes head; a frame with no descriptor anywhere is an untracked wire
 * completion that touches no owned state. Counts always converge when the
 * real queue drains: no ghost pending can survive. */
void T832Diag_npiTxDequeue(uint8_t sof, uint8_t cmd0, uint8_t cmd1, uint8_t dataLen)
{
  uint32_t key = OsalPort_enterCS();
  uint16_t i;
  uint16_t match = T832_DIAG_TXQ_DEPTH;
  if (t832Diag.inflight_valid) {
    T832Diag_record(T832_DIAG_EV_TX_MISMATCH, 9u,
                    t832Diag.inflight.cmd0, t832Diag.inflight.cmd1);
    T832Diag_inflightDisplacedLocked();
  }
  if (sof != T832_DIAG_NPI_SOF) {
    OsalPort_leaveCS(key);
    T832Diag_record(T832_DIAG_EV_TX_MISMATCH, 1u, sof, cmd0);
    key = OsalPort_enterCS();
    t832Diag.inflight.cls = T832_DIAG_TXCLS_UNSOLICITED;
    t832Diag.inflight.cmd0 = cmd0;
    t832Diag.inflight.cmd1 = cmd1;
    t832Diag.inflight.len = dataLen;
    t832Diag.inflight_valid = 1u;
    /* Counted once at physical completion, not here: a bad-SOF dequeue may
     * never reach TX_FINISHED, and an untracked frame finishes exactly once. */
    OsalPort_leaveCS(key);
    return;
  }
  for (i = 0u; i < t832Diag.txq_count; i++) {
    uint16_t slot = (uint16_t)((t832Diag.txq_head + i) % T832_DIAG_TXQ_DEPTH);
    if (t832Diag.txq[slot].cmd0 == cmd0 &&
        t832Diag.txq[slot].cmd1 == cmd1 &&
        t832Diag.txq[slot].len == dataLen) {
      match = slot;
      break;
    }
  }
  if (match == T832_DIAG_TXQ_DEPTH) {
    OsalPort_leaveCS(key);
    if (t832Diag.tx_untracked_n != 0xFFFFFFFFu) t832Diag.tx_untracked_n++;
    T832Diag_record(T832_DIAG_EV_TX_MISMATCH, 10u, cmd0, cmd1);
    key = OsalPort_enterCS();
    if (t832Diag.diag_untracked) {
      t832Diag.diag_pending = 0u;
      t832Diag.diag_untracked = 0u;
    }
    t832Diag.inflight.cls = T832_DIAG_TXCLS_UNSOLICITED;
    t832Diag.inflight.cmd0 = cmd0;
    t832Diag.inflight.cmd1 = cmd1;
    t832Diag.inflight.len = dataLen;
    t832Diag.inflight_valid = 1u;
    OsalPort_leaveCS(key);
    return;
  }
  while (t832Diag.txq_head != match) {
    /* An older owned frame completed without its own dequeue observation:
     * release it as unknown-outcome, never as delivered. */
    t832Diag.txq_head = (uint16_t)((t832Diag.txq_head + 1u) % T832_DIAG_TXQ_DEPTH);
    t832Diag.txq_count--;
    if (t832Diag.normal_pending) {
      t832Diag.normal_pending--;
      if (!t832Diag.normal_pending) t832Diag.oldest_pending_ms = 0u;
    }
    if (t832Diag.tx_uncertain_n != 0xFFFFFFFFu) t832Diag.tx_uncertain_n++;
    OsalPort_leaveCS(key);
    T832Diag_record(T832_DIAG_EV_TX_MISMATCH, 2u, cmd0, cmd1);
    key = OsalPort_enterCS();
  }
  t832Diag.inflight = t832Diag.txq[t832Diag.txq_head];
  t832Diag.txq_head = (uint16_t)((t832Diag.txq_head + 1u) % T832_DIAG_TXQ_DEPTH);
  t832Diag.txq_count--;
  t832Diag.inflight_valid = 1u;
  OsalPort_leaveCS(key);
}

void T832Diag_npiTrap(uint16_t attempted, uint16_t available)
{
  T832Diag_record(T832_DIAG_EV_NPI_TRAP, attempted, available, t832Diag.rx_high_water);
}

/* Allocation refusal at a patched SDK site. Site 1 is the NPI TX path
 * (NPITask_sendToHost / NPITask_processStackMsg): a previously queued owned
 * frame never reaches the wire, so exactly that entry is released. Site 2 is
 * the NPI RX path (NPITask_sendBufToStack inbound allocation, ZStack RX
 * allocation): the MT command never fired, so no TX ownership is involved
 * and pending state is never touched. */
void T832Diag_npiAllocFailed(uint8_t site, uint16_t requested,
                             uint8_t cmd0, uint8_t cmd1, uint8_t len)
{
  uint8_t owned;
  T832Diag_record(T832_DIAG_EV_NPI_ALLOC_FAIL, site, requested, 0u);
  if (site != 1u) return;
  if (T832Diag_isDiagFrame(cmd0, cmd1)) {
    t832Diag.diag_pending = 0u;
    if (t832Diag.export_lost != 0xFFFFFFFFu) t832Diag.export_lost++;
    T832Diag_record(T832_DIAG_EV_DIAG_LOSS, 1u, 2u, requested);
    T832Diag_txRelease(cmd0, cmd1, len, 1u);
    return;
  }
  if (((cmd0 & MT_RPC_CMD_TYPE_MASK) == MT_RPC_CMD_SRSP)) {
    t832Diag.response_queued = 0u;
  }
  owned = T832Diag_txRelease(cmd0, cmd1, len, 1u);
  if (!owned) {
    T832Diag_record(T832_DIAG_EV_TX_MISMATCH, 14u, cmd0, cmd1);
  }
}

/* TX-path refusal with an explicit stage (see t832_diag.h). Behaves as a
 * site-1 allocation failure: only the owned queued entry is reconciled. */
void T832Diag_npiTxRefused(uint8_t stage, uint8_t cmd0, uint8_t cmd1,
                           uint8_t len)
{
  uint8_t owned;
  T832Diag_record(T832_DIAG_EV_NPI_ALLOC_FAIL, 1u, stage, len);
  if (T832Diag_isDiagFrame(cmd0, cmd1)) {
    t832Diag.diag_pending = 0u;
    if (t832Diag.export_lost != 0xFFFFFFFFu) t832Diag.export_lost++;
    T832Diag_record(T832_DIAG_EV_DIAG_LOSS, 1u, 3u, stage);
    T832Diag_txRelease(cmd0, cmd1, len, 1u);
    return;
  }
  if (((cmd0 & MT_RPC_CMD_TYPE_MASK) == MT_RPC_CMD_SRSP)) {
    t832Diag.response_queued = 0u;
  }
  owned = T832Diag_txRelease(cmd0, cmd1, len, 1u);
  if (!owned) {
    T832Diag_record(T832_DIAG_EV_TX_MISMATCH, 14u, cmd0, cmd1);
  }
}

void T832Diag_uartConfigured(uint32_t baud, uint8_t flow)
{
  T832Diag_record(T832_DIAG_EV_TRANSPORT_CONFIG, (uint16_t)(baud / 100u), flow, 0u);
}

void T832Diag_uartRx(uint16_t size, uint16_t occupancy)
{
  if (occupancy > t832Diag.rx_high_water) t832Diag.rx_high_water = occupancy;
  t832Diag.npi_work_ms = (uint32_t)T832Diag_nowMs();
  if (t832Diag.rx_bytes <= 0xFFFFFFFFu - size) t832Diag.rx_bytes += size;
  else t832Diag.rx_bytes = 0xFFFFFFFFu;
  t832Diag.npi_rx_count += size;
}

void T832Diag_uartRxOverflow(uint16_t attempted, uint16_t occupancy)
{
  T832Diag_record(T832_DIAG_EV_NPI_RX_OVERFLOW, attempted, occupancy, t832Diag.rx_high_water);
}

void T832Diag_uartTxStart(uint16_t len)
{
  t832Diag.transport_active = 1u;
  t832Diag.tx_start_ms = (uint32_t)T832Diag_nowMs();
  (void)len;
}

void T832Diag_uartWriteRejected(uint16_t len, int16_t status)
{
  uint32_t key = OsalPort_enterCS();
  t832Diag.transport_active = 0u;
  if (t832Diag.inflight_valid) {
    /* A rejected write transmits nothing: the in-flight ownership is
     * released as refused, never completed, and the slot is closed so a
     * later TX_FINISHED cannot double-count it. */
    uint8_t cls = t832Diag.inflight.cls;
    uint8_t c0 = t832Diag.inflight.cmd0;
    uint8_t c1 = t832Diag.inflight.cmd1;
    if (cls == T832_DIAG_TXCLS_SYNC_SRSP || cls == T832_DIAG_TXCLS_NORMAL) {
      if (t832Diag.normal_pending) {
        t832Diag.normal_pending--;
        if (!t832Diag.normal_pending) t832Diag.oldest_pending_ms = 0u;
      }
      if (t832Diag.tx_orphan_n != 0xFFFFFFFFu) t832Diag.tx_orphan_n++;
    } else if (cls == T832_DIAG_TXCLS_DIAG) {
      t832Diag.diag_pending = 0u;
      if (t832Diag.export_lost != 0xFFFFFFFFu) t832Diag.export_lost++;
    }
    t832Diag.inflight_valid = 0u;
    OsalPort_leaveCS(key);
    T832Diag_record(T832_DIAG_EV_TX_MISMATCH, 11u, c0, c1);
  } else {
    OsalPort_leaveCS(key);
  }
  T832Diag_record(T832_DIAG_EV_NPI_WRITE_REJECT, len, (uint16_t)status, 0u);
}

void T832Diag_uartTxFinished(uint16_t len)
{
  uint32_t key = OsalPort_enterCS();
  uint16_t age = (uint16_t)((uint32_t)T832Diag_nowMs() - t832Diag.tx_start_ms);
  t832Diag.transport_active = 0u;
  t832Diag.npi_work_ms = (uint32_t)T832Diag_nowMs();
  t832Diag.npi_tx_count++;
  if (t832Diag.tx_frames != 0xFFFFFFFFu) t832Diag.tx_frames++;
  if (age > t832Diag.tx_age_max) t832Diag.tx_age_max = age;
  if (!t832Diag.inflight_valid) {
    OsalPort_leaveCS(key);
    if (t832Diag.tx_untracked_n != 0xFFFFFFFFu) t832Diag.tx_untracked_n++;
    T832Diag_record(T832_DIAG_EV_TX_MISMATCH, 7u, len, age);
    return;
  }
  if (t832Diag.inflight.cls == T832_DIAG_TXCLS_DIAG) {
    t832Diag.diag_pending = 0u;
    if (t832Diag.tx_diag_n != 0xFFFFFFFFu) t832Diag.tx_diag_n++;
  } else if (t832Diag.inflight.cls == T832_DIAG_TXCLS_SYNC_SRSP) {
    /* Only the SRSP stamped with the current SREQ generation clears
     * suppression. A late older SRSP is reported stale and leaves a newer
     * round-trip suppressed; its pending accounting still resolves. */
    if (t832Diag.inflight.gen == t832Diag.sync_gen) {
      t832Diag.sync_outstanding = 0u;
      t832Diag.response_queued = 0u;
    } else {
      OsalPort_leaveCS(key);
      T832Diag_record(T832_DIAG_EV_SYNC_ABANDON, 2u,
                      t832Diag.inflight.cmd0, t832Diag.inflight.cmd1);
      key = OsalPort_enterCS();
    }
    if (t832Diag.tx_sync_n != 0xFFFFFFFFu) t832Diag.tx_sync_n++;
    if (t832Diag.normal_pending) {
      t832Diag.normal_pending--;
      if (!t832Diag.normal_pending) t832Diag.oldest_pending_ms = 0u;
    }
    T832Diag_record(T832_DIAG_EV_NPI_TX_FINISHED, len, age, t832Diag.normal_pending);
  } else if (t832Diag.inflight.cls == T832_DIAG_TXCLS_NORMAL) {
    if (t832Diag.tx_normal_n != 0xFFFFFFFFu) t832Diag.tx_normal_n++;
    if (t832Diag.normal_pending) {
      t832Diag.normal_pending--;
      if (!t832Diag.normal_pending) t832Diag.oldest_pending_ms = 0u;
    } else {
      OsalPort_leaveCS(key);
      T832Diag_record(T832_DIAG_EV_TX_MISMATCH, 4u, len, age);
      key = OsalPort_enterCS();
    }
  } else {
    if (t832Diag.tx_unsol_n != 0xFFFFFFFFu) t832Diag.tx_unsol_n++;
  }
  t832Diag.inflight_valid = 0u;
  OsalPort_leaveCS(key);
  (void)len;
}

void T832Diag_startup(uint8_t stage, uint8_t cmd0, uint8_t cmd1)
{
  uint8_t kind = T832_DIAG_EV_STARTUP_ENTRY;
  if (stage == 2u) kind = T832_DIAG_EV_STARTUP_BDB_REQUEST;
  else if (stage == 3u) kind = T832_DIAG_EV_STARTUP_BDB_RETURN;
  else if (stage == 4u) kind = T832_DIAG_EV_STARTUP_SRSP_QUEUE;
  /* MT-task context (mt_zdo.c): observes startup stages only. It must not
   * refresh zstack_work_ms; genuine ZStack progress comes from the ZStack
   * task hooks (taskWork/bdb), and its age renders unknown until observed. */
  t832Diag.last_startup_stage = stage;
  t832Diag.last_startup_ms = (uint32_t)T832Diag_nowMs();
  t832Diag.last_startup_cmd0 = cmd0;
  t832Diag.last_startup_cmd1 = cmd1;
  T832Diag_record(kind, cmd0, cmd1, stage);
}

void T832Diag_networkState(uint8_t onNetwork, uint8_t nwkState)
{
  T832Diag_record(T832_DIAG_EV_NETWORK_STATE, onNetwork, nwkState, 0u);
}

void T832Diag_bdb(uint8_t stage, uint16_t detail)
{
  /* ZStack-task context (zstacktask.c): genuine stack progress. */
  t832Diag.zstack_work_ms = (uint32_t)T832Diag_nowMs();
  t832Diag.zstack_work_valid = 1u;
  T832Diag_record(stage == 1u ? T832_DIAG_EV_BDB_DISPATCH : T832_DIAG_EV_BDB_RETURN,
                  stage, detail, 0u);
}

void T832Diag_rxBufferFull(void)
{
  T832Diag_record(T832_DIAG_EV_RX_BUFFER_FULL, 0u, 0u, 0u);
}

void T832Diag_nvEvent(uint8_t stage, uint16_t b, uint16_t c)
{
  (void)c;
  if (stage == 1u) {
    t832Diag.nv_start_ms = (uint32_t)T832Diag_nowMs();
    T832Diag_record(T832_DIAG_EV_NV_EVENT, 1u, b, 0u);
  } else if (stage == 2u || stage == 3u) {
    uint16_t dur = (uint16_t)((uint32_t)T832Diag_nowMs() - t832Diag.nv_start_ms);
    T832Diag_record(stage == 3u ? T832_DIAG_EV_NV_FAULT : T832_DIAG_EV_NV_EVENT,
                    stage, b, dur);
  } else if (stage == 4u) {
    T832Diag_record(T832_DIAG_EV_NV_FAULT, 4u, b, 0u);
  }
}

void T832Diag_nvInit(uint8_t action)
{
  if (action >= 2u) {
    T832Diag_record(T832_DIAG_EV_NV_FAULT, 0u, action, 0u);
  } else {
    T832Diag_record(T832_DIAG_EV_NV_EVENT, 5u, action, 0u);
  }
}

/* Peek the oldest unstaged record: returns 1=critical, 2=routine, 0=empty.
 * skip_crit/skip_rout count records already staged from each ring during this
 * export, so successive peeks walk forward instead of returning the same
 * oldest record twice. Retirement stays deferred (T832Diag_popPeeked per
 * staged selector) so a refused MT build keeps the records queued; an ISR
 * record added between peek and retire only appends newer entries, which the
 * FIFO-order pops never touch. */
static uint8_t T832Diag_peekAt(uint8_t skip_crit, uint8_t skip_rout,
                               T832DiagRecord *out)
{
  uint32_t key = OsalPort_enterCS();
  uint8_t sel = 0u;

  if (t832Diag.critical_count > skip_crit) {
    uint16_t tail = (uint16_t)((t832Diag.critical_head +
                                T832_DIAG_CRITICAL_RECORDS -
                                t832Diag.critical_count + skip_crit) %
                               T832_DIAG_CRITICAL_RECORDS);
    *out = t832Diag.critical[tail];
    sel = 1u;
  } else if (t832Diag.routine_count > skip_rout) {
    uint16_t tail = (uint16_t)((t832Diag.routine_head +
                                T832_DIAG_ROUTINE_RECORDS -
                                t832Diag.routine_count + skip_rout) %
                               T832_DIAG_ROUTINE_RECORDS);
    *out = t832Diag.routine[tail];
    sel = 2u;
  }
  OsalPort_leaveCS(key);
  return sel;
}

/* Retire exactly the staged record by identity. If the ring has moved on
 * (a producer overwrote or coalesced the staged entry while MT allocated),
 * the staged copy is already stale: report the loss explicitly and retire
 * nothing, so unexported newer occurrences are never discarded. */
static void T832Diag_popPeeked(uint8_t sel, uint16_t seq)
{
  uint32_t key = OsalPort_enterCS();
  if (sel == 1u) {
    if (t832Diag.critical_count) {
      uint16_t tail = (uint16_t)((t832Diag.critical_head +
                                  T832_DIAG_CRITICAL_RECORDS -
                                  t832Diag.critical_count) %
                                 T832_DIAG_CRITICAL_RECORDS);
      if (t832Diag.critical[tail].sequence == seq) {
        t832Diag.critical_count--;
        OsalPort_leaveCS(key);
        return;
      }
    }
    OsalPort_leaveCS(key);
    T832Diag_record(T832_DIAG_EV_DIAG_LOSS, 2u, sel, seq);
  } else if (sel == 2u) {
    if (t832Diag.routine_count) {
      uint16_t tail = (uint16_t)((t832Diag.routine_head +
                                  T832_DIAG_ROUTINE_RECORDS -
                                  t832Diag.routine_count) %
                                 T832_DIAG_ROUTINE_RECORDS);
      if (t832Diag.routine[tail].sequence == seq) {
        t832Diag.routine_count--;
        OsalPort_leaveCS(key);
        return;
      }
    }
    OsalPort_leaveCS(key);
    T832Diag_record(T832_DIAG_EV_DIAG_LOSS, 2u, sel, seq);
  } else {
    OsalPort_leaveCS(key);
  }
}

static void T832Diag_put16(uint8_t **p, uint16_t v)
{
  *(*p)++ = (uint8_t)v;
  *(*p)++ = (uint8_t)(v >> 8);
}

static void T832Diag_put32(uint8_t **p, uint32_t v)
{
  T832Diag_put16(p, (uint16_t)v);
  T832Diag_put16(p, (uint16_t)(v >> 16));
}

static void T832Diag_put64(uint8_t **p, uint64_t v)
{
  T832Diag_put32(p, (uint32_t)v);
  T832Diag_put32(p, (uint32_t)(v >> 32));
}

static void T832Diag_hex(const uint8_t *src, uint8_t len, uint8_t *dst)
{
  static const char h[] = "0123456789ABCDEF";
  uint8_t i;
  for (i = 0; i < len; i++) {
    dst[2u * i] = (uint8_t)h[src[i] >> 4];
    dst[2u * i + 1u] = (uint8_t)h[src[i] & 0x0Fu];
  }
}

static void T832Diag_putRecord(uint8_t **p, const T832DiagRecord *r)
{
  T832Diag_put32(p, r->first_ms);
  T832Diag_put32(p, r->last_ms);
  T832Diag_put16(p, r->sequence);
  *(*p)++ = r->kind;
  *(*p)++ = r->flags;
  T832Diag_put16(p, r->a);
  T832Diag_put16(p, r->b);
  T832Diag_put16(p, r->c);
  T832Diag_put16(p, r->repeat_count);
}

/* Live system records are built at export time; they never sit in the rings. */
static T832DiagRecord T832Diag_liveHealth(uint32_t now, uint32_t scheduled)
{
  T832DiagRecord r;
  r.first_ms = now;
  r.last_ms = now;
  r.sequence = 0u;
  r.kind = T832_DIAG_EV_HEALTH;
  r.flags = 0u;
  r.a = T832Diag_sat16(scheduled);
  r.b = T832Diag_sat16(now - t832Diag.mt_work_ms);
  r.c = T832Diag_sat16(now - t832Diag.npi_work_ms);
  r.repeat_count = 1u;
  return r;
}

static T832DiagRecord T832Diag_liveAfState(uint32_t now)
{
  T832DiagRecord r;
  uint32_t age = t832Diag.af_outstanding ? now - t832Diag.af_oldest_ms : 0u;
  r.first_ms = now;
  r.last_ms = now;
  r.sequence = 0u;
  r.kind = T832_DIAG_EV_AF_STATE;
  r.flags = 0u;
  r.a = t832Diag.af_outstanding;
  r.b = T832Diag_sat16(age);
  r.c = t832Diag.af_outstanding_max;
  r.repeat_count = 1u;
  return r;
}

static T832DiagRecord T832Diag_liveTaskEvents(uint32_t now)
{
  T832DiagRecord r;
  r.first_ms = now;
  r.last_ms = now;
  r.sequence = 0u;
  r.kind = T832_DIAG_EV_TASK_EVENTS;
  r.flags = 0u;
  r.a = t832Diag.mt_last_events;
  r.b = t832Diag.mt_sticky_events;
  r.c = (uint16_t)(t832Diag.mt_schedule_count & 0xFFFFu);
  r.repeat_count = 1u;
  return r;
}

static T832DiagRecord T832Diag_liveResource(uint8_t which, uint32_t now)
{
  T832DiagRecord r;
  Memory_Stats memStats;
  r.first_ms = now;
  r.last_ms = now;
  r.sequence = 0u;
  r.kind = T832_DIAG_EV_RESOURCE;
  r.flags = 0u;
  r.a = which;
  r.b = 0u;
  r.c = 0u;
  r.repeat_count = 1u;
  switch (which) {
  case 1u:
    r.b = t832Diag.rx_high_water;
    r.c = t832Diag.normal_pending_max;
    break;
  case 2u:
    r.b = t832Diag.tx_age_max;
    r.c = t832Diag.zstack_work_valid ?
        T832Diag_sat16(now - t832Diag.zstack_work_ms) : 0xFFFFu;
    break;
  case 3u:
    r.b = (uint16_t)(t832Diag.rx_bytes & 0xFFFFu);
    r.c = (uint16_t)((t832Diag.rx_bytes >> 16) & 0xFFFFu);
    break;
  case 4u:
    r.b = (uint16_t)(t832Diag.tx_frames & 0xFFFFu);
    r.c = (uint16_t)((t832Diag.tx_frames >> 16) & 0xFFFFu);
    break;
  case 5u: {
    uint32_t age = t832Diag.normal_pending ? now - t832Diag.oldest_pending_ms : 0u;
    r.b = (uint16_t)(age & 0xFFFFu);
    r.c = (uint16_t)((age >> 16) & 0xFFFFu);
    break;
  }
  case 6u:
    r.b = (uint16_t)(t832Diag.export_lost & 0xFFFFu);
    r.c = (uint16_t)((t832Diag.export_lost >> 16) & 0xFFFFu);
    break;
  case 7u:
    memStats.totalSize = 0u;
    memStats.totalFreeSize = 0u;
    memStats.largestFreeSize = 0u;
    Memory_getStats(Memory_defaultHeapInstance, &memStats);
    if (memStats.totalSize == 0u) {
      r.b = 0xFFFFu;
      r.c = 0xFFFFu;
    } else {
      r.b = T832Diag_sat16(memStats.totalFreeSize >> 4);
      r.c = T832Diag_sat16(memStats.largestFreeSize >> 4);
    }
    break;
  case 8u:
    r.b = T832Diag_sat16(t832Diag.tx_diag_n);
    r.c = T832Diag_sat16(t832Diag.tx_sync_n);
    break;
  case 9u:
    r.b = T832Diag_sat16(t832Diag.af_confirmed_n);
    r.c = T832Diag_sat16(t832Diag.af_rejected_n);
    break;
  case 10u:
    r.b = t832Diag.last_cmd;
    r.c = T832Diag_sat16(now - t832Diag.last_cmd_ms);
    break;
  case 11u:
    r.b = t832Diag.last_startup_stage;
    r.c = T832Diag_sat16(now - t832Diag.last_startup_ms);
    break;
  case 12u:
    r.b = t832Diag.zstack_work_valid ?
        T832Diag_sat16(now - t832Diag.zstack_work_ms) : 0xFFFFu;
    r.c = T832Diag_sat16(now - t832Diag.npi_task_ms);
    break;
  case 13u:
    r.b = T832Diag_sat16(t832Diag.tx_normal_n);
    r.c = T832Diag_sat16(t832Diag.tx_unsol_n);
    break;
  default:
    break;
  }
  return r;
}

void T832Diag_exportPoll(void)
{
  uint64_t now64 = T832Diag_nowMs();
  uint32_t now = (uint32_t)now64;
  T832DiagRecord batch[T832_DIAG_BATCH_MAX];
  uint8_t staged[T832_DIAG_BATCH_MAX];
  uint16_t staged_seq[T832_DIAG_BATCH_MAX];
  uint8_t nbatch = 0u;
  uint8_t i;
  uint8_t healthDue = 0u;
  uint8_t resourceDue = 0u;
  uint8_t faultDue = 0u;
  uint8_t resAccepted = 0u;
  uint8_t healthComplete = 0u;
  uint8_t faultStaged = 0u;
  uint8_t res_idx_saved = t832Diag.res_ext_idx;

  /* Due detection never advances baselines: overdue work stays pending until
   * its records are staged into an accepted frame (see below). */
  if ((uint32_t)(now - t832Diag.last_health_ms) >= T832_DIAG_HEALTH_MS) {
    healthDue = 1u;
  }

  if ((uint32_t)(now - t832Diag.last_resource_ms) >= T832_DIAG_RESOURCE_MS) {
    resourceDue = 1u;
  }

  if (t832Diag.first_fault_valid &&
      (t832Diag.first_fault_export_ms == 0u ||
       (uint32_t)(now - t832Diag.first_fault_export_ms) >= T832_DIAG_RESOURCE_MS)) {
    faultDue = 1u;
  }

  if ((uint32_t)(now - t832Diag.last_export_ms) < T832_DIAG_EXPORT_MIN_MS) return;

  if (t832Diag.sync_outstanding || t832Diag.transport_active ||
      t832Diag.diag_pending || t832Diag.normal_pending) {
    if (t832Diag.export_skipped != 0xFFFFu) t832Diag.export_skipped++;
    return;
  }

  /* Keep one shadow slot free for our own frame: building while the
   * ownership FIFO is full would force our frame to fly untracked. */
  if (t832Diag.txq_count >= T832_DIAG_TXQ_DEPTH) {
    if (t832Diag.export_skipped != 0xFFFFu) t832Diag.export_skipped++;
    return;
  }

  /* Resources first: rarest cadence (60 s) always fits here (nbatch == 0),
   * so the 13 selectors rotate without starvation behind faults/health. */
  if (resourceDue) {
    uint8_t e;
    for (e = 0u; e < 2u && nbatch < T832_DIAG_BATCH_MAX; e++) {
      batch[nbatch] = T832Diag_liveResource((uint8_t)(1u + t832Diag.res_ext_idx), now);
      staged[nbatch] = 0u;
      nbatch++;
      t832Diag.res_ext_idx = (uint8_t)((t832Diag.res_ext_idx + 1u) % 13u);
    }
    resAccepted = 1u;
  }

  /* Sticky first-fault snapshot, independent of ring overwrites. The
   * original event kind is preserved in flags bits 7..2 (compatible
   * versioning: bit0 stays critical, bit1 stays snapshot). */
  if (faultDue && nbatch < T832_DIAG_BATCH_MAX) {
    uint8_t orig;
    batch[nbatch] = t832Diag.first_fault;
    orig = batch[nbatch].kind;
    batch[nbatch].kind = T832_DIAG_EV_FIRST_FAULT;
    batch[nbatch].flags |= (uint8_t)(T832_DIAG_FLAG_SNAPSHOT |
                                     (uint8_t)(orig << 2));
    staged[nbatch] = 0u;
    nbatch++;
    faultStaged = 1u;
  }

  /* Health triple in rotating order. A partial triple (no slots left) keeps
   * its baseline: the remainder stages on the next poll instead of waiting
   * a full interval. */
  if (healthDue) {
    while (nbatch < T832_DIAG_BATCH_MAX &&
           t832Diag.health_done != 0x07u) {
      if (t832Diag.health_rr == 0u) {
        batch[nbatch] = T832Diag_liveHealth(
            now, t832Diag.mt_schedule_count - t832Diag.last_health_schedule_count);
      } else if (t832Diag.health_rr == 1u) {
        batch[nbatch] = T832Diag_liveAfState(now);
      } else {
        batch[nbatch] = T832Diag_liveTaskEvents(now);
      }
      staged[nbatch] = 0u;
      nbatch++;
      t832Diag.health_done |= (uint8_t)(1u << t832Diag.health_rr);
      t832Diag.health_rr = (uint8_t)((t832Diag.health_rr + 1u) % 3u);
    }
    if (t832Diag.health_done == 0x07u) healthComplete = 1u;
  }

  while (nbatch < T832_DIAG_BATCH_MAX) {
    uint8_t sel;
    uint8_t i2;
    uint8_t skip_crit = 0u;
    uint8_t skip_rout = 0u;
    for (i2 = 0u; i2 < nbatch; i2++) {
      if (staged[i2] == 1u) skip_crit++;
      else if (staged[i2] == 2u) skip_rout++;
    }
    sel = T832Diag_peekAt(skip_crit, skip_rout, &batch[nbatch]);
    if (!sel) break;
    staged[nbatch] = sel;
    staged_seq[nbatch] = batch[nbatch].sequence;
    nbatch++;
  }
  if (!nbatch) return;

  {
    uint8_t bin[T832_DIAG_FRAME_BIN_MAX];
    uint8_t *p = bin;
    *p++ = 'T'; *p++ = '8'; *p++ = 'D'; *p++ = '1';
    *p++ = T832_DIAG_SCHEMA_VERSION;
    *p++ = 1u;
    T832Diag_put16(&p, (uint16_t)(++t832Diag.export_sequence));
    T832Diag_put16(&p, 1u);
    T832Diag_put64(&p, now64);
    T832Diag_put32(&p, (uint32_t)T832_BUILD_ID);
    T832Diag_put32(&p, t832Diag.capabilities);
    T832Diag_put16(&p, t832Diag.critical_overwrite);
    T832Diag_put16(&p, t832Diag.routine_overwrite);
    T832Diag_put16(&p, t832Diag.export_skipped);
    *p++ = nbatch;
    for (i = 0u; i < nbatch; i++) {
      T832Diag_putRecord(&p, &batch[i]);
    }

    {
      uint8_t out[240];
      uint8_t binLen = (uint8_t)(p - bin);
      uint8_t strLen = (uint8_t)(T832_DIAG_PREFIX_LEN + 2u * binLen);
      uint8_t outLen = (uint8_t)(1u + strLen);
      memcpy(out + 1u, T832_DIAG_PREFIX, T832_DIAG_PREFIX_LEN);
      T832Diag_hex(bin, binLen, out + 1u + T832_DIAG_PREFIX_LEN);
      out[0] = strLen;

      /* diag_pending is owned by T832Diag_responseQueued, which the real
       * MT_BuildAndSendZToolResponse invokes synchronously below. */
      t832Diag.staged_count = nbatch;
      t832Diag.build_failed = 0u;
      t832Diag.last_export_ms = now;
      MT_BuildAndSendZToolResponse(
          ((uint8_t)MT_RPC_CMD_AREQ | (uint8_t)MT_RPC_SYS_DBG),
          MT_DEBUG_MSG, outLen, out);
      if (t832Diag.build_failed) {
        /* MT refused the frame: nothing was queued; count the staged loss.
         * Baselines stay put so every due record is rebuilt next poll; only
         * the triple rotation restarts (live records duplicate, never lost). */
        t832Diag.diag_pending = 0u;
        t832Diag.export_lost += nbatch;
        t832Diag.health_done = 0u;
        t832Diag.res_ext_idx = res_idx_saved;
        T832Diag_record(T832_DIAG_EV_DIAG_LOSS, nbatch, 1u, outLen);
      } else {
        for (i = 0u; i < nbatch; i++) {
          if (staged[i]) T832Diag_popPeeked(staged[i], staged_seq[i]);
        }
        /* Baselines advance only for accepted work. */
        if (resAccepted) {
          t832Diag.last_resource_ms = now;
        }
        if (healthComplete) {
          t832Diag.last_health_ms = now;
          t832Diag.last_health_schedule_count = t832Diag.mt_schedule_count;
          t832Diag.health_done = 0u;
        }
        if (faultStaged) {
          t832Diag.first_fault_export_ms = now;
        }
      }
      t832Diag.staged_count = 0u;
    }
  }
}
