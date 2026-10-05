/* T832-DIAG-R0 host harness marker: recorder-behavior tests.
 *
 * Exercises the REAL ../t832_diag_impl.inc on the host with stubbed SDK
 * symbols (t832_host_sdk.h + stubs/ti/drivers/dpl/ClockP.h + stubs/mt_af.h
 * + stubs/ti/sysbios/runtime/Memory.h). Allocation is forbidden: link with
 * -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free so any heap
 * use by the recorder fails the link.
 *
 * The scripted call sequences below mirror the exact patched SDK callsites
 * (mt.c dispatch, npi_client_mt.c queue, npi_task.c dequeue/trap,
 * npi_tl_uart.c TX completion); presence of those callsites in the real
 * image is proven separately by exact-match patch evidence plus the
 * linked-image symbol gate in CI.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "t832_host_sdk.h"
#include "ti/sysbios/runtime/Memory.h"

#define CODE_REVISION_NUMBER 8320001u
#define T832_BUILD_ID 0xA5A50001u

/* ---- controllable host stand-ins ---- */

static uint32_t host_tick;
static int host_cs_depth;
static int host_cs_max_depth;
static int host_fail_alloc;
static uint32_t host_heap_total;
static uint32_t host_heap_free;
static uint32_t host_heap_largest;

uint32_t HostClock_getTicks(void) { return host_tick; }
uint32_t HostClock_getPeriodUs(void) { return 1000u; }
uint32_t ClockP_getSystemTicks(void) { return HostClock_getTicks(); }
uint32_t ClockP_getSystemTickPeriod(void) { return HostClock_getPeriodUs(); }

uint32_t HostCs_enter(void)
{
  host_cs_depth++;
  if (host_cs_depth > host_cs_max_depth) host_cs_max_depth = host_cs_depth;
  return (uint32_t)host_cs_depth;
}
void HostCs_leave(uint32_t key)
{
  (void)key;
  host_cs_depth--;
}
int HostCs_depth(void) { return host_cs_depth; }

void HostHeap_getStats(Memory_Stats *stats)
{
  stats->totalSize = host_heap_total;
  stats->totalFreeSize = host_heap_free;
  stats->largestFreeSize = host_heap_largest;
}
#define HOST_MAX_FRAMES 8192u
static uint8_t host_frame_type[HOST_MAX_FRAMES];
static uint8_t host_frame_id[HOST_MAX_FRAMES];
static uint8_t host_frame_len[HOST_MAX_FRAMES];
static uint8_t host_frame_data[HOST_MAX_FRAMES][256];
static uint32_t host_frame_count;

void HostMdi_capture(uint8_t cmdType, uint8_t cmdId, uint8_t len,
                     const uint8_t *data)
{
  uint32_t i = host_frame_count;
  if (i >= HOST_MAX_FRAMES) {
    printf("FAIL: frame capture overflow\n");
    exit(1);
  }
  host_frame_type[i] = cmdType;
  host_frame_id[i] = cmdId;
  host_frame_len[i] = len;
  memcpy(host_frame_data[i], data, len);
  host_frame_count++;
}

#include "t832_diag_impl.inc"

/* Defined after the .inc so IHeap_Handle is a complete type. */
IHeap_Handle Memory_defaultHeapInstance = 0;

void MT_BuildAndSendZToolResponse(uint8_t cmdType, uint8_t cmdId,
                                  uint8_t dataLen, uint8_t *dataPtr)
{
  /* Mirror the patched npi_client_mt.c: the queue hook runs synchronously
   * inside the build call, before the frame is handed to the NPI task. */
  T832Diag_responseQueued(cmdType, cmdId, dataLen, dataPtr);
  if (host_fail_alloc && cmdType == (MT_RPC_CMD_AREQ | MT_RPC_SYS_DBG) &&
      cmdId == MT_DEBUG_MSG) {
    /* Mirror MT-side allocation refusal: the hook fires, nothing queues.
     * Undo the queue-side effects first, exactly as a refused handoff would
     * never have produced them. */
    host_fail_alloc = 0;
    t832Diag.diag_pending = 0u;
    if (t832Diag.txq_count) {
      t832Diag.txq_count--;
    }
    T832Diag_responseAllocFailed(cmdType, cmdId, dataLen);
    return;
  }
  HostMdi_capture(cmdType, cmdId, dataLen, dataPtr);
}

/* ---- test utilities ---- */

static int failures;

#define CHECK(cond) do { \
    if (!(cond)) { \
      printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
      failures++; \
    } \
  } while (0)

static void advance_ms(uint32_t ms) { host_tick += ms; }

static void fresh_full(uint8_t task_id, uint32_t cause, uint8_t captured)
{
  host_tick = 0u;
  host_cs_depth = 0;
  host_cs_max_depth = 0;
  host_frame_count = 0u;
  host_fail_alloc = 0;
  host_heap_total = 6144u;
  host_heap_free = 4096u;
  host_heap_largest = 2048u;
  t832DiagResetCauseEarly = 0u;
  t832DiagResetCauseMagic = 0u;
  if (captured) {
    T832Diag_captureResetCauseEarly(cause);
  }
  T832Diag_init(task_id);
  CHECK(host_cs_depth == 0);
}

static void fresh(uint8_t task_id)
{
  fresh_full(task_id, 0x12u, 1u);
}

/* Drive one frame through the real NPI path order:
 * queue (already done by the test) -> dequeue -> TX start -> TX finish. */
static void wire_dequeue_finish(uint8_t sof, uint8_t cmd0, uint8_t cmd1,
                                uint8_t len)
{
  T832Diag_npiTxDequeue(sof, cmd0, cmd1, len);
  T832Diag_uartTxStart((uint16_t)(len + 5u));
  advance_ms(2u);
  T832Diag_uartTxFinished((uint16_t)(len + 5u));
}

typedef struct {
  uint16_t seq;
  uint8_t kind;
  uint8_t flags;
  uint16_t a;
  uint16_t b;
  uint16_t c;
  uint16_t repeat;
  uint32_t first_ms;
  uint32_t last_ms;
  uint16_t export_seq;
  uint32_t build_id;
  uint32_t caps;
  uint16_t crit_over;
  uint16_t rout_over;
  uint16_t skipped;
} DecRec;

typedef struct {
  uint16_t export_seq;
  uint32_t build_id;
  uint32_t caps;
  uint16_t crit_over;
  uint16_t rout_over;
  uint16_t skipped;
  uint8_t schema;
  uint8_t nrec;
  DecRec rec[4];
} DecFrame;

static uint8_t hexval(uint8_t ch)
{
  if (ch >= '0' && ch <= '9') return (uint8_t)(ch - '0');
  if (ch >= 'A' && ch <= 'F') return (uint8_t)(ch - 'A' + 10u);
  return (uint8_t)(ch - 'a' + 10u);
}

/* Decode captured frame i; returns record count or -1 when not a T832D2 frame. */
static int decode_frame(uint32_t i, DecFrame *out)
{
  uint8_t bin[113];
  uint32_t k;
  uint8_t len;
  uint8_t strLen;
  uint32_t pos;
  uint8_t n;
  if (host_frame_len[i] < 1u + 7u + 2u) return -1;
  len = host_frame_len[i];
  if (host_frame_data[i][0] != (uint8_t)(len - 1u)) return -1;
  if (memcmp(host_frame_data[i] + 1u, "T832D2:", 7) != 0) return -1;
  strLen = (uint8_t)(len - 1u);
  if (strLen < 7u || ((strLen - 7u) % 2u)) return -1;
  {
    uint8_t binLen = (uint8_t)((strLen - 7u) / 2u);
    if (binLen < 33u || binLen > 113u) return -1;
    for (k = 0; k < binLen; k++) {
      bin[k] = (uint8_t)((hexval(host_frame_data[i][1u + 7u + 2u * k]) << 4) |
                         hexval(host_frame_data[i][1u + 7u + 2u * k + 1u]));
    }
    if (memcmp(bin, "T8D1", 4) != 0) return -1;
    out->schema = bin[4];
    if (out->schema != 2u) return -1;
    out->export_seq = (uint16_t)(bin[6] | ((uint16_t)bin[7] << 8));
    out->build_id = (uint32_t)bin[18] | ((uint32_t)bin[19] << 8) |
                    ((uint32_t)bin[20] << 16) | ((uint32_t)bin[21] << 24);
    out->caps = (uint32_t)bin[22] | ((uint32_t)bin[23] << 8) |
                ((uint32_t)bin[24] << 16) | ((uint32_t)bin[25] << 24);
    out->crit_over = (uint16_t)(bin[26] | ((uint16_t)bin[27] << 8));
    out->rout_over = (uint16_t)(bin[28] | ((uint16_t)bin[29] << 8));
    out->skipped = (uint16_t)(bin[30] | ((uint16_t)bin[31] << 8));
    n = bin[32];
    if (n > 4u) return -1;
    if (binLen != (uint8_t)(33u + 20u * n)) return -1;
    out->nrec = n;
    for (k = 0; k < n; k++) {
      DecRec *r = &out->rec[k];
      pos = 33u + 20u * k;
      r->first_ms = (uint32_t)bin[pos] | ((uint32_t)bin[pos + 1] << 8) |
                    ((uint32_t)bin[pos + 2] << 16) | ((uint32_t)bin[pos + 3] << 24);
      r->last_ms = (uint32_t)bin[pos + 4] | ((uint32_t)bin[pos + 5] << 8) |
                   ((uint32_t)bin[pos + 6] << 16) | ((uint32_t)bin[pos + 7] << 24);
      r->seq = (uint16_t)(bin[pos + 8] | ((uint16_t)bin[pos + 9] << 8));
      r->kind = bin[pos + 10];
      r->flags = bin[pos + 11];
      r->a = (uint16_t)(bin[pos + 12] | ((uint16_t)bin[pos + 13] << 8));
      r->b = (uint16_t)(bin[pos + 14] | ((uint16_t)bin[pos + 15] << 8));
      r->c = (uint16_t)(bin[pos + 16] | ((uint16_t)bin[pos + 17] << 8));
      r->repeat = (uint16_t)(bin[pos + 18] | ((uint16_t)bin[pos + 19] << 8));
      r->export_seq = out->export_seq;
      r->build_id = out->build_id;
      r->caps = out->caps;
      r->crit_over = out->crit_over;
      r->rout_over = out->rout_over;
      r->skipped = out->skipped;
    }
    return (int)n;
  }
}

/* Find the most recent record with the given kind across all frames. */
static int find_kind(uint8_t kind, DecRec *out)
{
  uint32_t i = host_frame_count;
  DecFrame f;
  int k;
  while (i > 0u) {
    i--;
    if (decode_frame(i, &f) < 0) continue;
    for (k = (int)f.nrec - 1; k >= 0; k--) {
      if (f.rec[k].kind == kind) {
        *out = f.rec[k];
        return 1;
      }
    }
  }
  return 0;
}

/* Find any record with the given kind and a/b fields across all frames. */
static int find_kind_ab(uint8_t kind, uint16_t a, uint16_t b, DecRec *out)
{
  uint32_t i = host_frame_count;
  DecFrame f;
  int k;
  while (i > 0u) {
    i--;
    if (decode_frame(i, &f) < 0) continue;
    for (k = 0; k < (int)f.nrec; k++) {
      if (f.rec[k].kind == kind && f.rec[k].a == a && f.rec[k].b == b) {
        *out = f.rec[k];
        return 1;
      }
    }
  }
  return 0;
}

/* Complete a captured diagnostic frame on the wire: the NPI dequeue sees
 * the framed identity (SOF + MT data length) matching the queued entry. */
static void wire_complete_diag(uint32_t frame_idx)
{
  wire_dequeue_finish(0xFEu, (uint8_t)(MT_RPC_CMD_AREQ | MT_RPC_SYS_DBG),
                      MT_DEBUG_MSG, host_frame_len[frame_idx]);
}

/* Emit exactly one frame: gates clear, 5 s elapsed. Returns frame index. */
static uint32_t emit_one(void)
{
  uint32_t before = host_frame_count;
  DecFrame f;
  advance_ms(5000u);
  T832Diag_exportPoll();
  CHECK(host_frame_count == before + 1u);
  CHECK(host_cs_depth == 0);
  CHECK(decode_frame(before, &f) > 0);
  wire_complete_diag(before);
  return before;
}

/* Drain with periodics enabled: the export rate must exceed production. */
static void drain_all(void)
{
  uint32_t guard = 0u;
  while ((t832Diag.critical_count || t832Diag.routine_count) && guard < 900u) {
    uint32_t before = host_frame_count;
    T832Diag_exportPoll();
    if (host_frame_count == before) {
      advance_ms(5000u);
      T832Diag_exportPoll();
    }
    if (host_frame_count != before) {
      wire_complete_diag(host_frame_count - 1u);
    } else {
      advance_ms(5000u);
    }
    guard++;
  }
  CHECK(guard < 900u);
  CHECK(host_cs_depth == 0);
}

static void test_sizes(void)
{
  printf("sizes: record=%u state=%u\n",
         (unsigned)sizeof(T832DiagRecord), (unsigned)sizeof(T832DiagState));
  CHECK(sizeof(T832DiagRecord) == 20u);
  CHECK(sizeof(T832DiagState) <= 4096u);
}

static void test_boot_and_caps(void)
{
  DecFrame f;
  fresh(9u);
  CHECK(t832Diag.capabilities == 0x3FFFFFu);
  emit_one();
  CHECK(decode_frame(0u, &f) > 0);
  CHECK(f.schema == 2u);
  CHECK(f.build_id == 0xA5A50001u);
  CHECK(f.caps == 0x3FFFFFu);
  CHECK(f.nrec >= 1u);
  CHECK(f.rec[0].kind == 1u);
  CHECK(f.rec[0].a == 0x12u);
  CHECK(f.rec[0].b == 9u);
  CHECK(f.rec[0].c == 1u);
}

static void test_boot_invalid(void)
{
  DecRec r;
  fresh_full(9u, 0u, 0u);
  emit_one();
  CHECK(find_kind(1u, &r));
  CHECK(r.a == 0xFFFFu);
  CHECK(r.c == 0u);
  CHECK(find_kind(T832_DIAG_EV_BOOT_CAPTURE_INVALID, &r));
}

static void test_sync_gate(void)
{
  DecRec r;
  uint32_t n;
  uint8_t srsp[1] = {0};
  fresh(9u);
  emit_one();
  n = host_frame_count;
  /* SREQ outstanding: export must stall and count a skip. */
  T832Diag_commandRx(0x21u, 0x01u);
  advance_ms(5000u);
  T832Diag_exportPoll();
  CHECK(host_frame_count == n);
  /* Complete the sync round-trip: SRSP queued, dequeued, physically finished. */
  T832Diag_commandDispatch(0x21u, 0x01u);
  T832Diag_commandComplete(0x21u, 0x01u, 0u);
  T832Diag_responseQueued(0x61u, 0x01u, 1u, srsp);
  CHECK(t832Diag.sync_outstanding == 1u);
  wire_dequeue_finish(0xFEu, 0x61u, 0x01u, 1u);
  CHECK(t832Diag.sync_outstanding == 0u);
  CHECK(t832Diag.normal_pending == 0u);
  advance_ms(5000u);
  T832Diag_exportPoll();
  CHECK(host_frame_count == n + 1u);
  wire_complete_diag(n);
  drain_all();
  CHECK(find_kind(4u, &r));
  CHECK(find_kind(10u, &r));
  CHECK(r.b != 0u || r.c == t832Diag.normal_pending);
}

/* R04: an older AREQ finishing after an SRSP was queued must not clear the
 * sync flag, and a diagnostic finishing must not clear it either. */
static void test_overtake_completion(void)
{
  uint8_t areq[2] = {7, 8};
  uint8_t srsp[1] = {0};
  uint32_t k;
  DecRec r;
  fresh(9u);
  emit_one();
  /* Queue an AREQ first, then run an SREQ round-trip around it. */
  T832Diag_responseQueued(0x41u, 0x81u, 2u, areq);
  T832Diag_commandRx(0x21u, 0x01u);
  T832Diag_commandDispatch(0x21u, 0x01u);
  T832Diag_commandComplete(0x21u, 0x01u, 0u);
  T832Diag_responseQueued(0x61u, 0x01u, 1u, srsp);
  CHECK(t832Diag.normal_pending == 2u);
  /* The older AREQ finishes first: sync must survive, pending must drop. */
  wire_dequeue_finish(0xFEu, 0x41u, 0x81u, 2u);
  CHECK(t832Diag.sync_outstanding == 1u);
  CHECK(t832Diag.normal_pending == 1u);
  wire_dequeue_finish(0xFEu, 0x61u, 0x01u, 1u);
  CHECK(t832Diag.sync_outstanding == 0u);
  CHECK(t832Diag.normal_pending == 0u);
  /* Diagnostic queued ahead of an SRSP: each completion resolves its own. */
  advance_ms(5000u);
  T832Diag_exportPoll();
  CHECK(t832Diag.diag_pending == 1u);
  T832Diag_commandRx(0x21u, 0x02u);
  T832Diag_responseQueued(0x61u, 0x02u, 1u, srsp);
  wire_dequeue_finish(0xFEu, (uint8_t)(MT_RPC_CMD_AREQ | MT_RPC_SYS_DBG),
                      MT_DEBUG_MSG, host_frame_len[host_frame_count - 1u]);
  CHECK(t832Diag.diag_pending == 0u);
  CHECK(t832Diag.sync_outstanding == 1u);
  wire_dequeue_finish(0xFEu, 0x61u, 0x02u, 1u);
  CHECK(t832Diag.sync_outstanding == 0u);
  CHECK(t832Diag.normal_pending == 0u);
  /* No ownership mismatch may have been recorded on the orderly path. */
  drain_all();
  for (k = 0; k < host_frame_count; k++) {
    DecFrame f;
    int nrec = decode_frame(k, &f);
    int j;
    CHECK(nrec > 0);
    for (j = 0; j < nrec; j++) {
      CHECK(f.rec[j].kind != T832_DIAG_EV_TX_MISMATCH);
    }
  }
  CHECK(find_kind(10u, &r));
  (void)r;
}

static void test_flood_and_coalesce(void)
{
  uint32_t k;
  DecRec f;
  uint32_t frames_before;
  fresh(9u);
  emit_one();
  for (k = 0; k < 200u; k++) {
    T832Diag_commandRx(0x41u, 0x81u);
  }
  CHECK(t832Diag.routine_overwrite > 0u);
  CHECK(t832Diag.critical_count == 0u);
  for (k = 0; k < 70u; k++) {
    T832Diag_uartRxOverflow(300u, 250u);
  }
  CHECK(t832Diag.critical_count == 1u);
  CHECK(t832Diag.critical_overwrite == 0u);
  frames_before = host_frame_count;
  drain_all();
  CHECK(host_frame_count > frames_before);
  CHECK(find_kind(8u, &f));
  CHECK((f.flags & 1u) == 1u);
  CHECK(f.repeat == 70u);
  CHECK(f.a == 300u);
  /* First-fault snapshot arrives verbatim with the snapshot flag. */
  CHECK(find_kind(T832_DIAG_EV_FIRST_FAULT, &f));
  CHECK((f.flags & T832_DIAG_FLAG_SNAPSHOT) != 0u);
  CHECK(f.a == 300u);
  CHECK(f.b == 250u);
  /* Live health bypasses the rings: sequence zero, always available. */
  CHECK(find_kind(19u, &f));
  CHECK(f.seq == 0u);
}

static void test_diag_traffic_excluded(void)
{
  uint16_t before;
  fresh(9u);
  emit_one();
  before = t832Diag.normal_pending;
  T832Diag_responseQueued(0x48u, 0x80u, 111u, host_frame_data[0]);
  CHECK(t832Diag.normal_pending == before);
  CHECK(t832Diag.diag_pending == 1u);
  T832Diag_responseAllocFailed(0x48u, 0x80u, 120u);
  /* Our own build failure flags the exporter; it is not a radio fault. */
  CHECK(t832Diag.build_failed == 1u);
  CHECK(t832Diag.first_fault_valid == 0u);
  /* A normal-path allocation failure is still a critical system event. */
  T832Diag_responseAllocFailed(0x61u, 0x01u, 10u);
  CHECK(t832Diag.first_fault_valid == 1u);
}

static void test_diag_build_loss(void)
{
  DecRec r;
  uint16_t lost_before;
  fresh(9u);
  emit_one();
  T832Diag_commandRx(0x41u, 0x81u);
  lost_before = (uint16_t)t832Diag.export_lost;
  host_fail_alloc = 1;
  advance_ms(5000u);
  T832Diag_exportPoll();
  CHECK(t832Diag.diag_pending == 0u);
  CHECK(t832Diag.export_lost > (uint32_t)lost_before);
  CHECK(t832Diag.critical_count == 0u);
  /* The staged record was never retired: it still drains afterwards. */
  drain_all();
  CHECK(find_kind(2u, &r));
  CHECK(find_kind(T832_DIAG_EV_DIAG_LOSS, &r));
  CHECK(r.a >= 1u);
}

static void test_task_events(void)
{
  DecRec f;
  fresh(9u);
  emit_one();
  T832Diag_taskScheduled(9u, 0x0008u);
  T832Diag_taskScheduled(9u, 0x0010u);
  T832Diag_taskWork(T832_DIAG_WORK_MT, SYS_EVENT_MSG);
  {
    /* No genuine ZStack-task observation yet: age renders unknown, not zero. */
    T832DiagRecord res12 = T832Diag_liveResource(12u, (uint32_t)T832Diag_nowMs());
    CHECK(res12.b == 0xFFFFu);
    CHECK(t832Diag.zstack_work_valid == 0u);
  }
  T832Diag_taskWork(T832_DIAG_WORK_ZSTACK, SYS_EVENT_MSG);
  T832Diag_npiTaskWake();
  CHECK(t832Diag.zstack_work_ms != 0u);
  CHECK(t832Diag.zstack_work_valid == 1u);
  CHECK(t832Diag.npi_task_ms != 0u);
  advance_ms(10000u);
  T832Diag_exportPoll();
  wire_complete_diag(host_frame_count - 1u);
  drain_all();
  CHECK(find_kind(26u, &f));
  CHECK(f.a == 0x0010u);
  CHECK(f.b == 0x0018u);
}

/* R10: AF acceptance comes from the SRSP payload, confirms correlate. */
static void test_af_accept_confirm(void)
{
  /* SREQ AF 0x01: [len,cmd0,cmd1,dstLo,dstHi,dstEp,srcEp,clLo,clHi,trans,...] */
  uint8_t req[13] = {10, 0x24, 0x01, 0x34, 0x12, 3, 5, 6, 7, 0x33, 0x30, 0x1E, 0};
  uint8_t srsp_rej[1] = {2};
  uint8_t srsp_ok[1] = {0};
  uint8_t conf[3] = {0, 5, 0x33};
  DecRec r;
  fresh(9u);
  emit_one();
  T832Diag_afDispatch(0x24u, 0x01u, req, 13u);
  /* Handler return alone resolves nothing. */
  T832Diag_commandComplete(0x24u, 0x01u, 0u);
  CHECK(t832Diag.af_outstanding == 0u);
  T832Diag_responseQueued(0x64u, 0x01u, 1u, srsp_rej);
  CHECK(t832Diag.af_outstanding == 0u);
  CHECK(t832Diag.af_rejected_n == 1u);
  wire_dequeue_finish(0xFEu, 0x64u, 0x01u, 1u);
  drain_all();
  CHECK(find_kind(T832_DIAG_EV_AF_REJECT, &r));
  CHECK(r.a == 5u);
  CHECK(r.b == 0x33u);
  CHECK(r.c == 2u);
  /* Accept path, then confirm correlation. */
  T832Diag_afDispatch(0x24u, 0x01u, req, 13u);
  T832Diag_responseQueued(0x64u, 0x01u, 1u, srsp_ok);
  CHECK(t832Diag.af_outstanding == 1u);
  wire_dequeue_finish(0xFEu, 0x64u, 0x01u, 1u);
  T832Diag_responseQueued(0x44u, 0x80u, 3u, conf);
  CHECK(t832Diag.af_outstanding == 0u);
  CHECK(t832Diag.af_confirmed_n == 1u);
  wire_dequeue_finish(0xFEu, 0x44u, 0x80u, 3u);
  /* Duplicate confirm is an orphan anomaly, not a second resolution. */
  T832Diag_responseQueued(0x44u, 0x80u, 3u, conf);
  CHECK(t832Diag.af_outstanding == 0u);
  wire_dequeue_finish(0xFEu, 0x44u, 0x80u, 3u);
  drain_all();
  CHECK(find_kind(T832_DIAG_EV_AF_ANOMALY, &r));
  CHECK(r.a == 1u);
}

static const uint8_t *req_trunc(void)
{
  static const uint8_t t[5] = {2, 0x24, 0x01, 0x34, 0x12};
  return t;
}

static void test_af_variants_overflow(void)
{
  /* EXT 0x02: ep[9+3], srcEp[12+3], trans[15+3] relative to frame head. */
  uint8_t ext[22] = {19, 0x24, 0x02, 2,
                     1, 2, 3, 4, 5, 6, 7, 8,
                     7, 0x34, 0x12, 9, 0x06, 0x07, 0x44, 0x30, 0x1E, 0};
  /* SRCRTG 0x03 shares the 0x01 head: srcEp pl[3], trans pl[6]. */
  uint8_t src[13] = {10, 0x24, 0x03, 0x34, 0x12, 3, 6, 0x06, 0x07, 0x55,
                     0x01, 0x30, 0x1E};
  uint8_t srsp_ok[1] = {0};
  uint8_t srsp_bad[1] = {5};
  uint8_t areq[10] = {7, 0x44, 0x01, 0x34, 0x12, 3, 8, 0x06, 0x07, 0x55};
  uint8_t k;
  DecRec r;
  fresh(9u);
  emit_one();
  T832Diag_afDispatch(0x24u, 0x02u, ext, 22u);
  T832Diag_responseQueued(0x64u, 0x02u, 1u, srsp_ok);
  CHECK(t832Diag.af_outstanding == 1u);
  wire_dequeue_finish(0xFEu, 0x64u, 0x02u, 1u);
  {
    uint8_t conf_ext[3] = {0, 9, 0x44};
    T832Diag_responseQueued(0x44u, 0x80u, 3u, conf_ext);
    CHECK(t832Diag.af_outstanding == 0u);
    wire_dequeue_finish(0xFEu, 0x44u, 0x80u, 3u);
  }
  /* Nonzero SRSP status is a rejection: no table entry, reject counted. */
  T832Diag_afDispatch(0x24u, 0x03u, src, 13u);
  T832Diag_responseQueued(0x64u, 0x03u, 1u, srsp_bad);
  CHECK(t832Diag.af_outstanding == 0u);
  CHECK(t832Diag.af_rejected_n == 1u);
  wire_dequeue_finish(0xFEu, 0x64u, 0x03u, 1u);
  /* Fill the table with unconfirmed AREQ requests, then overflow it. */
  for (k = 0; k < 8u; k++) {
    areq[6] = (uint8_t)(20u + k);
    areq[9] = (uint8_t)(0x60u + k);
    T832Diag_afDispatch(0x44u, 0x01u, areq, 10u);
  }
  CHECK(t832Diag.af_outstanding == 8u);
  areq[6] = 99u;
  areq[9] = 0x77u;
  T832Diag_afDispatch(0x44u, 0x01u, areq, 10u);
  CHECK(t832Diag.af_outstanding == 8u);
  /* Transaction reuse supersedes the tracked entry. */
  areq[6] = 9u;
  areq[9] = 0x44u;
  T832Diag_afDispatch(0x44u, 0x01u, areq, 10u);
  /* Truncated payloads are anomalies, not parses. */
  T832Diag_afDispatch(0x24u, 0x01u, req_trunc(), 5u);
  drain_all();
  CHECK(find_kind(T832_DIAG_EV_AF_REJECT, &r));
  CHECK(r.a == 6u);
  CHECK(r.b == 0x55u);
  CHECK(r.c == 5u);
  CHECK(find_kind(T832_DIAG_EV_AF_ANOMALY, &r));
  CHECK(t832Diag.af_outstanding_max == 8u);
  CHECK(find_kind(28u, &r));
  CHECK(r.c == 8u);
}

static void test_nv_events(void)
{
  DecRec f;
  fresh(9u);
  emit_one();
  T832Diag_nvInit(0u);
  T832Diag_nvEvent(1u, 100u, 0u);
  advance_ms(50u);
  T832Diag_nvEvent(2u, 0u, 0u);
  T832Diag_nvEvent(3u, 16u, 0u);
  T832Diag_nvEvent(4u, 5u, 0u);
  T832Diag_nvInit(3u);
  CHECK(t832Diag.critical_count == 3u);
  drain_all();
  CHECK(find_kind(27u, &f));
  CHECK(find_kind(29u, &f));
  CHECK(f.a == 0u);
  CHECK(f.b == 3u);
}

static void test_npi_paths(void)
{
  DecRec r;
  uint8_t payload[2] = {1, 2};
  uint8_t outLen;
  fresh(9u);
  emit_one();
  /* Central trap records before spinning; it is first-fault eligible. */
  T832Diag_npiTrap(300u, 100u);
  CHECK(t832Diag.first_fault_valid == 1u);
  drain_all();
  CHECK(find_kind(T832_DIAG_EV_NPI_TRAP, &r));
  CHECK(r.a == 300u);
  CHECK(r.b == 100u);
  /* Bad SOF at dequeue is flagged; the frame stays unaccounted. */
  T832Diag_responseQueued(0x41u, 0x02u, 2u, payload);
  T832Diag_npiTxDequeue(0x00u, 0x41u, 0x02u, 2u);
  CHECK(t832Diag.normal_pending == 1u);
  T832Diag_uartTxStart(9u);
  T832Diag_uartTxFinished(9u);
  CHECK(t832Diag.normal_pending == 1u);
  CHECK(t832Diag.tx_unsol_n >= 1u);
  /* The queued descriptor is still there: a correct dequeue resolves it. */
  T832Diag_npiTxDequeue(0xFEu, 0x41u, 0x02u, 2u);
  T832Diag_uartTxStart(9u);
  T832Diag_uartTxFinished(9u);
  CHECK(t832Diag.normal_pending == 0u);
  /* App-originated frames join the same ownership accounting. */
  T832Diag_npiTxQueuedOther(0x42u, 0x03u, 4u);
  CHECK(t832Diag.normal_pending == 1u);
  wire_dequeue_finish(0xFEu, 0x42u, 0x03u, 4u);
  CHECK(t832Diag.normal_pending == 0u);
  /* B01 as refined by R4-F01: an NPI TX-side drop retires nothing by
   * header match — the owned entry survives with descriptor AND pending
   * unit intact (the frame was never queue-hooked, so nothing is spent),
   * the outcome counts uncertain, and the survivor completes exactly. */
  T832Diag_responseQueued(0x41u, 0x04u, 2u, payload);
  CHECK(t832Diag.normal_pending == 1u);
  {
    uint32_t uncertain_before = t832Diag.tx_uncertain_n;
    uint32_t orphan_before = t832Diag.tx_orphan_n;
    T832Diag_npiAllocFailed(1u, 12u, 0x41u, 0x04u, 2u);
    CHECK(t832Diag.normal_pending == 1u);
    CHECK(t832Diag.txq_count == 1u);
    CHECK(t832Diag.tx_uncertain_n == uncertain_before + 1u);
    CHECK(t832Diag.tx_orphan_n == orphan_before);
  }
  wire_dequeue_finish(0xFEu, 0x41u, 0x04u, 2u);
  CHECK(t832Diag.txq_count == 0u);
  CHECK(t832Diag.normal_pending == 0u);
  /* A dropped diagnostic frame is counted loss, never a radio fault. */
  advance_ms(5000u);
  T832Diag_exportPoll();
  CHECK(t832Diag.diag_pending == 1u);
  outLen = host_frame_len[host_frame_count - 1u];
  T832Diag_npiAllocFailed(1u, (uint16_t)(outLen + 3u),
                          (uint8_t)(MT_RPC_CMD_AREQ | MT_RPC_SYS_DBG),
                          MT_DEBUG_MSG, outLen);
  CHECK(t832Diag.diag_pending == 0u);
  CHECK(t832Diag.export_lost == 1u);
  CHECK(t832Diag.first_fault_valid == 1u);
  drain_all();
  CHECK(find_kind(T832_DIAG_EV_NPI_ALLOC_FAIL, &r));
  CHECK(find_kind(T832_DIAG_EV_DIAG_LOSS, &r));
  CHECK(r.b == 2u);
  /* RX-side drops carry no pending state and release no ownership. */
  {
    uint32_t orphan_before = t832Diag.tx_orphan_n;
    uint32_t uncertain_before = t832Diag.tx_uncertain_n;
    T832Diag_npiAllocFailed(2u, 12u, 0x21u, 0x01u, 9u);
    CHECK(t832Diag.normal_pending == 0u);
    CHECK(t832Diag.tx_orphan_n == orphan_before);
    CHECK(t832Diag.tx_uncertain_n == uncertain_before);
  }
  /* A repeated SREQ abandons the previous sync round-trip explicitly. */
  T832Diag_commandRx(0x21u, 0x01u);
  T832Diag_commandRx(0x21u, 0x02u);
  CHECK(t832Diag.sync_outstanding == 1u);
  {
    uint8_t srsp2[1] = {0};
    T832Diag_responseQueued(0x61u, 0x02u, 1u, srsp2);
    wire_dequeue_finish(0xFEu, 0x61u, 0x02u, 1u);
    CHECK(t832Diag.sync_outstanding == 0u);
  }
  drain_all();
  CHECK(find_kind(T832_DIAG_EV_SYNC_ABANDON, &r));
  CHECK(r.a == 1u);
}

static void test_tick_wrap(void)
{
  fresh(9u);
  host_tick = 0xFFFFFFF0u;
  T832Diag_commandRx(0x41u, 0x81u);
  advance_ms(0x20u);
  T832Diag_commandRx(0x41u, 0x81u);
  CHECK(t832Diag.tick_wraps == 1u);
  CHECK(host_cs_depth == 0);
  CHECK(host_cs_max_depth >= 1);
}

static void test_heap_resource(void)
{
  DecRec r;
  int ticks;
  fresh(9u);
  emit_one();
  /* Two resource slots per export (resources go first); a full 13-slot
   * rotation needs 7 resource-due exports; run 14 for margin. */
  for (ticks = 0; ticks < 14; ticks++) {
    advance_ms(60000u);
    T832Diag_exportPoll();
    wire_complete_diag(host_frame_count - 1u);
  }
  drain_all();
  CHECK(find_kind(20u, &r));
  /* Heap stats present: 4096>>4 free, 2048>>4 largest. */
  {
    uint32_t i = host_frame_count;
    DecFrame f;
    int seen = 0;
    while (i > 0u) {
      DecRec *q;
      int k;
      i--;
      if (decode_frame(i, &f) <= 0) continue;
      for (k = 0; k < f.nrec; k++) {
        q = &f.rec[k];
        if (q->kind == 20u && q->a == 7u) {
          CHECK(q->b == 256u);
          CHECK(q->c == 128u);
          seen = 1;
        }
      }
    }
    CHECK(seen == 1);
  }
  /* Zero-sized heap reports the documented unavailable sentinel. */
  host_heap_total = 0u;
  host_heap_free = 0u;
  host_heap_largest = 0u;
  for (ticks = 0; ticks < 14; ticks++) {
    advance_ms(60000u);
    T832Diag_exportPoll();
    wire_complete_diag(host_frame_count - 1u);
  }
  {
    uint32_t i = host_frame_count;
    DecFrame f;
    int seen = 0;
    int k;
    while (i > 0u) {
      i--;
      if (decode_frame(i, &f) <= 0) continue;
      for (k = 0; k < f.nrec; k++) {
        if (f.rec[k].kind == 20u && f.rec[k].a == 7u &&
            f.rec[k].b == 0xFFFFu && f.rec[k].c == 0xFFFFu) {
          seen = 1;
        }
      }
    }
    CHECK(seen == 1);
  }
}

static void test_frame_budget(void)
{
  uint32_t i;
  DecFrame f;
  int saw_full = 0;
  fresh(9u);
  T832Diag_uartRxOverflow(400u, 300u);
  drain_all();
  for (i = 0; i < host_frame_count; i++) {
    int nrec;
    CHECK(host_frame_len[i] <= 240u);
    CHECK(host_frame_data[i][0] == (uint8_t)(host_frame_len[i] - 1u));
    CHECK(host_frame_type[i] == (MT_RPC_CMD_AREQ | MT_RPC_SYS_DBG));
    CHECK(host_frame_id[i] == MT_DEBUG_MSG);
    CHECK(memcmp(host_frame_data[i] + 1u, "T832D2:", 7) == 0);
    nrec = decode_frame(i, &f);
    CHECK(nrec > 0);
    CHECK(nrec <= 4);
    if (nrec == 4) saw_full = 1;
  }
  CHECK(find_kind(8u, &f.rec[0]));
  (void)saw_full;
}

static void dump_scenario(const char *path)
{
  FILE *fh;
  uint32_t i;
  uint8_t srsp[1] = {0};
  fresh(9u);
  T832Diag_commandRx(0x21u, 0x01u);
  T832Diag_commandDispatch(0x21u, 0x01u);
  T832Diag_commandComplete(0x21u, 0x01u, 0u);
  T832Diag_responseQueued(0x61u, 0x01u, 1u, srsp);
  wire_dequeue_finish(0xFEu, 0x61u, 0x01u, 1u);
  emit_one();
  T832Diag_commandRx(0x41u, 0x81u);
  advance_ms(10000u);
  emit_one();
  drain_all();
  fh = fopen(path, "w");
  if (!fh) {
    printf("FAIL: cannot open dump path\n");
    failures++;
    return;
  }
  for (i = 0; i < host_frame_count; i++) {
    uint32_t k;
    for (k = 0; k < host_frame_len[i]; k++) {
      fprintf(fh, "%02X", host_frame_data[i][k]);
    }
    fprintf(fh, "\n");
  }
  fclose(fh);
  printf("DUMP-OK %u frames -> %s\n", (unsigned)host_frame_count, path);
}

/* B01: no TX refusal stage retires by header match. Each refusal leaves
 * the owned descriptor queued (one pending unit is released with the
 * known-dead message when a same-class entry matches), counts explicitly
 * uncertain (TX_MISMATCH 15u), and the survivor still completes exactly
 * through its own dequeue/finish. Same call order as the patched SDK
 * (queue observes first, refusal reconciles after). */
/* R4-F01: no unowned TX refusal stage retires by header match. Each
 * unowned refusal (stages 1, 2, 4, 5, 6) leaves the owned descriptor
 * queued and its pending unit intact; the survivor still completes exactly
 * through its own dequeue/finish. Only the stage-3 owned refusal retires,
 * and exactly the frame the sendToHost queue hook just stored. Same call
 * order as the patched SDK (queue observes first, refusal follows). */
/* Forward: defined with the patched-site mirrors below. */
static void sdk_sendToHost_mirror(uint8_t cmd0, uint8_t cmd1, uint8_t len,
                                  uint8_t fail_stage);
static void test_tx_refused_stages(void)
{
  uint8_t payload[2] = {1, 2};
  uint8_t stage;
  DecRec r;
  fresh(9u);
  emit_one();
  for (stage = 1u; stage <= 6u; stage++) {
    uint8_t cmd0 = (stage <= 3u) ? 0x41u : 0x61u;
    uint8_t cmd1 = (uint8_t)(0x10u + stage);
    uint32_t uncertain_before = t832Diag.tx_uncertain_n;
    uint32_t orphan_before = t832Diag.tx_orphan_n;
    T832Diag_responseQueued(cmd0, cmd1, 2u, payload);
    CHECK(t832Diag.normal_pending == 1u);
    CHECK(t832Diag.txq_count == 1u);
    sdk_sendToHost_mirror(cmd0, cmd1, 2u, stage);
    if (stage == 3u) {
      /* Owned: the mirror queued this same frame, then refused exactly it.
       * Net effect is as if it never queued; the earlier owned entry is
       * untouched. */
      CHECK(t832Diag.txq_count == 1u);
      CHECK(t832Diag.normal_pending == 1u);
    } else {
      /* Unowned: the refused frame was never queue-hooked; the survivor
       * keeps its descriptor and its pending unit. */
      CHECK(t832Diag.txq_count == 1u);
      CHECK(t832Diag.normal_pending == 1u);
    }
    CHECK(t832Diag.tx_uncertain_n == uncertain_before + 1u);
    CHECK(t832Diag.tx_orphan_n == orphan_before);
    CHECK(t832Diag.response_queued == 0u);
    /* The survivor is untouched: its own completion converges cleanly. */
    wire_dequeue_finish(0xFEu, cmd0, cmd1, 2u);
    CHECK(t832Diag.txq_count == 0u);
    CHECK(t832Diag.normal_pending == 0u);
  }
  /* Refusal with no owned entry: reported uncertain, nothing attributed. */
  {
    uint32_t pending_before = t832Diag.normal_pending;
    uint32_t uncertain_before = t832Diag.tx_uncertain_n;
    T832Diag_npiTxRefused(3u, 0x41u, 0x77u, 2u);
    CHECK(t832Diag.normal_pending == pending_before);
    CHECK(t832Diag.tx_uncertain_n == uncertain_before + 1u);
  }
  drain_all();
  for (stage = 1u; stage <= 6u; stage++) {
    CHECK(find_kind_ab(T832_DIAG_EV_NPI_ALLOC_FAIL, 1u, stage, &r));
  }
  CHECK(find_kind_ab(T832_DIAG_EV_TX_MISMATCH, 15u, 0x41u, &r));
  CHECK(host_cs_depth == 0);
  CHECK(host_cs_max_depth <= 4);
  (void)r;
}

/* Forward: defined with the AF tests below; used by the B03 AF fixture. */
static void queue_srps_ok_finish(void);

/* B01 patched-site control-flow mirrors. The real patched SDK bodies
 * execute only in the CI firmware build (npi_client_mt.c response queue,
 * npi_task.c sendToHost/processStackMsg refuse branches); their presence
 * there is proven by exact-match patch evidence plus the linked-image
 * symbol gate. These mirrors reproduce each site's exact hook call order
 * (anchors: apply_diag.py diag.response.queue/alloc_fail,
 * diag.npi_task.send_to_host/send_to_host_refuse) with injectable
 * allocation failure, so fixtures drive production sequences through the
 * real recorder logic instead of hand-ordered hook calls. */
static void sdk_client_queue_mirror(uint8_t cmdType, uint8_t cmdId,
                                    uint8_t dataLen, const uint8_t *payload,
                                    int fail_alloc)
{
  if (fail_alloc) {
    /* Patched npi_client_mt.c else-branch: hook fires, nothing queues. */
    T832Diag_responseAllocFailed(cmdType, cmdId,
                                 (uint16_t)(dataLen + 3u));
    return;
  }
  T832Diag_responseQueued(cmdType, cmdId, dataLen, payload);
}

/* R4-F01 patched-site control-flow mirror. Only stage 3 runs after the
 * queue hook in production (push before switch/default in patched
 * NPITask_sendToHost); stages 1, 2, 4, 5, 6 refuse frames the recorder
 * never queue-hooked, so no QueuedOther call precedes them here. */
static void sdk_sendToHost_mirror(uint8_t cmd0, uint8_t cmd1, uint8_t len,
                                  uint8_t fail_stage)
{
  if (fail_stage == 0u) {
    /* Patched NPITask_sendToHost success branch: queue record stored. */
    T832Diag_npiTxQueuedOther(cmd0, cmd1, len);
    return;
  }
  if (fail_stage == 3u) {
    /* Patched stage-3 order: queue hook first, then the owned refusal of
     * exactly that frame. */
    T832Diag_npiTxQueuedOther(cmd0, cmd1, len);
    T832Diag_npiTxRefusedOwned(fail_stage, cmd0, cmd1, len);
    return;
  }
  /* Patched refuse branches (stages 1-2 sendToHost, 4-6 processStackMsg):
   * the message never entered the ownership FIFO here. */
  T832Diag_npiTxRefused(fail_stage, cmd0, cmd1, len);
}

/* R4-F01 oracle: two identical headers/lengths. A queues through the
 * MT-response entry point; B is refused at each NPI refusal stage without
 * ever queueing. A's descriptor survives every unowned refusal and resolves
 * only through its own completion; counters stay truthful (uncertain per
 * refusal, no invented orphans, pending converges). No wire completion is
 * ever fabricated for a refused frame: refused B produces no dequeue. Then
 * the owned-refusal shape in production order: B queues too (identical
 * header, newer descriptor) and sendToHost refuses exactly B — B retires,
 * A survives with its pending unit, and A completes alone. */
static void test_b01_identical_headers_refusal(void)
{
  uint8_t payload[2] = {1, 2};
  uint8_t stage;
  DecRec r;
  /* Single fresh for the whole oracle: host_frame history must accumulate
   * across phases for the final exported-evidence checks. Every phase ends
   * with clean ownership (count 0, pending 0), so phases stay isolated by
   * state, not by reset. */
  fresh(9u);
  emit_one();
  for (stage = 1u; stage <= 6u; stage++) {
    uint32_t uncertain_before;
    uint32_t orphan_before;
    uncertain_before = t832Diag.tx_uncertain_n;
    orphan_before = t832Diag.tx_orphan_n;
    sdk_client_queue_mirror(0x41u, 0x50u, 2u, payload, 0);
    CHECK(t832Diag.normal_pending == 1u);
    CHECK(t832Diag.txq_count == 1u);
    sdk_sendToHost_mirror(0x41u, 0x50u, 2u, stage);
    if (stage == 3u) {
      /* Owned: the mirror queued B, then refused exactly B. A survives. */
      CHECK(t832Diag.txq_count == 1u);
      CHECK(t832Diag.normal_pending == 1u);
    } else {
      /* Unowned: B never queued; A's descriptor and pending unit survive. */
      CHECK(t832Diag.txq_count == 1u);
      CHECK(t832Diag.normal_pending == 1u);
    }
    CHECK(t832Diag.tx_uncertain_n == uncertain_before + 1u);
    CHECK(t832Diag.tx_orphan_n == orphan_before);
    /* Only A's genuine completion exists; B was never on the wire. */
    wire_dequeue_finish(0xFEu, 0x41u, 0x50u, 2u);
    CHECK(t832Diag.txq_count == 0u);
    CHECK(t832Diag.normal_pending == 0u);
  }
  /* Owned-refusal disambiguation in production order: A and B share header
   * and class; B queues through sendToHost and is refused there. Only B
   * retires; A completes alone. */
  {
    uint32_t uncertain_before;
    uncertain_before = t832Diag.tx_uncertain_n;
    sdk_client_queue_mirror(0x41u, 0x51u, 2u, payload, 0);
    CHECK(t832Diag.txq_count == 1u);
    CHECK(t832Diag.normal_pending == 1u);
    sdk_sendToHost_mirror(0x41u, 0x51u, 2u, 3u);
    CHECK(t832Diag.txq_count == 1u);
    CHECK(t832Diag.normal_pending == 1u);
    CHECK(t832Diag.tx_uncertain_n == uncertain_before + 1u);
    wire_dequeue_finish(0xFEu, 0x41u, 0x51u, 2u);
    CHECK(t832Diag.txq_count == 0u);
    CHECK(t832Diag.normal_pending == 0u);
  }
  /* Shadow-overflow shape: 8 owned intact, untracked 9th refused. */
  {
    uint8_t k;
    uint32_t uncertain_before;
    uint32_t overflow_before = t832Diag.tx_overflow_n;
    for (k = 0u; k < 8u; k++) {
      sdk_client_queue_mirror(0x41u, (uint8_t)(0x60u + k), 2u, payload, 0);
    }
    CHECK(t832Diag.txq_count == 8u);
    sdk_client_queue_mirror(0x41u, 0x68u, 2u, payload, 0);
    CHECK(t832Diag.tx_overflow_n == overflow_before + 1u);
    uncertain_before = t832Diag.tx_uncertain_n;
    sdk_sendToHost_mirror(0x41u, 0x68u, 2u, 5u);
    CHECK(t832Diag.txq_count == 8u);
    CHECK(t832Diag.tx_uncertain_n == uncertain_before + 1u);
    for (k = 0u; k < 8u; k++) {
      wire_dequeue_finish(0xFEu, 0x41u, (uint8_t)(0x60u + k), 2u);
    }
    CHECK(t832Diag.txq_count == 0u);
    CHECK(t832Diag.normal_pending == 0u);
  }
  /* SRSP shape: the stamped descriptor survives refusal with its SREQ
   * generation intact and still clears suppression on completion. */
  {
    uint8_t srsp[1] = {0};
    uint16_t stamped;
    T832Diag_commandRx(0x21u, 0x09u);
    T832Diag_commandDispatch(0x21u, 0x09u);
    T832Diag_commandComplete(0x21u, 0x09u, 0u);
    sdk_client_queue_mirror(0x61u, 0x09u, 1u, srsp, 0);
    stamped = t832Diag.txq[t832Diag.txq_head].gen;
    CHECK(stamped == t832Diag.sync_gen);
    sdk_sendToHost_mirror(0x61u, 0x09u, 1u, 3u);
    CHECK(t832Diag.txq_count == 1u);
    CHECK(t832Diag.txq[t832Diag.txq_head].gen == stamped);
    CHECK(t832Diag.response_queued == 0u);
    wire_dequeue_finish(0xFEu, 0x61u, 0x09u, 1u);
    CHECK(t832Diag.sync_outstanding == 0u);
    CHECK(t832Diag.txq_count == 0u);
  }
  drain_all();
  CHECK(find_kind_ab(T832_DIAG_EV_TX_MISMATCH, 15u, 0x41u, &r));
  CHECK(host_cs_depth == 0);
  CHECK(host_cs_max_depth <= 4);
  (void)r;
}

/* R4-F01: eight owned MT AREQs genuinely refused downstream, then quiet
 * polls. Each owned refusal retires exactly its own descriptor, so the
 * shadow FIFO drains to zero and the next export poll proceeds: bounded
 * recovery with no real normal/sync work outstanding. Pre-fix the eight
 * stale descriptors wedge txq_count at 8 and every future poll takes the
 * FIFO-full early return. */
static void test_f01_owned_refusals_drain_and_export(void)
{
  uint8_t k;
  DecRec r;
  fresh(9u);
  for (k = 0u; k < 8u; k++) {
    /* Production order per frame: the NPI task queues it for the UART,
     * then the unsupported-type branch refuses exactly it. Each cycle
     * converges to zero: no descriptor or pending unit leaks. */
    sdk_sendToHost_mirror(0x41u, (uint8_t)(0x60u + k), 2u, 3u);
    CHECK(t832Diag.txq_count == 0u);
    CHECK(t832Diag.normal_pending == 0u);
  }
  /* Quiet polls now export: the FIFO-full block is gone. */
  emit_one();
  drain_all();
  CHECK(find_kind_ab(T832_DIAG_EV_TX_MISMATCH, 15u, 0x41u, &r));
  CHECK(host_cs_depth == 0);
  (void)r;
}

/* R4-F01 overflow: the shadow is full of live owned frames when a ninth
 * frame is queued and refused. The queue hook overflows (stash sentinel),
 * so the owned refusal retires nothing: all eight survivors keep their
 * descriptors and pending units, and converge through genuine completions.
 * Pre-fix the refused header match spends a survivor's pending credit. */
static void test_f01_refused_overflow_preserves_survivors(void)
{
  uint8_t payload[2] = {1, 2};
  uint8_t k;
  uint32_t overflow_before;
  uint32_t uncertain_before;
  fresh(9u);
  emit_one();
  for (k = 0u; k < 8u; k++) {
    sdk_client_queue_mirror(0x41u, (uint8_t)(0x60u + k), 2u, payload, 0);
  }
  CHECK(t832Diag.txq_count == 8u);
  CHECK(t832Diag.normal_pending == 8u);
  overflow_before = t832Diag.tx_overflow_n;
  uncertain_before = t832Diag.tx_uncertain_n;
  /* Ninth frame shares survivor 0's header; its queue push overflows. */
  sdk_sendToHost_mirror(0x41u, 0x60u, 2u, 0u);
  CHECK(t832Diag.tx_overflow_n == overflow_before + 1u);
  CHECK(t832Diag.txq_count == 8u);
  T832Diag_npiTxRefusedOwned(3u, 0x41u, 0x60u, 2u);
  CHECK(t832Diag.txq_count == 8u);
  CHECK(t832Diag.normal_pending == 8u);
  CHECK(t832Diag.tx_uncertain_n == uncertain_before + 1u);
  for (k = 0u; k < 8u; k++) {
    wire_dequeue_finish(0xFEu, 0x41u, (uint8_t)(0x60u + k), 2u);
  }
  CHECK(t832Diag.txq_count == 0u);
  CHECK(t832Diag.normal_pending == 0u);
  drain_all();
  CHECK(host_cs_depth == 0);
}

/* R4-F09: a full AF table eviction recomputes the oldest outstanding
 * timestamp inside the atomic insertion. After evicting the oldest entry
 * the tracked oldest is the oldest survivor with distinct ages, including
 * across a tick wrap. Pre-fix the evicted stamp lingers and the reported
 * age covers work no longer tracked. */
static void test_f09_af_evict_recomputes_oldest(void)
{
  uint8_t areq[10] = {7, 0x44, 0x01, 0x34, 0x12, 3, 8, 0x06, 0x07, 0x55};
  uint8_t k;
  uint32_t oldest_before;
  T832DiagRecord live;
  fresh(9u);
  emit_one();
  for (k = 0u; k < 8u; k++) {
    advance_ms(100u);
    areq[6] = (uint8_t)(20u + k);
    areq[9] = (uint8_t)(0x60u + k);
    T832Diag_afDispatch(0x44u, 0x01u, areq, 10u);
  }
  CHECK(t832Diag.af_outstanding == 8u);
  oldest_before = t832Diag.af_oldest_ms;
  advance_ms(100u);
  areq[6] = 99u;
  areq[9] = 0x77u;
  T832Diag_afDispatch(0x44u, 0x01u, areq, 10u);
  CHECK(t832Diag.af_outstanding == 8u);
  CHECK(t832Diag.af_oldest_ms != oldest_before);
  CHECK(t832Diag.af_oldest_ms == oldest_before + 100u);
  live = T832Diag_liveAfState((uint32_t)HostClock_getTicks());
  CHECK(live.a == 8u);
  CHECK(live.b == 700u);
  /* Wrap: cross the 32-bit tick boundary with distinct ages — the
   * victim comparison is unsigned subtraction, so the pre-wrap oldest
   * (0xFFFFFFF0) is still evicted first and the survivor stamp is the
   * post-wrap 0x00000000. */
  fresh(9u);
  emit_one();
  host_tick = 0xFFFFFFE0u;
  for (k = 0u; k < 8u; k++) {
    host_tick += 16u;
    areq[6] = (uint8_t)(30u + k);
    areq[9] = (uint8_t)(0x70u + k);
    T832Diag_afDispatch(0x44u, 0x01u, areq, 10u);
  }
  CHECK(t832Diag.af_outstanding == 8u);
  oldest_before = t832Diag.af_oldest_ms;
  CHECK(oldest_before == 0xFFFFFFF0u);
  host_tick += 16u;
  areq[6] = 98u;
  areq[9] = 0x78u;
  T832Diag_afDispatch(0x44u, 0x01u, areq, 10u);
  CHECK(t832Diag.af_outstanding == 8u);
  CHECK(t832Diag.af_oldest_ms == 0x00000000u);
  CHECK(t832Diag.af_oldest_ms == oldest_before + 16u);
  drain_all();
  CHECK(host_cs_depth == 0);
}

/* R4-F10: a saturated record staged for export, then one more identical
 * occurrence before retirement. record() advances last_ms even though
 * repeat_count pins at 0xFFFF; the staged copy is stale, so retirement
 * must preserve (re-stage) the newer last_ms instead of exporting stale
 * bytes and retiring silently. Same-tick coalescing still retires: no
 * newer occurrence exists then. Pre-fix the stale copy retires and the
 * newer last_ms is lost with no report. */
static void test_f10_saturated_last_ms_preserved(void)
{
  T832DiagRecord staged_copy;
  T832DiagRecord restaged;
  uint8_t sel;
  uint32_t i;
  uint32_t newer_last;
  uint32_t frames_before;
  DecFrame f;
  int found = 0;
  int k;
  fresh(9u);
  emit_one();
  T832Diag_npiTrap(300u, 100u);
  /* Saturate genuinely through the real coalescing path. */
  for (i = 0u; i < 65534u; i++) {
    T832Diag_npiTrap(300u, 100u);
  }
  sel = T832Diag_peekAt(0u, 0u, &staged_copy);
  CHECK(sel == 1u);
  CHECK(staged_copy.repeat_count == 0xFFFFu);
  advance_ms(10u);
  T832Diag_npiTrap(300u, 100u);
  newer_last = staged_copy.last_ms + 10u;
  T832Diag_popPeeked(sel, staged_copy.sequence, staged_copy.first_ms,
                     staged_copy.last_ms, staged_copy.repeat_count);
  CHECK(t832Diag.critical_count == 1u);
  /* The preserved entry re-stages whole with the newer last_ms. */
  sel = T832Diag_peekAt(0u, 0u, &staged_copy);
  CHECK(sel == 1u);
  CHECK(staged_copy.repeat_count == 0xFFFFu);
  CHECK(staged_copy.last_ms == newer_last);
  restaged = staged_copy;
  /* The preserved entry leaves the ring only through the production export
   * path: wire bytes must carry the newer last_ms (a live-record crowd
   * may split this across two polls, so scan until found). */
  frames_before = host_frame_count;
  for (i = 0u; i < 4u && !found; i++) {
    uint32_t idx;
    advance_ms(5000u);
    T832Diag_exportPoll();
    if (host_frame_count == frames_before) break;
    idx = host_frame_count - 1u;
    CHECK(decode_frame(idx, &f) > 0);
    for (k = 0; k < (int)f.nrec; k++) {
      if (f.rec[k].kind == T832_DIAG_EV_NPI_TRAP &&
          f.rec[k].a == 300u && f.rec[k].b == 100u) {
        found = 1;
        CHECK(f.rec[k].repeat == 0xFFFFu);
        CHECK(f.rec[k].last_ms == restaged.last_ms);
      }
    }
    wire_complete_diag(idx);
  }
  CHECK(found == 1);
  CHECK(t832Diag.critical_count == 0u);
  /* Same-tick coalescing is still detected as stale (repeat differs) and
   * preserved for re-stage: nothing is silently retired. */
  T832Diag_npiTrap(301u, 101u);
  sel = T832Diag_peekAt(0u, 0u, &staged_copy);
  CHECK(sel == 1u);
  T832Diag_npiTrap(301u, 101u);
  T832Diag_popPeeked(sel, staged_copy.sequence, staged_copy.first_ms,
                     staged_copy.last_ms, staged_copy.repeat_count);
  CHECK(t832Diag.critical_count == 1u);
  drain_all();
  {
    DecRec loss;
    CHECK(find_kind_ab(T832_DIAG_EV_DIAG_LOSS, 3u, 0xFFFFu, &loss));
  }
  CHECK(host_cs_depth == 0);
}

/* B02 oracle: a critical record staged for export, then an identical fault
 * while MT allocates/sends (the ISR window), must not lose the newer
 * occurrence. Retirement by full staged identity reports the staleness
 * (DIAG_LOSS 3u, staged vs live repeats), retires nothing, and the next
 * poll re-stages the coalesced entry whole. */
static void test_b02_staged_coalesce_preserved(void)
{
  T832DiagRecord staged_copy;
  uint8_t sel;
  DecRec r;
  fresh(9u);
  emit_one();
  CHECK(t832Diag.critical_count == 0u);
  T832Diag_npiTrap(300u, 100u);
  CHECK(t832Diag.critical_count == 1u);
  sel = T832Diag_peekAt(0u, 0u, &staged_copy);
  CHECK(sel == 1u);
  CHECK(staged_copy.repeat_count == 1u);
  /* The ISR-identical fault lands between staging and retirement. */
  T832Diag_npiTrap(300u, 100u);
  T832Diag_popPeeked(sel, staged_copy.sequence, staged_copy.first_ms,
                     staged_copy.last_ms, 1u);
  CHECK(t832Diag.critical_count == 1u);
  /* Re-stage before any drain: the coalesced entry (repeat 2) exports
   * whole and retires. */
  sel = T832Diag_peekAt(0u, 0u, &staged_copy);
  CHECK(sel == 1u);
  CHECK(staged_copy.repeat_count == 2u);
  T832Diag_popPeeked(sel, staged_copy.sequence, staged_copy.first_ms,
                     staged_copy.last_ms, staged_copy.repeat_count);
  CHECK(t832Diag.critical_count == 0u);
  drain_all();
  CHECK(find_kind_ab(T832_DIAG_EV_DIAG_LOSS, 3u, 1u, &r));
  CHECK(r.c == 2u);
  CHECK(host_cs_depth == 0);
  (void)r;
}

/* B02 saturated repeats: the count pins at 0xFFFF (documented bound) while
 * timing extends; a pre-saturation staged copy is stale (loss reported),
 * the saturated entry retires by its saturated identity. */
static void test_b02_saturated_repeat_identity(void)
{
  T832DiagRecord staged_copy;
  T832DiagRecord *tail;
  uint8_t sel;
  uint16_t cap = T832_DIAG_CRITICAL_RECORDS;
  DecRec r;
  fresh(9u);
  emit_one();
  T832Diag_npiTrap(300u, 100u);
  sel = T832Diag_peekAt(0u, 0u, &staged_copy);
  CHECK(sel == 1u);
  tail = &t832Diag.critical[(uint16_t)((t832Diag.critical_head + cap - 1u) % cap)];
  tail->repeat_count = 0xFFFFu;
  advance_ms(10u);
  T832Diag_npiTrap(300u, 100u);
  CHECK(tail->repeat_count == 0xFFFFu);
  T832Diag_popPeeked(sel, staged_copy.sequence, staged_copy.first_ms,
                     staged_copy.last_ms, 1u);
  CHECK(t832Diag.critical_count == 1u);
  sel = T832Diag_peekAt(0u, 0u, &staged_copy);
  CHECK(staged_copy.repeat_count == 0xFFFFu);
  T832Diag_popPeeked(sel, staged_copy.sequence, staged_copy.first_ms,
                     staged_copy.last_ms, staged_copy.repeat_count);
  CHECK(t832Diag.critical_count == 0u);
  drain_all();
  CHECK(find_kind_ab(T832_DIAG_EV_DIAG_LOSS, 3u, 1u, &r));
  CHECK(r.c == 0xFFFFu);
  CHECK(host_cs_depth == 0);
  (void)r;
}

/* B02 wrap/collision: first_ms disambiguates same-sequence entries. A
 * staged identity from before a sequence reuse must not retire the newer
 * same-sequence entry. */
static void test_b02_sequence_reuse_identity(void)
{
  T832DiagRecord staged_a;
  T832DiagRecord staged_b;
  uint8_t sel;
  DecRec r;
  fresh(9u);
  emit_one();
  T832Diag_npiTrap(300u, 100u);
  sel = T832Diag_peekAt(0u, 0u, &staged_a);
  CHECK(sel == 1u);
  /* Force a sequence reuse: the next record takes A's 16-bit sequence
   * with a different creation time (the wrap-collision shape). The
   * recorder pre-increments a 32-bit counter and truncates, so seeding
   * S-1 (mod 2^32) reuses S exactly, including across the S==0 wrap. */
  advance_ms(5u);
  t832Diag.record_sequence = (uint32_t)(staged_a.sequence - 1u);
  T832Diag_npiTrap(301u, 101u);
  /* Tail is still A: A's identity retires exactly A. */
  T832Diag_popPeeked(sel, staged_a.sequence, staged_a.first_ms,
                     staged_a.last_ms, staged_a.repeat_count);
  CHECK(t832Diag.critical_count == 1u);
  /* Tail is now B: same reused sequence, different creation time. */
  sel = T832Diag_peekAt(0u, 0u, &staged_b);
  CHECK(sel == 1u);
  CHECK(staged_b.sequence == staged_a.sequence);
  CHECK(staged_b.first_ms != staged_a.first_ms);
  /* A's stale identity must not retire B. */
  T832Diag_popPeeked(sel, staged_a.sequence, staged_a.first_ms,
                     staged_a.last_ms, staged_a.repeat_count);
  CHECK(t832Diag.critical_count == 1u);
  /* B retires by its own identity. */
  sel = T832Diag_peekAt(0u, 0u, &staged_b);
  T832Diag_popPeeked(sel, staged_b.sequence, staged_b.first_ms,
                     staged_b.last_ms, staged_b.repeat_count);
  CHECK(t832Diag.critical_count == 0u);
  drain_all();
  CHECK(find_kind_ab(T832_DIAG_EV_DIAG_LOSS, 3u, 1u, &r));
  CHECK(host_cs_depth == 0);
  (void)r;
}

/* B03 oracle: producer traffic interleaved at every remaining section
 * boundary cannot steal an SRSP's SREQ stamp or skew pending pairing.
 * Each SRSP keeps its own generation; only the current-generation
 * completion clears suppression; pending converges exactly. */
static void test_b03_srsp_generation_atomic(void)
{
  uint8_t srsp[1] = {0};
  uint8_t payload[2] = {1, 2};
  DecRec r;
  fresh(9u);
  emit_one();
  T832Diag_commandRx(0x21u, 0x01u);
  T832Diag_commandDispatch(0x21u, 0x01u);
  T832Diag_commandComplete(0x21u, 0x01u, 0u);
  sdk_client_queue_mirror(0x61u, 0x01u, 1u, srsp, 0);
  /* Producer burst at the former split boundary: pushes between the SRSP
   * queue and its completion must not move or copy its stamp. */
  sdk_client_queue_mirror(0x41u, 0x70u, 2u, payload, 0);
  sdk_sendToHost_mirror(0x41u, 0x71u, 2u, 0u);
  CHECK(t832Diag.txq_count == 3u);
  CHECK(t832Diag.normal_pending == 3u);
  CHECK(t832Diag.txq[t832Diag.txq_head].gen == t832Diag.sync_gen);
  T832Diag_commandRx(0x21u, 0x02u);
  sdk_client_queue_mirror(0x61u, 0x02u, 1u, srsp, 0);
  CHECK(t832Diag.txq_count == 4u);
  CHECK(t832Diag.normal_pending == 4u);
  /* Stale SRSP1 completes first: abandon, suppression held for SREQ2. */
  wire_dequeue_finish(0xFEu, 0x61u, 0x01u, 1u);
  CHECK(t832Diag.sync_outstanding == 1u);
  /* SRSP2's dequeue retires both caught-between NORMAL frames as
   * unknown-outcome: explicitly uncertain, never delivered. */
  wire_dequeue_finish(0xFEu, 0x61u, 0x02u, 1u);
  CHECK(t832Diag.sync_outstanding == 0u);
  CHECK(t832Diag.tx_uncertain_n == 2u);
  CHECK(t832Diag.txq_count == 0u);
  CHECK(t832Diag.normal_pending == 0u);
  drain_all();
  CHECK(find_kind_ab(T832_DIAG_EV_SYNC_ABANDON, 2u, 0x61u, &r));
  CHECK(find_kind_ab(T832_DIAG_EV_TX_MISMATCH, 2u, 0x61u, &r));
  CHECK(host_cs_depth == 0);
  CHECK(host_cs_max_depth <= 4);
  (void)r;
}

/* B03 oracle: AF confirm/remove is atomic with generation re-validation.
 * Same-key replacement survives; churn preserves outstanding == used;
 * nonzero confirms stay rejects; the 8u replacement race never fires. */
static void test_b03_af_confirm_replacement(void)
{
  uint8_t req[13] = {10, 0x24, 0x01, 0x34, 0x12, 3, 5, 6, 7, 0x33, 0x30, 0x1E, 0};
  uint8_t k;
  uint8_t used;
  DecRec r;
  fresh(9u);
  emit_one();
  T832Diag_afDispatch(0x24u, 0x01u, req, 13u);
  queue_srps_ok_finish();
  CHECK(t832Diag.af_outstanding == 1u);
  /* Same-key replacement supersedes (generation bumps); the confirm for
   * the key removes exactly one live entry, not a phantom. */
  T832Diag_afDispatch(0x24u, 0x01u, req, 13u);
  queue_srps_ok_finish();
  CHECK(t832Diag.af_outstanding == 1u);
  T832Diag_afConfirm(0u, 5u, 0x33u);
  CHECK(t832Diag.af_outstanding == 0u);
  CHECK(t832Diag.af_confirmed_n == 1u);
  /* Churn: interleaved inserts, confirms (ok + nonzero) and evictions
   * keep outstanding == used slots at every step. */
  for (k = 0u; k < 24u; k++) {
    req[6] = (uint8_t)(0x40u + (k % 10u));
    req[9] = (uint8_t)(0x50u + k);
    T832Diag_afDispatch(0x24u, 0x01u, req, 13u);
    queue_srps_ok_finish();
    if ((k % 3u) == 2u) {
      T832Diag_afConfirm((uint8_t)(k % 2u), (uint8_t)(0x40u + (k % 10u)),
                         (uint8_t)(0x50u + k));
    }
    {
      uint8_t i;
      uint8_t n = 0u;
      for (i = 0u; i < T832_DIAG_AF_DEPTH; i++) {
        if (t832Diag.af[i].used) n++;
      }
      CHECK(t832Diag.af_outstanding == n);
    }
  }
  used = 0u;
  {
    uint8_t i;
    for (i = 0u; i < T832_DIAG_AF_DEPTH; i++) {
      if (t832Diag.af[i].used) used++;
    }
  }
  CHECK(t832Diag.af_outstanding == used);
  CHECK(t832Diag.af_outstanding <= T832_DIAG_AF_DEPTH);
  drain_all();
  /* The 8u replacement race never fires under churn. */
  {
    uint32_t i = host_frame_count;
    int saw_race = 0;
    while (i > 0u) {
      DecFrame f;
      int k;
      i--;
      if (decode_frame(i, &f) <= 0) continue;
      for (k = 0; k < (int)f.nrec; k++) {
        if (f.rec[k].kind == T832_DIAG_EV_AF_ANOMALY && f.rec[k].a == 8u) {
          saw_race = 1;
        }
      }
    }
    CHECK(saw_race == 0);
  }
  CHECK(host_cs_depth == 0);
  CHECK(host_cs_max_depth <= 4);
  (void)r;
}

/* A02/S02: nine frames into an eight-slot shadow; the ninth is refused
 * without corrupting the eight owned descriptors, and every completion
 * converges back to zero pending with telemetry resumed. */
static void test_fifo_overflow_converges(void)
{
  uint8_t payload[2] = {1, 2};
  uint8_t k;
  DecRec r;
  fresh(9u);
  emit_one();
  for (k = 0u; k < 8u; k++) {
    T832Diag_responseQueued(0x41u, (uint8_t)(0x20u + (k % 4u)), 2u, payload);
  }
  CHECK(t832Diag.txq_count == 8u);
  CHECK(t832Diag.normal_pending == 8u);
  T832Diag_responseQueued(0x41u, 0x20u, 2u, payload);
  CHECK(t832Diag.txq_count == 8u);
  CHECK(t832Diag.normal_pending == 8u);
  CHECK(t832Diag.tx_overflow_n == 1u);
  for (k = 0u; k < 8u; k++) {
    wire_dequeue_finish(0xFEu, 0x41u, (uint8_t)(0x20u + (k % 4u)), 2u);
  }
  CHECK(t832Diag.txq_count == 0u);
  CHECK(t832Diag.normal_pending == 0u);
  CHECK(t832Diag.tx_uncertain_n == 0u);
  emit_one();
  /* The refused ninth frame still reaches wire untracked: no ghost. */
  T832Diag_npiTxDequeue(0xFEu, 0x41u, 0x20u, 2u);
  CHECK(t832Diag.normal_pending == 0u);
  T832Diag_uartTxStart(7u);
  advance_ms(2u);
  T832Diag_uartTxFinished(7u);
  CHECK(t832Diag.normal_pending == 0u);
  CHECK(t832Diag.tx_untracked_n == 1u);
  CHECK(t832Diag.tx_unsol_n == 1u);
  drain_all();
  CHECK(find_kind_ab(T832_DIAG_EV_TX_MISMATCH, 5u, 0x41u, &r));
  CHECK(find_kind_ab(T832_DIAG_EV_TX_MISMATCH, 10u, 0x41u, &r));
  CHECK(host_cs_depth == 0);
  CHECK(host_cs_max_depth <= 4);
  (void)r;
}

/* A02/S02: a completion matching a deeper descriptor retires only the
 * older ones as unknown-outcome; an unknown frame is untracked. */
static void test_mismatch_retire(void)
{
  uint8_t payload[2] = {1, 2};
  DecRec r;
  fresh(9u);
  emit_one();
  T832Diag_responseQueued(0x41u, 0x30u, 2u, payload);
  T832Diag_responseQueued(0x41u, 0x31u, 2u, payload);
  T832Diag_responseQueued(0x41u, 0x32u, 2u, payload);
  CHECK(t832Diag.normal_pending == 3u);
  T832Diag_npiTxDequeue(0xFEu, 0x41u, 0x32u, 2u);
  CHECK(t832Diag.txq_count == 0u);
  CHECK(t832Diag.normal_pending == 1u);
  CHECK(t832Diag.tx_uncertain_n == 2u);
  T832Diag_uartTxStart(7u);
  advance_ms(2u);
  T832Diag_uartTxFinished(7u);
  CHECK(t832Diag.normal_pending == 0u);
  CHECK(t832Diag.txq_count == 0u);
  T832Diag_npiTxDequeue(0xFEu, 0x41u, 0x77u, 2u);
  T832Diag_uartTxStart(7u);
  advance_ms(2u);
  T832Diag_uartTxFinished(7u);
  CHECK(t832Diag.normal_pending == 0u);
  CHECK(t832Diag.tx_untracked_n == 1u);
  drain_all();
  CHECK(find_kind_ab(T832_DIAG_EV_TX_MISMATCH, 2u, 0x41u, &r));
  CHECK(find_kind_ab(T832_DIAG_EV_TX_MISMATCH, 10u, 0x41u, &r));
  CHECK(host_cs_depth == 0);
  (void)r;
}

/* A02/S02: a callback-less UART write rejection releases the in-flight
 * ownership as refused, never as delivered; a stray finish cannot recount. */
static void test_write_reject(void)
{
  uint8_t payload[2] = {1, 2};
  DecRec r;
  fresh(9u);
  emit_one();
  T832Diag_responseQueued(0x41u, 0x40u, 2u, payload);
  T832Diag_npiTxDequeue(0xFEu, 0x41u, 0x40u, 2u);
  T832Diag_uartTxStart(7u);
  {
    uint32_t orphan_before = t832Diag.tx_orphan_n;
    T832Diag_uartWriteRejected(7u, (int16_t)-1);
    CHECK(t832Diag.tx_orphan_n == orphan_before + 1u);
  }
  CHECK(t832Diag.normal_pending == 0u);
  CHECK(t832Diag.inflight_valid == 0u);
  CHECK(t832Diag.transport_active == 0u);
  T832Diag_uartTxFinished(7u);
  CHECK(t832Diag.normal_pending == 0u);
  CHECK(t832Diag.tx_untracked_n == 1u);
  emit_one();
  drain_all();
  CHECK(find_kind_ab(T832_DIAG_EV_TX_MISMATCH, 11u, 0x41u, &r));
  CHECK(find_kind(T832_DIAG_EV_NPI_WRITE_REJECT, &r));
  (void)r;
}

/* A03/S03: staged records retire by identity. Overwriting the staged entry
 * before retirement reports the loss and retires nothing newer. */
static void test_staged_retire_identity(void)
{
  T832DiagRecord staged_copy;
  uint8_t sel;
  uint16_t k;
  DecRec r;
  DecFrame f;
  uint32_t i;
  int k2;
  int seen_newest = 0;
  fresh(9u);
  emit_one();
  for (k = 0u; k < 64u; k++) {
    T832Diag_commandRx(0x41u, (uint8_t)k);
  }
  CHECK(t832Diag.routine_count == 64u);
  sel = T832Diag_peekAt(0u, 0u, &staged_copy);
  CHECK(sel == 2u);
  for (k = 64u; k < 128u; k++) {
    T832Diag_commandRx(0x41u, (uint8_t)k);
  }
  CHECK(t832Diag.routine_count == 64u);
  CHECK(t832Diag.routine_overwrite == 64u);
  {
    uint16_t before = t832Diag.routine_count;
    T832Diag_popPeeked(sel, staged_copy.sequence, staged_copy.first_ms,
                       staged_copy.last_ms, staged_copy.repeat_count);
    CHECK(t832Diag.routine_count == before);
  }
  sel = T832Diag_peekAt(0u, 0u, &staged_copy);
  CHECK(sel == 2u);
  T832Diag_popPeeked(sel, staged_copy.sequence, staged_copy.first_ms,
                     staged_copy.last_ms, staged_copy.repeat_count);
  CHECK(t832Diag.routine_count == 63u);
  drain_all();
  CHECK(find_kind_ab(T832_DIAG_EV_DIAG_LOSS, 2u, 2u, &r));
  for (i = 0u; i < host_frame_count; i++) {
    if (decode_frame(i, &f) <= 0) continue;
    for (k2 = 0; k2 < (int)f.nrec; k2++) {
      if (f.rec[k2].kind == T832_DIAG_EV_MT_COMMAND_RX &&
          f.rec[k2].a == 0x41u && f.rec[k2].b == 127u) {
        seen_newest = 1;
      }
    }
  }
  CHECK(seen_newest == 1);
  CHECK(host_cs_depth == 0);
  (void)r;
}

/* A04/S04: only the SRSP stamped with the current SREQ generation clears
 * suppression; late older SRSPs stay suppressed explicitly. */
static void test_sreq_generations(void)
{
  uint8_t srsp[1] = {0};
  uint8_t srsp_err[1] = {5};
  DecRec r;
  fresh(9u);
  emit_one();
  T832Diag_commandRx(0x21u, 0x01u);
  T832Diag_commandDispatch(0x21u, 0x01u);
  T832Diag_commandComplete(0x21u, 0x01u, 0u);
  T832Diag_responseQueued(0x61u, 0x01u, 1u, srsp);
  T832Diag_commandRx(0x21u, 0x02u);
  wire_dequeue_finish(0xFEu, 0x61u, 0x01u, 1u);
  CHECK(t832Diag.sync_outstanding == 1u);
  CHECK(t832Diag.normal_pending == 0u);
  T832Diag_commandDispatch(0x21u, 0x02u);
  T832Diag_commandComplete(0x21u, 0x02u, 0u);
  T832Diag_responseQueued(0x61u, 0x02u, 1u, srsp);
  wire_dequeue_finish(0xFEu, 0x61u, 0x02u, 1u);
  CHECK(t832Diag.sync_outstanding == 0u);
  T832Diag_commandRx(0x21u, 0x03u);
  T832Diag_responseQueued(0x61u, 0x03u, 1u, srsp);
  T832Diag_commandRx(0x21u, 0x03u);
  wire_dequeue_finish(0xFEu, 0x61u, 0x03u, 1u);
  CHECK(t832Diag.sync_outstanding == 1u);
  T832Diag_responseQueued(0x61u, 0x03u, 1u, srsp);
  wire_dequeue_finish(0xFEu, 0x61u, 0x03u, 1u);
  CHECK(t832Diag.sync_outstanding == 0u);
  T832Diag_commandRx(0x21u, 0x04u);
  T832Diag_responseQueued(0x61u, 0x04u, 1u, srsp_err);
  wire_dequeue_finish(0xFEu, 0x61u, 0x04u, 1u);
  CHECK(t832Diag.sync_outstanding == 0u);
  drain_all();
  CHECK(find_kind_ab(T832_DIAG_EV_SYNC_ABANDON, 1u, 0x21u, &r));
  CHECK(find_kind_ab(T832_DIAG_EV_SYNC_ABANDON, 2u, 0x61u, &r));
  CHECK(host_cs_depth == 0);
  (void)r;
}

/* A05/S05: fifteen simulated minutes of one-second polls with a sticky
 * fault, scheduling pressure, busy transports, a sync stall and MT build
 * refusals. Asserts true schedule deltas, all 13 resource selectors within a
 * bounded export gap, retained overdue work, first-fault repeats with
 * original identity, bounded ring draining and exact wire budgets. */
static void test_fair_schedule_15min(void)
{
  uint32_t t;
  uint32_t scanned = 0u;
  uint32_t exports = 0u;
  uint32_t last_export_t = 0u;
  uint32_t health_nonzero = 0u;
  uint32_t fault_repeats = 0u;
  uint32_t fault_orig_ok = 0u;
  uint32_t sel_seen[13] = {0};
  uint32_t sel_last[13];
  uint32_t sel_maxgap[13] = {0};
  uint32_t s;
  uint8_t srsp[1] = {0};
  DecFrame f;
  int k;
  for (s = 0u; s < 13u; s++) sel_last[s] = 0xFFFFFFFFu;
  fresh(9u);
  emit_one();
  exports = host_frame_count;
  last_export_t = 0u;
  /* Sticky fault: response-alloc failure is critical, no transport involved. */
  T832Diag_responseAllocFailed(0x21u, 0x01u, 9u);
  for (t = 1u; t <= 900u; t++) {
    advance_ms(1000u);
    if (t % 3u == 0u) T832Diag_taskScheduled(9u, 0x0040u);
    if (t >= 200u && t < 260u) t832Diag.transport_active = 1u;
    else if (t == 260u) t832Diag.transport_active = 0u;
    if (t == 500u) T832Diag_commandRx(0x21u, 0x09u);
    if (t == 560u) {
      T832Diag_responseQueued(0x61u, 0x09u, 1u, srsp);
      wire_dequeue_finish(0xFEu, 0x61u, 0x09u, 1u);
    }
    if (t == 420u || t == 840u) host_fail_alloc = 1u;
    T832Diag_exportPoll();
    if (t832Diag.diag_pending) wire_complete_diag(host_frame_count - 1u);
    while (scanned < host_frame_count) {
      uint32_t gap;
      CHECK(decode_frame(scanned, &f) > 0);
      CHECK(f.nrec <= 4u);
      CHECK(host_frame_len[scanned] <= 234u);
      exports++;
      gap = t - last_export_t;
      /* The pre-loop baseline export has no poll timestamp: it is decoded
       * at t=1 but exported at now~=0, so the first loop export's poll gap
       * (5-1=4) is decode skew, not a schedule violation (the 5000 ms
       * throttle itself guarantees the true 5 s delta). Measure from the
       * second loop export on, where decode poll == export poll. */
      if (scanned > 1u) CHECK(gap >= 5u);
      last_export_t = t;
      for (k = 0; k < (int)f.nrec; k++) {
        if (f.rec[k].kind == T832_DIAG_EV_HEALTH) {
          if (f.rec[k].a != 0u) health_nonzero++;
        } else if (f.rec[k].kind == T832_DIAG_EV_RESOURCE) {
          uint8_t sel = (uint8_t)f.rec[k].a;
          CHECK(sel >= 1u && sel <= 13u);
          sel_seen[sel - 1u]++;
          if (sel_last[sel - 1u] != 0xFFFFFFFFu) {
            uint32_t g = exports - sel_last[sel - 1u];
            if (g > sel_maxgap[sel - 1u]) sel_maxgap[sel - 1u] = g;
          }
          sel_last[sel - 1u] = exports;
        } else if (f.rec[k].kind == T832_DIAG_EV_FIRST_FAULT) {
          fault_repeats++;
          if ((f.rec[k].flags & 2u) &&
              (uint8_t)(f.rec[k].flags >> 2) == T832_DIAG_EV_RESPONSE_ALLOC_FAIL &&
              f.rec[k].a == 0x21u) {
            fault_orig_ok = 1u;
          }
        }
      }
      scanned++;
    }
  }
  CHECK(health_nonzero > 0u);
  CHECK(fault_repeats >= 5u);
  CHECK(fault_orig_ok == 1u);
  CHECK(t832Diag.export_skipped > 0u);
  for (s = 0u; s < 13u; s++) {
    CHECK(sel_seen[s] >= 2u);
    /* Bounded revisit: a full 13-selector rotation is 7 resource-due
     * cycles (~7 min) plus stall windows; 100 exports (~8.3 min) bounds it. */
    CHECK(sel_maxgap[s] <= 100u);
  }
  drain_all();
  CHECK(t832Diag.critical_count <= 64u);
  CHECK(t832Diag.routine_count <= 64u);
  CHECK(host_cs_depth == 0);
}

/* A06/S06: main() order — NV init, fault and recovery hooks run before MT
 * init; every early event and the first-fault identity survive with an
 * honest approximate-timing marker. */
static void test_early_nv_preserved(void)
{
  DecRec r;
  DecFrame f;
  uint32_t i;
  int k;
  int seen_nv_init = 0;
  int seen_nv_start = 0;
  int seen_nv_fault = 0;
  int seen_approx = 0;
  int seen_orig = 0;
  host_tick = 0u;
  host_cs_depth = 0;
  host_cs_max_depth = 0;
  host_fail_alloc = 0;
  host_frame_count = 0u;
  host_heap_total = 6144u;
  host_heap_free = 4096u;
  host_heap_largest = 2048u;
  t832DiagResetCauseMagic = (uint32_t)T832_DIAG_BOOT_MAGIC;
  t832DiagResetCauseEarly = 0x61u;
  memset(&t832Diag, 0, sizeof(t832Diag));
  T832Diag_nvInit(0u);
  T832Diag_nvEvent(1u, 7u, 0u);
  T832Diag_nvEvent(3u, 7u, 0u);
  CHECK(t832Diag.initialized == 0u);
  T832Diag_init(9u);
  CHECK(t832Diag.initialized == 1u);
  advance_ms(6000u);
  T832Diag_exportPoll();
  wire_complete_diag(host_frame_count - 1u);
  drain_all();
  for (i = 0u; i < host_frame_count; i++) {
    if (decode_frame(i, &f) <= 0) continue;
    for (k = 0; k < (int)f.nrec; k++) {
      if (f.rec[k].kind == T832_DIAG_EV_NV_EVENT && f.rec[k].a == 5u) {
        seen_nv_init = 1;
      }
      if (f.rec[k].kind == T832_DIAG_EV_NV_EVENT && f.rec[k].a == 1u &&
          f.rec[k].b == 7u) {
        seen_nv_start = 1;
      }
      if (f.rec[k].kind == T832_DIAG_EV_NV_FAULT) {
        seen_nv_fault = 1;
      }
      if (f.rec[k].kind == T832_DIAG_EV_TIMING_APPROX && f.rec[k].a == 3u) {
        seen_approx = 1;
      }
      if (f.rec[k].kind == T832_DIAG_EV_FIRST_FAULT &&
          (uint8_t)(f.rec[k].flags >> 2) == T832_DIAG_EV_NV_FAULT) {
        seen_orig = 1;
      }
    }
  }
  CHECK(seen_nv_init == 1);
  CHECK(seen_nv_start == 1);
  CHECK(seen_nv_fault == 1);
  CHECK(seen_approx == 1);
  CHECK(seen_orig == 1);
  CHECK(find_kind(T832_DIAG_EV_BOOT, &r));
  (void)r;
}

/* Queue one accepted AF SRSP and run it through the real wire path so TX
 * ownership never accumulates inside AF-table tests. */
static void queue_srps_ok_finish(void)
{
  uint8_t srsp_ok[1] = {0};
  T832Diag_responseQueued(0x64u, 0x01u, 1u, srsp_ok);
  wire_dequeue_finish(0xFEu, 0x64u, 0x01u, 1u);
}

/* A07/S07: duplicate keys supersede in place (no phantom), failed confirms
 * keep raw status as rejects, oldest age recomputes from survivors,
 * wrap-safe eviction drops the largest age, AREQ work tracks unconfirmed. */
static void test_af_correlation(void)
{
  uint8_t req[13] = {10, 0x24, 0x01, 0x34, 0x12, 3, 5, 6, 7, 0x33, 0x30, 0x1E, 0};
  uint8_t areq[10] = {7, 0x44, 0x01, 0x34, 0x12, 3, 9, 6, 7, 0x44};
  uint8_t k;
  DecRec r;
  fresh(9u);
  emit_one();
  T832Diag_afDispatch(0x24u, 0x01u, req, 13u);
  queue_srps_ok_finish();
  T832Diag_afDispatch(0x24u, 0x01u, req, 13u);
  queue_srps_ok_finish();
  CHECK(t832Diag.af_outstanding == 1u);
  CHECK(t832Diag.af_unconfirmed_n == 0u);
  CHECK(t832Diag.af_accepted_n == 1u);
  T832Diag_afConfirm(5u, 5u, 0x33u);
  CHECK(t832Diag.af_outstanding == 0u);
  CHECK(t832Diag.af_confirmed_n == 0u);
  CHECK(t832Diag.af_rejected_n == 1u);
  T832Diag_afDispatch(0x44u, 0x01u, areq, 10u);
  CHECK(t832Diag.af_unconfirmed_n == 1u);
  CHECK(t832Diag.af_areq_n == 1u);
  T832Diag_afConfirm(0u, 9u, 0x44u);
  CHECK(t832Diag.af_unconfirmed_n == 0u);
  CHECK(t832Diag.af_confirmed_n == 1u);
  /* Oldest recompute: remove A, age must track surviving B (30, not 80).
   * The AF key is (SrcEp, TransID) = payload bytes 3 and 6, i.e. req[6]
   * and req[9] (AF_DATA_REQUEST: DstAddr(2), DstEp, SrcEp, Cluster(2),
   * TransID, ...); req[5] is DstEp and plays no part in correlation. */
  advance_ms(100u);
  req[6] = 6u; req[9] = 0x34u;
  T832Diag_afDispatch(0x24u, 0x01u, req, 13u);
  queue_srps_ok_finish();
  advance_ms(50u);
  req[6] = 7u; req[9] = 0x35u;
  T832Diag_afDispatch(0x24u, 0x01u, req, 13u);
  queue_srps_ok_finish();
  advance_ms(30u);
  T832Diag_afConfirm(0u, 6u, 0x34u);
  CHECK(t832Diag.af_outstanding == 1u);
  {
    T832DiagRecord st = T832Diag_liveAfState((uint32_t)T832Diag_nowMs());
    /* Survivor age: 30 ms of advances between B's insert and this read,
     * plus the 2 ms UART TX model inside B's own wire finish (the insert
     * lands before the +2). Without oldest-recompute the removed A's time
     * would linger and report 84. */
    CHECK(st.b == 32u);
  }
  T832Diag_afConfirm(0u, 7u, 0x35u);
  CHECK(t832Diag.af_outstanding == 0u);
  /* Wrap-safe eviction across a tick wrap: drop largest age, keep newest. */
  host_tick = 0xFFFFFF00u;
  T832Diag_afDispatch(0x24u, 0x01u, req, 13u);
  queue_srps_ok_finish();
  advance_ms(2000u);
  for (k = 0u; k < 7u; k++) {
    req[5] = (uint8_t)(0x50u + k);
    req[9] = (uint8_t)(0x60u + k);
    T832Diag_afDispatch(0x24u, 0x01u, req, 13u);
    queue_srps_ok_finish();
  }
  CHECK(t832Diag.af_outstanding == 8u);
  req[5] = 0x58u; req[9] = 0x68u;
  T832Diag_afDispatch(0x24u, 0x01u, req, 13u);
  queue_srps_ok_finish();
  CHECK(t832Diag.af_outstanding == 8u);
  /* Victim was the pre-wrap oldest by age (ep 7/trans 0x35): confirming it
   * is now an orphan, while the post-wrap entries still correlate. */
  T832Diag_afConfirm(0u, 7u, 0x35u);
  CHECK(t832Diag.af_outstanding == 8u);
  /* Correlate by the true key (SrcEp 7, TransID 0x60): req[5] is DstEp. */
  T832Diag_afConfirm(0u, 7u, 0x60u);
  CHECK(t832Diag.af_outstanding == 7u);
  drain_all();
  CHECK(find_kind_ab(T832_DIAG_EV_AF_REJECT, 5u, 0x33u, &r));
  CHECK(find_kind_ab(T832_DIAG_EV_AF_ANOMALY, 1u, 7u, &r));
  CHECK(find_kind_ab(T832_DIAG_EV_AF_ANOMALY, 4u, 7u, &r));
  (void)r;
}

int main(int argc, char **argv)
{
  if (argc == 3 && strcmp(argv[1], "dump") == 0) {
    dump_scenario(argv[2]);
    if (failures) {
      printf("HARNESS RESULT: FAIL (%d)\n", failures);
      return 1;
    }
    return 0;
  }
  test_sizes();
  test_boot_and_caps();
  test_boot_invalid();
  test_sync_gate();
  test_overtake_completion();
  test_flood_and_coalesce();
  test_diag_traffic_excluded();
  test_diag_build_loss();
  test_task_events();
  test_af_accept_confirm();
  test_af_variants_overflow();
  test_nv_events();
  test_npi_paths();
  test_tx_refused_stages();
  test_b01_identical_headers_refusal();
  test_f01_owned_refusals_drain_and_export();
  test_f01_refused_overflow_preserves_survivors();
  test_f09_af_evict_recomputes_oldest();
  test_f10_saturated_last_ms_preserved();
  test_b02_staged_coalesce_preserved();
  test_b02_saturated_repeat_identity();
  test_b02_sequence_reuse_identity();
  test_b03_srsp_generation_atomic();
  test_b03_af_confirm_replacement();
  test_fifo_overflow_converges();
  test_mismatch_retire();
  test_write_reject();
  test_staged_retire_identity();
  test_sreq_generations();
  test_fair_schedule_15min();
  test_early_nv_preserved();
  test_af_correlation();
  test_tick_wrap();
  test_heap_resource();
  test_frame_budget();
  if (failures) {
    printf("HARNESS RESULT: FAIL (%d)\n", failures);
    return 1;
  }
  printf("HARNESS RESULT: PASS\n");
  return 0;
}
