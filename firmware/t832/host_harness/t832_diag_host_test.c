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
  T832Diag_taskWork(T832_DIAG_WORK_ZSTACK, SYS_EVENT_MSG);
  T832Diag_npiTaskWake();
  CHECK(t832Diag.zstack_work_ms != 0u);
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
  /* NPI TX-side drop reconciles the matching queue entry and pending flag. */
  T832Diag_responseQueued(0x41u, 0x04u, 2u, payload);
  CHECK(t832Diag.normal_pending == 1u);
  {
    uint32_t orphan_before = t832Diag.tx_orphan_n;
    T832Diag_npiAllocFailed(1u, 12u, 0x41u, 0x04u, 2u);
    CHECK(t832Diag.normal_pending == 0u);
    CHECK(t832Diag.txq_count == 0u);
    CHECK(t832Diag.tx_orphan_n == orphan_before + 1u);
  }
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
  /* One resource slot per export while the 10 s health triple is due, so a
   * full 13-slot rotation needs 13 exports; run 14 for margin. */
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

/* A01/S01: every real TX refusal stage reconciles only its owned entry;
 * RX refusals never touch ownership. Same call order as the patched SDK
 * (queue observes first, refusal reconciles after). */
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
    uint32_t orphan_before = t832Diag.tx_orphan_n;
    T832Diag_responseQueued(cmd0, cmd1, 2u, payload);
    CHECK(t832Diag.normal_pending == 1u);
    CHECK(t832Diag.txq_count == 1u);
    T832Diag_npiTxRefused(stage, cmd0, cmd1, 2u);
    CHECK(t832Diag.normal_pending == 0u);
    CHECK(t832Diag.txq_count == 0u);
    CHECK(t832Diag.tx_orphan_n == orphan_before + 1u);
    CHECK(t832Diag.response_queued == 0u);
  }
  /* Refusal with no owned entry: reported, nothing released. */
  {
    uint32_t pending_before = t832Diag.normal_pending;
    T832Diag_npiTxRefused(3u, 0x41u, 0x77u, 2u);
    CHECK(t832Diag.normal_pending == pending_before);
  }
  drain_all();
  for (stage = 1u; stage <= 6u; stage++) {
    CHECK(find_kind_ab(T832_DIAG_EV_NPI_ALLOC_FAIL, 1u, stage, &r));
  }
  CHECK(find_kind_ab(T832_DIAG_EV_TX_MISMATCH, 14u, 0x41u, &r));
  CHECK(host_cs_depth == 0);
  CHECK(host_cs_max_depth <= 4u);
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
  CHECK(host_cs_max_depth <= 4u);
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
  CHECK(t832Diag.txq_count == 1u);
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
    T832Diag_popPeeked(sel, staged_copy.sequence);
    CHECK(t832Diag.routine_count == before);
  }
  sel = T832Diag_peekAt(0u, 0u, &staged_copy);
  CHECK(sel == 2u);
  T832Diag_popPeeked(sel, staged_copy.sequence);
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
  test_fifo_overflow_converges();
  test_mismatch_retire();
  test_write_reject();
  test_staged_retire_identity();
  test_sreq_generations();
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
