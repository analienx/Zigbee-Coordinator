#!/usr/bin/env python3
"""Real producer-to-UART chain C proof for the TXQ strand witness.

Compiles the actual composed bodies: MT_BuildAndSendZToolResponse ->
OsalPort queue -> NPITask_processStackMsg -> NPITask_ProcessTXQ ->
NPITL_writeTL -> NPITLUART_writeTransport/callback -> TL completion ->
NPITask_transportTxDoneCallBack, plus the real NPITask_process message,
TX_READY and TX_DONE sections and the snapshot strand check. Only OSAL,
Queue, semaphore and UART2 driver primitives are stubs; queue and counter
state are the real composed variables, never re-implemented mirrors.
Hosted disposable source only; no serial, hardware, NV or RF access.
"""
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from r4_uart_tx_liveness import TL, UART, extract
from r4_uart_tx_liveness_harness import actual_functions
from r4_txq_strand_witness import TASK

CLIENT = "source/ti/zstack/npi/npi_client_mt.c"
STATUS = "PASS_REAL_PRODUCER_TXQ_CHAIN_BURST_AND_STRAND_MUTANTS"
CASES = ("burst", "stranded_snapshot", "blocked", "failed")


def _statement(text, marker):
    if text.count(marker) != 1:
        raise RuntimeError("TXQ_HARNESS_STATEMENT_DRIFT_" + marker[:40])
    start = text.index(marker)
    opening = text.index("{", start)
    depth = 0
    for pos in range(opening, len(text)):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                return text[start:pos + 1]
    raise RuntimeError("TXQ_HARNESS_STATEMENT_UNBALANCED")


def _sections(task):
    process = extract(task, "static void NPITask_process(void)")
    merge = process.split(
        "// Capture the ISR events flags now within a critical section.\n", 1)[1].split(
        "// MRDY event\n", 1)[0]
    beginning = "            // An ASYNC message is ready to send to the Host\n"
    ending = "            // The Transport Layer has received some bytes\n"
    if task.count(beginning) != 1 or task.count(ending) != 1:
        raise RuntimeError("TXQ_HARNESS_ASYNC_SECTION_DRIFT")
    async_body = beginning + task.split(beginning, 1)[1].split(ending, 1)[0]
    msg_begin = "            // Message Event\n"
    if process.count(msg_begin) != 1:
        raise RuntimeError("TXQ_HARNESS_MESSAGE_SECTION_DRIFT")
    message = process.split(msg_begin, 1)[1].split(beginning, 1)[0]
    done = _statement(process,
                      "            if(npiServiceTaskEvents & NPITASK_TRANSPORT_TX_DONE_EVENT)")
    return merge, message, async_body, done


def _counter_defs(*texts):
    names = []
    for text in texts:
        for name in re.findall(r"volatile uint32_t (B4_\w+) = 0u?;", text):
            if name not in names:
                names.append(name)
    return "".join("volatile uint32_t %s = 0;\n" % name for name in names)


def _fixture(sdk, task_text, bodies, progress_override=None):
    client = (sdk / CLIENT).read_text(encoding="utf-8")
    task = task_text
    merge, message, async_body, done = _sections(task)
    hook = ""
    producer = extract(client, "void MT_BuildAndSendZToolResponse(uint8_t cmdType, uint8_t cmdId,\n                                  uint8_t dataLen, uint8_t *pData)")
    tick = extract(client, "static void B4_AfRspTick(volatile uint32_t *p)")
    stack_msg = extract(task, "static void NPITask_processStackMsg(uint8_t *pMsg)")
    process_txq = extract(task, "static void NPITask_ProcessTXQ(void)")
    tx_done_cb = extract(task, "static void NPITask_transportTxDoneCallBack(int size)")
    npi_tick = extract(task, "static void B4_AfNpiTick(volatile uint32_t *p)")
    progress = bodies["progress"] if progress_override is None else progress_override
    ordered = [bodies["latch"], bodies["failed"], bodies["unavailable"],
               progress, tick, producer, npi_tick, stack_msg, process_txq,
               tx_done_cb, bodies["writer"], bodies["abort"],
               bodies["transmission"], bodies["uart_writer"], bodies["callback"]]
    if "B4_TxqSnapshotCheck" not in bodies["progress"]:
        raise RuntimeError("TXQ_HARNESS_SNAPSHOT_CHECK_MISSING")
    counters = _counter_defs(task, client)
    return r"""
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "b1_management.h"
typedef unsigned short uint16;
typedef unsigned char uint8;
typedef void *UART2_Handle;
#define NPI_FLOW_CTRL 0
#define NPI_TL_BUF_SIZE 270
#define UART2_STATUS_SUCCESS 0
#define TRUE true
#define FALSE false
#define MTRPC_FRAME_HDR_SZ 3
#define MTRPC_POS_LEN 0
#define MTRPC_POS_CMD0 1
#define MTRPC_POS_CMD1 2
#define NPITASK_TRANSPORT_TX_DONE_EVENT 0x0004u
#define NPITASK_TX_READY_EVENT 0x0010u
#define NPI_MAX_FRAG_SIZE 270
typedef struct Queue_Elem { struct Queue_Elem *next; } Queue_Elem;
typedef struct { Queue_Elem *head, *tail; } Queue_Obj;
typedef struct { uint8_t *pBuf; uint16_t pBufSize; uint8_t msgType; } NPIMSG_msg_t;
typedef struct NPI_QueueRec { Queue_Elem _elem; NPIMSG_msg_t *npiMsg; } NPI_QueueRec;
enum { NPIMSG_Type_ASYNC = 1, NPIMSG_Type_SYNCRSP = 2 };
static Queue_Obj txq_obj, rxq_obj, syncq_obj;
static void *npiTxQueue = &txq_obj, *npiRxQueue = &rxq_obj, *npiSyncTxQueue = &syncq_obj;
static void Queue_enqueue(void *q, Queue_Elem *e) {
  Queue_Obj *o = q; e->next = NULL;
  if (o->tail) o->tail->next = e; else o->head = e; o->tail = e;
}
static Queue_Elem *Queue_dequeue(void *q) {
  Queue_Obj *o = q; Queue_Elem *e = o->head;
  if (e) { o->head = e->next; if (!o->head) o->tail = NULL; }
  return e;
}
static bool Queue_empty(void *q) { return ((Queue_Obj *)q)->head == NULL; }
static int sem_obj, sem_count, sem_posts;
static void *npiSemHandle = &sem_obj;
static void Semaphore_post(void *h) { (void)h; sem_count++; sem_posts++; }
static uint8_t *osal_fifo[1024];
static int osal_head, osal_tail;
static uint8_t npiServiceTaskId = 7;
static uint8_t npiTaskID = 7;
static uint8_t *OsalPort_msgAllocate(size_t n) { return malloc(n); }
static unsigned OsalPort_msgSend(uint8_t id, void *ptr) {
  if (id != 7) return 1u;
  osal_fifo[osal_tail++ & 1023] = ptr; Semaphore_post(npiSemHandle); return 0u;
}
static uint8_t *OsalPort_msgReceive(uint8_t id) {
  (void)id; if (osal_head == osal_tail) return NULL;
  return osal_fifo[osal_head++ & 1023];
}
static unsigned OsalPort_msgDeallocate(void *p) { free(p); return 0u; }
static void *OsalPort_malloc(size_t n) { return malloc(n); }
static void OsalPort_free(void *p) { free(p); }
static NPIMSG_msg_t *NPIFrame_frameMsg(uint8_t *pMsg) {
  uint8_t len = pMsg[MTRPC_POS_LEN];
  NPIMSG_msg_t *m = malloc(sizeof *m);
  uint8_t *framed = malloc((size_t)len + 4u);
  framed[0] = 0xFE; framed[1] = len; framed[2] = pMsg[1]; framed[3] = pMsg[2];
  if (len > 1) memcpy(framed + 4, pMsg + 3, (size_t)len - 1u);
  m->pBuf = framed; m->pBufSize = (uint16_t)(len + 4u);
  m->msgType = NPIMSG_Type_ASYNC; /* production profile: NPI_SREQRSP off */
  OsalPort_msgDeallocate(pMsg);
  return m;
}
static void (*incomingTXEventAppCBFunc)(uint8_t *) = NULL;
enum { INTERCEPT = 1, ECHO = 2, NONE = 3 };
static int incomingTXReroute = NONE;
static uint32_t npiServiceTaskEvents;
static uint16_t TX_DONE_ISR_EVENT_FLAG, MRDY_ISR_EVENT_FLAG, TRANSPORT_RX_ISR_EVENT_FLAG;
static void b1_evidence_note_npi_wake(void) {}
static volatile bool npiTxActive;
static uint8_t npiTxBuf[NPI_TL_BUF_SIZE];
static uint16 npiTxBufLen, msgFragLen, npiRxBufHead, npiRxBufTail;
static uint8_t *msgFrag;
static unsigned txPktCount;
static uint16 TransportTxLen;
static uint8_t *TransportTxBuf = npiTxBuf;
static UART2_Handle uartHandle;
static int cs_depth, cs_unbalanced, abort_inside_cs;
static int driver_status, startup_completions;
static uint8_t b1_management_flags, b1_management_first_error;
static uint8_t b1_management_current_error, b1_management_stage;
static uint8_t b1_network_ready_attested, b1_boot_startup_state;
static uint8_t b1_startup_first_failure;
static uint32_t OsalPort_enterCS(void) { return (uint32_t)cs_depth++; }
static void OsalPort_leaveCS(uint32_t key) {
 if (cs_depth != (int)key + 1) cs_unbalanced++;
 cs_depth = (int)key;
}
#define B1_CS_ENTER() OsalPort_enterCS()
#define B1_CS_LEAVE(key) OsalPort_leaveCS((uint32_t)(key))
static void NPITask_transportTxDoneCallBack(int size);
static void (*taskTxCB)(int) = NPITask_transportTxDoneCallBack;
static void rx_task_stub(int size) { (void)size; }
static void (*taskRxCB)(int) = rx_task_stub;
static bool NPITL_checkNpiBusy(void) { return npiTxActive; }
uint16 NPITL_writeTL(uint8 *buf, uint16 len);
static void NPITLUART_writeCallBack(UART2_Handle handle, void *ptr, size_t size, void *userArg, int_fast16_t status);
uint16 NPITLUART_writeTransport(uint16 len);
static uint16 (*transportWrite)(uint16) = NPITLUART_writeTransport;
static void NPITL_transmissionCallBack(uint16 rx, uint16 tx);
static void (*npiTransmitCB)(uint16, uint16) = NPITL_transmissionCallBack;
void b1_startup_tx_submit(const uint8_t *p, uint16_t len) { (void)p; (void)len; }
void b1_startup_tx_accepted(uint16_t len, int ok) { (void)len; (void)ok; }
void b1_startup_tx_result(uint16_t len, int ok) {
 (void)len; if (ok) startup_completions++;
}
static unsigned uart_submits;
static uint8_t submitted[512][280];
static uint16_t submitted_len[512];
static int_fast16_t UART2_write(UART2_Handle h, const void *p, size_t len, void *arg) {
 (void)h; (void)arg;
 if (uart_submits < 512) {
   memcpy(submitted[uart_submits], p, len);
   submitted_len[uart_submits] = (uint16_t)len;
 }
 uart_submits++;
 return driver_status;
}
""" + counters + "\n".join(ordered) + r"""
static int cycle(void) {
  uint32_t key;
  uint8_t *pMsg = NULL;
  """ + hook + r"""if (sem_count == 0) return 0;
  sem_count--;
""" + merge + message + async_body + done + r"""
  return 1;
}
static uint32_t snap32(unsigned idx) {
  uint8_t out[80];
  B4_V43_Snapshot(out);
  return (uint32_t)out[idx * 4] | ((uint32_t)out[idx * 4 + 1] << 8) |
         ((uint32_t)out[idx * 4 + 2] << 16) | ((uint32_t)out[idx * 4 + 3] << 24);
}
static void produce(int n, int base) {
  int i;
  for (i = 0; i < n; i++) {
    uint8_t v = (uint8_t)(base + i);
    MT_BuildAndSendZToolResponse(0x64u, 0x01u, 1u, &v);
  }
}
static void complete_ok(void) {
  NPITLUART_writeCallBack(NULL, NULL, TransportTxLen, NULL, UART2_STATUS_SUCCESS);
}
static int drive(int target, int max_cycles) {
  int i;
  for (i = 0; i < max_cycles; i++) {
    cycle();
    if (npiTxActive) complete_ok();
    if ((int)uart_submits >= target && !npiTxActive &&
        Queue_empty(npiTxQueue) && osal_head == osal_tail) return 0;
  }
  return 1;
}
int main(int argc, char **argv) {
  if (argc != 2) return 2;
  if (!strcmp(argv[1], "burst")) {
    int i;
    produce(128, 0);
    if (drive(128, 20000)) return 10;
    for (i = 0; i < 128; i++)
      if (submitted[i][2] != 0x64 || submitted[i][3] != 0x01 ||
          submitted[i][4] != (uint8_t)i) return 11;
    if (snap32(3) != 128 || snap32(5) != 128 || snap32(10) != 0) return 12;
    if (startup_completions != 128) return 13;
  } else if (!strcmp(argv[1], "stranded_snapshot")) {
    int guard = 0;
    produce(3, 0);
    while (!npiTxActive && guard++ < 100) cycle();
    if (!npiTxActive || uart_submits != 1) return 20;
    complete_ok();
    /* Lose the completion wake, then enqueue the remaining producer
     * frames while the TL is marked busy so none is submitted. */
    TX_DONE_ISR_EVENT_FLAG = 0; sem_count = 0;
    npiTxActive = true;
    Semaphore_post(npiSemHandle); Semaphore_post(npiSemHandle);
    while (osal_head != osal_tail) { if (!cycle()) return 21; }
    if (B4_NpiAsyncDepth != 2 || Queue_empty(npiTxQueue)) return 22;
    npiTxActive = false;
    if (snap32(10) != 0 && snap32(10) != 6) return 27;
    if (snap32(10) != 6 || snap32(12) != 2) return 23;
    if (uart_submits != 1 || B4_NpiAsyncDepth != 2) return 24;
    Semaphore_post(npiSemHandle);
    produce(1, 3);
    if (drive(4, 20000)) return 25;
    if (submitted[3][4] != 3 || snap32(10) != 6) return 26;
  } else if (!strcmp(argv[1], "blocked")) {
    int i, posts_before;
    produce(2, 0);
    for (i = 0; i < 20 && !npiTxActive; i++) cycle();
    if (!npiTxActive || uart_submits != 1) return 30;
    posts_before = sem_posts;
    for (i = 0; i < 50; i++) cycle();
    if (snap32(10) != 0 || uart_submits != 1 || B4_NpiAsyncDepth != 1) return 31;
    if (sem_posts - posts_before > 8) return 32;
  } else if (!strcmp(argv[1], "failed")) {
    int i;
    produce(2, 0);
    for (i = 0; i < 20 && !npiTxActive; i++) cycle();
    if (!npiTxActive) return 40;
    NPITLUART_writeCallBack(NULL, NULL, TransportTxLen, NULL, 4);
    if (npiTxActive || !b1_management_transport_unavailable()) return 41;
    for (i = 0; i < 5; i++) cycle();
    if (snap32(10) != 2 || snap32(5) != 0 || snap32(6) != 1) return 42;
    if (uart_submits != 1 || B4_NpiAsyncDepth != 1) return 43;
  } else return 3;
  if (cs_depth || cs_unbalanced || abort_inside_cs) return 44;
  printf("TXQ_CHAIN_PASS %s\n", argv[1]);
  return 0;
}
"""


def exercise(sdk):
    sdk = Path(sdk)
    bodies, management_path = actual_functions(sdk)
    task = (sdk / TASK).read_text(encoding="utf-8")
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if cc is None:
        raise RuntimeError("TXQ_CHAIN_C_COMPILER_REQUIRED")

    def run(label, source, cases, expected_rc=0):
        with tempfile.TemporaryDirectory(prefix="p7u-txq-") as tmp:
            path = Path(tmp)
            inp, exe = path / "actual.c", path / "actual"
            inp.write_text(source)
            compiled = subprocess.run(
                [cc, "-std=c11", "-Wall", "-Wextra", "-Wno-unused-variable",
                 "-Wno-unused-function", "-Wno-unused-parameter",
                 "-I", str(management_path.parent), str(inp), "-o", str(exe)],
                text=True, capture_output=True, timeout=30)
            if compiled.returncode:
                raise RuntimeError("TXQ_CHAIN_COMPILE_" + label + ": " +
                                   compiled.stderr[-1600:])
            passed = []
            for case in cases:
                done = subprocess.run([str(exe), case], text=True,
                                      capture_output=True, timeout=10)
                if done.returncode != expected_rc or (expected_rc == 0 and
                        "TXQ_CHAIN_PASS " + case not in done.stdout):
                    raise RuntimeError(
                        "TXQ_CHAIN_CASE_%s_%s: %s expected %s" %
                        (label, case, done.returncode, expected_rc))
                passed.append(case)
            return passed

    source = _fixture(sdk, task, bodies)
    cases = run("PRODUCTION_CHAIN", source, CASES)
    progress = bodies["progress"]
    call = "    B4_TxqSnapshotCheck(); /* B4_TXQ_STRAND_WITNESS */"
    if progress.count(call) != 1:
        raise RuntimeError("TXQ_CHAIN_SNAPSHOT_CALL_ANCHOR")
    mutants = []
    run("missing_snapshot_check",
        _fixture(sdk, task, bodies, progress.replace(call, "", 1)),
        ["stranded_snapshot"], expected_rc=23)
    mutants.append("missing_snapshot_check")
    anchor = "B4_V43_FirstFault(6u, 0, B4_NpiAsyncDepth, 0u);"
    if progress.count(anchor) != 1:
        raise RuntimeError("TXQ_CHAIN_STRAND_LATCH_ANCHOR")
    run("missing_strand_latch",
        _fixture(sdk, task, bodies, progress.replace(anchor, "(void)0;", 1)),
        ["stranded_snapshot"], expected_rc=23)
    mutants.append("missing_strand_latch")
    _, _, async_body, _ = _sections(task)
    busy_anchor = "else if (!NPITL_checkNpiBusy()"
    if async_body.count(busy_anchor) != 1:
        raise RuntimeError("TXQ_CHAIN_BUSY_GUARD_ANCHOR")
    mutant_task = task.replace(
        busy_anchor, "else if (1 || !NPITL_checkNpiBusy()", 1)
    run("busy_repost_spin", _fixture(sdk, mutant_task, bodies),
        ["blocked"], expected_rc=32)
    mutants.append("busy_repost_spin")
    callback = bodies["callback"]
    abort_anchor = "NPITL_abortFailedTx(); /* preserve B1 HOLD; no false TX completion */"
    if callback.count(abort_anchor) != 1:
        raise RuntimeError("TXQ_CHAIN_ABORT_ANCHOR")
    mutant_bodies = dict(bodies)
    mutant_bodies["callback"] = callback.replace(abort_anchor, "", 1)
    run("missing_abort_notify", _fixture(sdk, task, mutant_bodies),
        ["failed"], expected_rc=41)
    mutants.append("missing_abort_notify")
    return {"status": STATUS, "cases": cases, "negative_mutants": mutants,
            "producer": "REAL_MT_BUILDANDSEND_TO_OSAL_TO_PROCESSSTACKMSG",
            "consumer": "REAL_PROCESSTXQ_TO_TL_TO_UART_CALLBACK",
            "burst_frames": 128, "ordering_preserved": True,
            "hardware_access": False}
