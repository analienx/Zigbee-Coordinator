#!/usr/bin/env python3
"""Compile actual patched TI NPI RX callback, ring discard, and frame reset.

Uses source extracted from pinned TI C composed by the B1 qualification job.
This is an offline proof of conditional liveness, not a reproduction of the
production hang or verification of the real UART/ESP/USB boundary.
"""
import argparse
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from r4_npi_rx_overflow_liveness import PATHS, TASK, FRAME, RX, patch_sources
from r4_uart_tx_liveness import extract


def make_harness(source):
    task, frame, ring = source[TASK], source[FRAME], source[RX]
    rx_callback = extract(task, "static void NPITask_transportRXCallBack(int size)")
    reset_frame = extract(frame, "void NPIFrame_resetAfterRxOverflow(void)")
    drop_ring = extract(ring, "void NPIRxBuf_DiscardAll(void)")
    marker = "                if (B4_R4_RxOverflowPending != 0u)"
    end = "                NPIFrame_collectFrameData();"
    assert task.count(marker) == 1 and task.count(end) == 1
    task_case = marker + task.split(marker, 1)[1].split(end, 1)[0] + end
    assert "NPIRxBuf_DiscardAll();" in task_case
    assert "NPIFrame_resetAfterRxOverflow();" in task_case
    assert "for(;;);" not in rx_callback
    return r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
typedef uint8_t uint8;
typedef uint16_t uint16;
#define NPI_TL_BUF_SIZE 270
#define NPIFRAMEMT_SOP_STATE 0u
#define NPITASK_TRANSPORT_RX_EVENT 0x0040
static uint16_t RxBufHead = 0, RxBufTail = 0;
static uint8_t state = 0, LEN_Token = 0, tempDataLen = 0;
static uint8_t *pMsg = NULL;
static volatile uint8_t B4_R4_RxOverflowPending = 0;
static uint16_t TRANSPORT_RX_ISR_EVENT_FLAG = 0;
static unsigned posts = 0, collect_calls = 0, dropped = 0;
static unsigned critical = 0;
static int semaphore_object = 0;
#define npiSemHandle (&semaphore_object)
uint32_t OsalPort_enterCS(void) { critical++; return 0; }
void OsalPort_leaveCS(uint32_t k) { (void)k; assert(critical>0); critical--; }
void Semaphore_post(void *h) { assert(h == npiSemHandle); posts++; }
void OsalPort_msgDeallocate(uint8_t *p) { free(p); dropped++; }
uint16_t NPIRxBuf_GetRxBufCount(void) {
  return (RxBufTail + 270u - RxBufHead) % 270u;
}
uint16_t NPIRxBuf_GetRxBufAvail(void) {
  return 270u - NPIRxBuf_GetRxBufCount();
}
uint16_t NPIRxBuf_Read(uint16_t n) {
  assert(n < NPIRxBuf_GetRxBufAvail());
  RxBufTail = (RxBufTail + n) % 270u;
  return n;
}
void NPIFrame_collectFrameData(void) { collect_calls++; }
''' + '\n' + rx_callback + '\n' + drop_ring + '\n' + reset_frame + r'''
static void drain_npi_task(void) {
''' + task_case + r'''
}
int main(void) {
  // Filled ring + partial parser: equivalent to the source's overflow path.
  RxBufHead = 0; RxBufTail = 268;
  state = 3; LEN_Token = 8; tempDataLen = 3;
  pMsg = malloc(12); assert(pMsg);
  NPITask_transportRXCallBack(4);
  assert(B4_R4_RxOverflowPending && posts == 1);
  assert(TRANSPORT_RX_ISR_EVENT_FLAG == NPITASK_TRANSPORT_RX_EVENT);
  assert(RxBufTail == 268 && RxBufHead == 0); // no ISR data mutation
  assert(dropped == 0); // ISR did not free parser memory
  drain_npi_task();
  assert(!B4_R4_RxOverflowPending);
  assert(NPIRxBuf_GetRxBufCount() == 0);
  assert(state == 0 && pMsg == NULL && LEN_Token == 0 && tempDataLen == 0);
  assert(dropped == 1 && collect_calls == 1 && critical == 0);
  // Verify the next fresh UART fragment still enters receive ring normally.
  TRANSPORT_RX_ISR_EVENT_FLAG=0;
  NPITask_transportRXCallBack(5);
  assert(!B4_R4_RxOverflowPending && NPIRxBuf_GetRxBufCount() == 5);
  assert(posts == 2 && TRANSPORT_RX_ISR_EVENT_FLAG == NPITASK_TRANSPORT_RX_EVENT);
  drain_npi_task();
  assert(dropped == 1 && collect_calls == 2 && critical == 0);
  // No double-free of an already completed parser frame.
  state = NPIFRAMEMT_SOP_STATE;
  NPIFrame_resetAfterRxOverflow();
  assert(dropped == 1);
  puts("NPI_RX_OVERFLOW_REPAIRED_CALLBACK_AND_NEXT_FRAME_PASS");
  return 0;
}
'''


def main():
    arg = argparse.ArgumentParser(description=__doc__)
    arg.add_argument("--sdk", type=pathlib.Path, required=True)
    opts = arg.parse_args()
    src = {p: (opts.sdk / p).read_text(encoding="utf-8") for p in PATHS}
    assert "for(;;);" in extract(src[TASK], "static void NPITask_transportRXCallBack(int size)")
    changed = patch_sources(src)
    assert "for(;;);" not in extract(changed[TASK], "static void NPITask_transportRXCallBack(int size)")
    assert "B4_R4_RX_OVERFLOW_DROP_V1" in changed[FRAME]
    assert "B4_R4_RX_OVERFLOW_DROP_V1" in changed[RX]
    assert not any("NVOCMP" in changed[p] for p in (FRAME,RX))
    try:
        patch_sources(changed)
    except ValueError as e:
        assert str(e) == "NPI_RX_ALREADY_PATCHED"
    else:
        raise AssertionError("Double application must be rejected")
    with tempfile.TemporaryDirectory(prefix="p7u-npi-rx-") as d:
        c = pathlib.Path(d) / "rx.c"
        exe = pathlib.Path(d) / "rx"
        c.write_text(make_harness(changed), encoding="utf-8")
        subprocess.run(["gcc", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                        "-no-pie", str(c), "-o", str(exe)], check=True)
        subprocess.run([str(exe)], check=True)
    print("PINNED_TI_NPI_RX_OVERFLOW_SOURCE_ORACLE_PASS")


if __name__ == "__main__":
    main()
