#!/usr/bin/env python3
"""Compile the EMITTED V57 npi_frame_mt.c and reject behavior mutants.

The whole composed TI file is compiled with OSAL, RX-buffer and Clock stubs
(ASan/UBSan). The scenarios replay the field symptom (a stray SOF and length
byte long before the host's first ping), prove that a frame without an idle
gap is never dropped however late the NPI task runs, cover the resync in
every parser state with exact allocation accounting, the length bound, the
reported-gap race inside TI's bulk data read, and the B1E8 layout. Hosted
model only: no claim about what is on the radio's RX line at power-on.
"""
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile

from r4_v57_npi_rx_resync import FRAME, MARKER

STUB = r"""
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define MTRPC_FRAME_HDR_SZ 3
#define MTRPC_POS_LEN 0
#define MTRPC_POS_CMD0 1
#define MTRPC_POS_CMD1 2
#define MTRPC_CMD_TYPE_MASK 0xE0
#define MTRPC_CMD_SREQ 0x20
#define MTRPC_CMD_SRSP 0x60
#define MT_RPC_DATA_MAX 250
typedef enum { NPIMSG_Type_ASYNC = 0, NPIMSG_Type_SYNCREQ, NPIMSG_Type_SYNCRSP } NPIMSG_Type;
typedef struct { uint16_t pBufSize; NPIMSG_Type msgType; uint8_t *pBuf; } NPIMSG_msg_t;
typedef void (*npiIncomingFrameCBack_t)(uint16_t, uint8_t *, NPIMSG_Type);
#define RING 270u
#define Clock_tickPeriod 10u
static uint32_t now_ticks;
static uint32_t Clock_getTicks(void) { return now_ticks; }
static void *live[32];
static unsigned live_n, allocs, frees, fail_alloc;
static uint8_t *OsalPort_msgAllocate(uint16_t n)
{
    uint8_t *p;
    if (fail_alloc) { --fail_alloc; return NULL; }
    assert(live_n < 32u);
    p = malloc(n ? n : 1u); assert(p != NULL);
    live[live_n++] = p; ++allocs; return p;
}
static uint8_t OsalPort_msgDeallocate(uint8_t *p)
{
    unsigned i;
    for (i = 0u; i < live_n && live[i] != p; ++i) {}
    assert(i < live_n); /* never NULL, stale or freed twice */
    live[i] = live[--live_n]; free(p); ++frees; return 0u;
}
static void *OsalPort_malloc(uint32_t n) { return malloc(n); }
static void OsalPort_free(void *p) { free(p); }
static uint8_t ring[RING];
static uint16_t ring_head, ring_tail;
static void (*after_last_single_read)(void);
static uint16_t NPIRxBuf_GetRxBufCount(void)
{
    return (uint16_t)((ring_tail + RING - ring_head) % RING);
}
static uint16_t NPIRxBuf_ReadFromRxBuf(uint8_t *buf, uint16_t len)
{
    uint16_t i;
    for (i = 0u; i < len; ++i)
    {
        assert(NPIRxBuf_GetRxBufCount() != 0u);
        buf[i] = ring[ring_head]; ring_head = (uint16_t)((ring_head + 1u) % RING);
    }
    if (len == 1u && after_last_single_read != NULL && NPIRxBuf_GetRxBufCount() == 0u)
    {
        void (*hook)(void) = after_last_single_read;
        after_last_single_read = NULL; hook();
    }
    return len;
}
"""

MAIN = r"""
static const uint8_t PING[7] = { 0xFE, 0x02, 0x21, 0x01, 0x01, 0x00, 0x23 };
static unsigned delivered;
static uint8_t last[260];
static uint16_t last_n;
static void deliver(uint16_t n, uint8_t *p, NPIMSG_Type type)
{
    assert(type == NPIMSG_Type_ASYNC && n <= sizeof(last));
    memcpy(last, p, n); last_n = n; ++delivered;
    (void)OsalPort_msgDeallocate(p); /* the NPI task owns a delivered frame */
}
static void advance_ms(uint32_t ms) { now_ticks += ms * 100u; }
/* The transport RX callback: V57 hook first, then TI's copy. */
static void feed(const uint8_t *bytes, unsigned n)
{
    unsigned i;
    B4_V57_RxArrived(NPIRxBuf_GetRxBufCount());
    for (i = 0u; i < n; ++i)
    {
        ring[ring_tail] = bytes[i]; ring_tail = (uint16_t)((ring_tail + 1u) % RING);
        assert(ring_tail != ring_head);
    }
}
static void run(void) { NPIFrame_collectFrameData(); assert(NPIRxBuf_GetRxBufCount() == 0u || fail_alloc); }
static void fresh(uint32_t start_tick)
{
    assert(live_n == 0u);
    memset(&B4_V57_Rx, 0, sizeof(B4_V57_Rx));
    B4_V57_GapSeq = 0u; B4_V57_GapSeen = 0u; B4_V57_LastArrival = 0u; B4_V57_Arrived = 0u;
    state = NPIFRAMEMT_SOP_STATE; pMsg = NULL; LEN_Token = 0u; tempDataLen = 0u;
    ring_head = ring_tail = 0u; delivered = 0u; last_n = 0u; allocs = frees = 0u; fail_alloc = 0u;
    after_last_single_read = NULL; now_ticks = start_tick;
    NPIFrame_initialize(deliver);
}
static void expect_ping(unsigned count)
{
    assert(delivered == count && last_n == 5u && !memcmp(last, PING + 1, 5u));
}
static void late_ping(void) { advance_ms(2000u); feed(PING, sizeof(PING)); }
static uint32_t get32(const uint8_t *p) { return p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24); }

int main(void)
{
    static const uint8_t stray[2] = { 0xFE, 0x7C };
    static const uint8_t prefix[6] = { 0xFE, 0x05, 0x21, 0x01, 0xAA, 0xBB };
    uint8_t big[255], out[248 + 8];
    unsigned i, n;

    /* 1. A correctly framed stream is TI's: one frame, one delivery. */
    fresh(1000u);
    feed(PING, sizeof(PING)); run();
    expect_ping(1u);
    assert(B4_V57_Rx.framesOk == 1u && B4_V57_Rx.seenOk && B4_V57_Rx.firstOkTick == 1000u);
    assert(B4_V57_Rx.resyncs == 0u && B4_V57_Rx.junk == 0u && allocs == 1u && frees == 1u);

    /* 2. The field symptom: a stray SOF and length byte at power-on, the
     *    host's first ping minutes later. TI swallows the ping (and the
     *    next 120 bytes); V57 answers the first one. */
    fresh(0u);
    advance_ms(900u); feed(stray, sizeof(stray)); run();
    assert(state == NPIFRAMEMT_CMD_STATE1 && live_n == 1u && delivered == 0u);
    advance_ms(250000u); feed(PING, sizeof(PING)); run();
    expect_ping(1u);
    assert(B4_V57_Rx.resyncs == 1u && B4_V57_Rx.firstState == NPIFRAMEMT_CMD_STATE1);
    assert(B4_V57_Rx.firstLen == 0x7Cu && B4_V57_Rx.firstResyncTick == now_ticks && live_n == 0u);
    assert(B4_V57_Rx.firstOkTick == now_ticks && B4_V57_Rx.framesOk == 1u && B4_V57_Rx.fcsFail == 0u);
    /* Later quiet periods between whole frames change nothing. */
    for (i = 0u; i < 5u; ++i) { advance_ms(700u); feed(PING, sizeof(PING)); run(); }
    expect_ping(6u);
    assert(B4_V57_Rx.resyncs == 1u && B4_V57_GapSeq == 7u && live_n == 0u);
    /* A second stale frame is dropped too; the first record is kept. */
    advance_ms(700u); feed(prefix, 5u); run(); late_ping(); run();
    expect_ping(7u);
    assert(B4_V57_Rx.resyncs == 2u && B4_V57_Rx.firstState == NPIFRAMEMT_CMD_STATE1);
    assert(B4_V57_Rx.firstLen == 0x7Cu && B4_V57_Rx.firstCmd0 == 0u && B4_V57_Rx.firstCollected == 0u);
    assert(B4_V57_Rx.lastResyncTick == now_ticks && B4_V57_Rx.firstResyncTick != now_ticks && live_n == 0u);

    /* 3. One frame in two chunks without an idle gap: never dropped,
     *    whether the NPI task runs between the chunks or seconds later. */
    fresh(500u);
    feed(PING, 3u); run(); advance_ms(499u); feed(PING + 3, 4u); run();
    expect_ping(1u); assert(B4_V57_Rx.resyncs == 0u);
    fresh(500u);
    feed(PING, 3u); run(); advance_ms(1u); feed(PING + 3, 4u); advance_ms(5000u); run();
    expect_ping(1u); assert(B4_V57_Rx.resyncs == 0u);
    /* Across the 32-bit tick wrap. */
    fresh(0xFFFFFF00u);
    feed(PING, 3u); run(); advance_ms(10u); feed(PING + 3, 4u); run();
    expect_ping(1u); assert(B4_V57_Rx.resyncs == 0u && now_ticks < 0x1000u);

    /* 4. A gap that finds unparsed bytes marks no boundary (TI behaviour):
     *    the parser is mid-frame, the middle chunk is still unread. */
    fresh(500u);
    feed(PING, 2u); run(); advance_ms(1u); feed(PING + 2, 2u);
    advance_ms(2000u); feed(PING + 4, 3u); run();
    expect_ping(1u); assert(B4_V57_Rx.resyncs == 0u && B4_V57_GapSeq == 1u);

    /* 5. The resync in every parser state frees exactly what it owns. */
    for (n = 1u; n <= 6u; ++n)
    {
        static const uint8_t want[7] = { 0u, NPIFRAMEMT_LEN_STATE, NPIFRAMEMT_CMD_STATE1,
            NPIFRAMEMT_CMD_STATE2, NPIFRAMEMT_DATA_STATE, NPIFRAMEMT_DATA_STATE, NPIFRAMEMT_DATA_STATE };
        fresh(700u);
        feed(prefix, n); run();
        assert(state == want[n] && live_n == (n >= 2u ? 1u : 0u));
        late_ping(); run();
        expect_ping(1u);
        assert(B4_V57_Rx.resyncs == 1u && B4_V57_Rx.firstState == want[n] && live_n == 0u);
        assert(B4_V57_Rx.firstLen == (n >= 2u ? 0x05u : 0u));
        assert(B4_V57_Rx.firstCmd0 == (n >= 3u ? 0x21u : 0u));
        assert(B4_V57_Rx.firstCmd1 == (n >= 4u ? 0x01u : 0u));
        assert(B4_V57_Rx.firstCollected == (n >= 5u ? n - 4u : 0u));
        assert(allocs == (n >= 2u ? 2u : 1u) && frees == allocs);
    }
    /* ... including the FCS state (all data collected, FCS never came). */
    {
        static const uint8_t nofcs[5] = { 0xFE, 0x01, 0x21, 0x01, 0x55 };
        fresh(700u);
        feed(nofcs, sizeof(nofcs)); run();
        assert(state == NPIFRAMEMT_FCS_STATE && live_n == 1u);
        late_ping(); run();
        expect_ping(1u);
        assert(B4_V57_Rx.firstState == NPIFRAMEMT_FCS_STATE && B4_V57_Rx.firstCollected == 1u && live_n == 0u);
    }

    /* 6. A gap reported while TI's bulk data read is about to count the
     *    buffer: the bytes behind the gap are not appended to stale data. */
    fresh(700u);
    after_last_single_read = late_ping;
    feed(prefix, 5u); run();
    expect_ping(1u);
    assert(B4_V57_Rx.resyncs == 1u && B4_V57_Rx.firstState == NPIFRAMEMT_DATA_STATE);
    assert(B4_V57_Rx.firstCollected == 1u && live_n == 0u);

    /* 7. Length bound: 251..255 are not lengths; a repeated SOF restarts. */
    fresh(700u);
    {
        static const uint8_t ff[2] = { 0xFE, 0xFF };
        static const uint8_t fb[2] = { 0xFE, 0xFB };
        static const uint8_t twice[6] = { 0xFE, 0xFE, 0x00, 0x21, 0x02, 0x23 };
        feed(ff, 2u); feed(PING, sizeof(PING)); run();
        expect_ping(1u); assert(B4_V57_Rx.oversize == 1u && allocs == 1u);
        feed(fb, 2u); feed(PING, sizeof(PING)); run();
        expect_ping(2u); assert(B4_V57_Rx.oversize == 2u && allocs == 2u);
        feed(twice, sizeof(twice)); run();
        assert(delivered == 3u && last_n == 3u && last[0] == 0u && last[1] == 0x21u && last[2] == 0x02u);
        assert(B4_V57_Rx.oversize == 3u && B4_V57_Rx.resyncs == 0u && B4_V57_Rx.junk == 0u);
    }
    /* The longest real frame (250 data bytes) still passes. */
    fresh(700u);
    big[0] = 0xFE; big[1] = 250u; big[2] = 0x21u; big[3] = 0x09u;
    for (i = 0u; i < 250u; ++i) big[4u + i] = (uint8_t)(i * 7u);
    big[254] = npiframe_calcMTFCS(big + 1, 253u);
    feed(big, 100u); run(); feed(big + 100, 155u); run();
    assert(delivered == 1u && last_n == 253u && !memcmp(last, big + 1, 253u) && B4_V57_Rx.oversize == 0u);

    /* 8. TI's FCS rejection is unchanged and counted; no leak. */
    fresh(700u);
    {
        uint8_t bad[7]; memcpy(bad, PING, 7u); bad[6] ^= 0x01u;
        feed(bad, 7u); feed(PING, 7u); run();
        expect_ping(1u);
        assert(B4_V57_Rx.fcsFail == 1u && B4_V57_Rx.lastFcsTick == now_ticks && live_n == 0u);
        assert(allocs == 2u && frees == 2u && B4_V57_Rx.framesOk == 1u);
    }

    /* 9. Discarded bytes: all counted, the first eight kept only until
     *    this boot's first valid frame. */
    fresh(700u);
    {
        static const uint8_t text[12] = "ESP-ROM:esp3";
        static const uint8_t more[3] = { 0x11, 0x22, 0x33 };
        feed(text, 12u); run();
        assert(B4_V57_Rx.junk == 12u && B4_V57_Rx.bootJunkCount == 8u && !memcmp(B4_V57_Rx.bootJunk, text, 8u));
        fresh(700u);
        feed(text, 3u); feed(PING, 7u); feed(more, 3u); run();
        expect_ping(1u);
        assert(B4_V57_Rx.junk == 6u && B4_V57_Rx.bootJunkCount == 3u && !memcmp(B4_V57_Rx.bootJunk, text, 3u));
    }

    /* 10. Allocation failure keeps TI's early return and is counted. */
    fresh(700u);
    fail_alloc = 1u; feed(PING, 7u); NPIFrame_collectFrameData();
    assert(state == NPIFRAMEMT_SOP_STATE && B4_V57_Rx.allocFail == 1u && delivered == 0u && live_n == 0u);
    NPIFrame_collectFrameData();
    assert(NPIRxBuf_GetRxBufCount() == 0u && delivered == 0u);
    feed(PING, 7u); run(); expect_ping(1u);

    /* 11. B1E8 layout (the NPI owner adds the digest at 8..11). */
    fresh(0u);
    advance_ms(900u); feed(stray, 2u); run();
    advance_ms(60000u);
    {
        static const uint8_t junk[2] = { 0x41, 0x42 };
        uint8_t bad[7]; memcpy(bad, PING, 7u); bad[6] ^= 0x80u;
        feed(junk, 2u); run();          /* resync (first), then two discarded bytes */
        advance_ms(100u); feed(bad, 7u); run();
        advance_ms(100u); feed(PING, 7u); run();
        advance_ms(100u); feed(PING, 3u); run(); /* mid-frame when the page is read */
    }
    memset(out, 0xEE, sizeof(out));
    B4_V57_RxFrameSnapshot(out);
    assert(!memcmp(out, "B1E8", 4) && out[4] == 1u && out[5] == 248u && out[6] == 7u && out[7] == 0u);
    assert(get32(out + 8) == 0u && get32(out + 12) == now_ticks);
    assert(get32(out + 16) == 1u && get32(out + 20) == 1u && get32(out + 24) == 1u && get32(out + 28) == 0u);
    assert(get32(out + 32) == 2u && get32(out + 36) == 0u && get32(out + 40) == B4_V57_GapSeq);
    assert(get32(out + 44) == now_ticks - 10000u && get32(out + 48) == 90000u + 6000000u);
    assert(get32(out + 52) == get32(out + 48) && get32(out + 56) == now_ticks - 20000u);
    assert(out[60] == NPIFRAMEMT_CMD_STATE1 && out[61] == 0x7Cu && out[62] == 0u && out[63] == 0u && out[64] == 0u);
    assert(out[65] == NPIFRAMEMT_CMD_STATE2 && out[66] == 2u && out[67] == 250u);
    assert(out[68] == 0x41u && out[69] == 0x42u && out[70] == 0u && out[76] == 0xF4u && out[77] == 0x01u);
    for (i = 78u; i < 248u; ++i) assert(out[i] == 0u);
    for (i = 248u; i < sizeof(out); ++i) assert(out[i] == 0xEEu);
    late_ping(); run(); expect_ping(2u); assert(live_n == 0u);

    printf("V57_NPI_RX_FRAME_RESYNC_REAL_C_PASS\n");
    return 0;
}
"""

MUTANTS = {
    "resync_removed": (
        "        if (B4_V57_GapPending()) B4_V57_ResyncAfterGap();\n", ""),
    "every_chunk_is_a_gap": (
        "         (uint32_t)(now - B4_V57_LastArrival) >= (B4_V57_IDLE_MS * 1000u) / Clock_tickPeriod))",
        "         (uint32_t)(now - B4_V57_LastArrival) >= 1u))"),
    "gap_ignores_unparsed_bytes": ("    if (pending == 0u &&\n", "    if (\n"),
    "tick_wrap_not_modular": (
        "         (uint32_t)(now - B4_V57_LastArrival) >= (B4_V57_IDLE_MS * 1000u) / Clock_tickPeriod))",
        "         now < B4_V57_LastArrival || "
        "now - B4_V57_LastArrival >= (B4_V57_IDLE_MS * 1000u) / Clock_tickPeriod))"),
    "idle_limit_shortened": ("#define B4_V57_IDLE_MS 500u\n", "#define B4_V57_IDLE_MS 400u\n"),
    "partial_frame_leaked": (
        "    if (state != NPIFRAMEMT_LEN_STATE) OsalPort_msgDeallocate(pMsg);\n", ""),
    "len_state_frees_unowned": (
        "    if (state != NPIFRAMEMT_LEN_STATE) OsalPort_msgDeallocate(pMsg);\n",
        "    OsalPort_msgDeallocate(pMsg);\n"),
    "resync_keeps_state": ("    pMsg = NULL;\n    state = NPIFRAMEMT_SOP_STATE;\n", "    pMsg = NULL;\n"),
    "bulk_read_crosses_gap": (
        "                if (B4_V57_GapPending()) uint8_tsInRxBuffer = 0u;\n", ""),
    "length_bound_removed": ("                if (ch > B4_V57_LEN_MAX)\n", "                if (0)\n"),
    "length_bound_too_low": ("#define B4_V57_LEN_MAX 250u", "#define B4_V57_LEN_MAX 249u"),
    "repeated_sof_dropped": (
        "                    state = (ch == MT_SOF) ? NPIFRAMEMT_LEN_STATE : NPIFRAMEMT_SOP_STATE;\n",
        "                    state = NPIFRAMEMT_SOP_STATE;\n"),
    "boot_junk_after_first_frame": (
        "                    if (!B4_V57_Rx.seenOk && B4_V57_Rx.bootJunkCount < B4_V57_BOOT_JUNK)\n",
        "                    if (B4_V57_Rx.bootJunkCount < B4_V57_BOOT_JUNK)\n"),
    "first_resync_overwritten": ("    if (B4_V57_Rx.resyncs == 0u)\n    {\n", "    {\n"),
    "fcs_failure_not_counted": ("                    B4_V57_Inc(&B4_V57_Rx.fcsFail);\n", ""),
    "alloc_failure_not_counted": ("                    B4_V57_Inc(&B4_V57_Rx.allocFail);\n", ""),
    "snapshot_offset_shifted": (
        "    B4_V57_Put32(out + 24u, B4_V57_Rx.resyncs);", "    B4_V57_Put32(out + 28u, B4_V57_Rx.resyncs);"),
    "snapshot_state_flag_dropped": (
        "                       (state != NPIFRAMEMT_SOP_STATE ? 4u : 0u));", "                       0u);"),
}


def compose(sdk):
    text = (Path(sdk) / FRAME).read_text()
    if text.count(MARKER) != 1:
        raise ValueError("V57_NPI_FRAME_HARNESS_MARKER")
    body = "\n".join(line for line in text.splitlines() if not line.startswith("#include"))
    return STUB + body + "\n" + MAIN


def exercise(sdk):
    code = compose(sdk)
    cc = shutil.which("cc") or shutil.which("gcc")
    if cc is None:
        raise RuntimeError("V57_NATIVE_C_COMPILER_REQUIRED")

    def build(name, source, should_pass):
        with tempfile.TemporaryDirectory(prefix="p7u-v57-npi-rx-") as td:
            unit, exe = Path(td) / "t.c", Path(td) / "t"
            unit.write_text(source, encoding="utf-8")
            built = subprocess.run(
                [cc, "-std=c11", "-O0", "-g", "-Wall", "-Wextra", "-Werror",
                 "-Wno-unused-function", "-Wno-unused-parameter",
                 "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                 str(unit), "-o", str(exe)], capture_output=True, text=True, timeout=60)
            if built.returncode:
                raise RuntimeError("V57_NPI_FRAME_C_COMPILE_" + name + ": " + built.stderr[-3000:])
            run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=30)
            if (run.returncode == 0) != should_pass:
                raise RuntimeError("V57_NPI_FRAME_MUTANT_NOT_REJECTED_" + name + ": " +
                                   run.stdout[-400:] + run.stderr[-800:])
            return run.stdout.strip()

    output = build("actual", code, True)
    rejected = []
    for label, (old, new) in MUTANTS.items():
        if code.count(old) != 1:
            raise ValueError("V57_NPI_FRAME_MUTANT_PREIMAGE_" + label + " occurrences=" + str(code.count(old)))
        build(label, code.replace(old, new, 1), False)
        rejected.append("npi_rx:" + label)
    return {"schema": "p7u-v57-emitted-npi-frame-actual-c-v1", "status": "PASS",
            "frame_sha256": hashlib.sha256((Path(sdk) / FRAME).read_bytes()).hexdigest(),
            "compiled_actual_npi_frame_mt": True, "negative_mutants_rejected": rejected,
            "hosted_model_only": True, "rx_line_garbage_source_proven": False, "output": output}
