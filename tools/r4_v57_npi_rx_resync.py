#!/usr/bin/env python3
"""V57: the MT frame parser drops a stale partial frame after an idle RX gap.

Source facts at the pinned TI SDK 3615ad5d (source/ti/zstack/npi/npi_frame_mt.c,
NPIFrame_collectFrameData, linked by the ZNP projectspec):
  * the UART frame parser has no inter-byte timeout. After a start-of-frame
    byte (0xFE) it takes the next byte as the length and then waits, for any
    amount of time, for length + 3 more bytes before it looks at the FCS;
  * the length byte is not bounded: 251..255 are accepted although no MT
    frame carries more than MT_RPC_DATA_MAX (250) data bytes.
One stray 0xFE followed by one more byte on the radio's RX line (power-on
glitch, bridge start-up, a truncated host write) therefore makes the radio
swallow the next up-to-258 valid host bytes as "data" of a frame that never
existed. Nothing is answered until that many bytes have been sent.

Field evidence (10 and 11 Nov 2026, V56; 1 and 2 Nov, V53/V54): after a
simultaneous host and SLZB power-on the radio answered no SYS_PING on the
first three Zigbee2MQTT starts and answered on the fourth, with no radio
restart in between. Each start sends 26 bytes: a 5-byte ping (250 ms), 0xEF,
a ping (250 ms), then up to three pings (6 s each). On 11 Nov the fourth
start's two quick pings also went unanswered and its first 6 s ping was
answered. Replayed into TI's unmodified parser, exactly that pattern
follows from one stray SOF plus a length of 82..86 before the first start,
and from no other length. The live B1E pages read on 11 Nov show the
firmware up since power-on (uptime = host uptime) with no NPI/UART fault,
HOLD or reset. A stall that ended within the same 1.5 s of the fourth start
on both mornings is not excluded. The stray bytes were not captured, so this
stage also records what the parser discards (B1E8): the next bad morning
tells the two apart.

This stage changes nothing for a correctly framed byte stream:
  1. Idle resync. The transport RX callback (npi_task.c, V50 stage) reports
     every chunk's arrival. If a chunk arrives into an EMPTY parser buffer
     more than 500 ms after the previous chunk, whatever the parser had
     collected before it is stale: the partial frame is freed and the parser
     hunts for a start-of-frame again. A frame whose bytes arrive without
     such a gap is never touched, however late the NPI task processes them,
     and a gap that finds unparsed bytes is ignored (TI behaviour).
  2. Length bound. A length byte above MT_RPC_DATA_MAX is not a length. It
     ends that candidate frame at once; if it is itself 0xFE it is taken as
     the next start-of-frame.
  3. RAM-only evidence, answered by the NPI owner as B1E8 (op4 page6): valid
     frames, FCS failures, idle resyncs, rejected lengths, discarded bytes,
     the first resync's parser state, and the first eight bytes discarded
     before this boot's first valid frame. Inbound bytes only, never NV data.
"""
import hashlib
from pathlib import Path

from r4_uart_tx_liveness import once

FRAME = "source/ti/zstack/npi/npi_frame_mt.c"
MT_RPC = "source/ti/zstack/mt/mt_rpc.h"
PRISTINE_SHA256 = "1417a4aaef8431471fc2919da8264ffa00f67c8107e3cdb5bd4e072205e0d44b"
MARKER = "B4_V57_NPI_RX_FRAME_RESYNC"
EVIDENCE_SIZE = 248
IDLE_MS = 500
LEN_MAX = 250

INCLUDES = '#include <string.h>\n#include "mt_rpc.h"\n'
INCLUDES_NEW = ('#include <string.h>\n#include <stdint.h>\n'
                '#include <ti/sysbios/knl/Clock.h>\n#include "mt_rpc.h"\n')

STATE_ANCHOR = "static uint8_t tempDataLen;\n//@}\n"

STATE = r"""
/* B4_V57_NPI_RX_FRAME_RESYNC: see the V57 stage receipt.
 * TI's collector below waits without limit for LEN + 3 bytes after any
 * 0xFE. A stray 0xFE on the RX line therefore swallows the following valid
 * host frames. V57 frees a partial frame when the next chunk arrives after
 * an idle gap into an empty parser buffer, and refuses impossible lengths.
 *
 * Ownership: B4_V57_RxArrived runs in the transport RX callback (UART
 * callback context, one caller, never re-entered) and owns LastArrival,
 * Arrived and the writes of GapSeq. Everything else belongs to the NPI task
 * that runs the collector and answers the snapshot; it only reads GapSeq,
 * an aligned 32-bit load. */
#define B4_V57_IDLE_MS 500u
#define B4_V57_LEN_MAX 250u /* MT_RPC_DATA_MAX */
#if defined(MT_RPC_DATA_MAX) && (MT_RPC_DATA_MAX != 250)
#error B4_V57 length bound requires MT_RPC_DATA_MAX == 250
#endif
#define B4_V57_EVIDENCE_SIZE 248u
#define B4_V57_BOOT_JUNK 8u
typedef struct
{
    uint32_t framesOk, fcsFail, resyncs, oversize, junk, allocFail;
    uint32_t firstOkTick, firstResyncTick, lastResyncTick, lastFcsTick;
    uint8_t seenOk, firstState, firstLen, firstCmd0, firstCmd1, firstCollected;
    uint8_t bootJunkCount, bootJunk[B4_V57_BOOT_JUNK];
} B4_V57_Rx_t;
static B4_V57_Rx_t B4_V57_Rx;
static volatile uint32_t B4_V57_GapSeq = 0u;
static uint32_t B4_V57_GapSeen = 0u;
static uint32_t B4_V57_LastArrival = 0u;
static uint8_t B4_V57_Arrived = 0u;

static void B4_V57_Inc(uint32_t *value)
{
    if (*value != 0xFFFFFFFFu) ++*value;
}

/* Transport RX callback, before TI copies the chunk into the parser buffer.
 * pending = bytes the parser has not consumed yet. Only a gap that finds
 * the buffer empty marks an exact boundary: the parser state then describes
 * precisely the bytes received before the gap. */
void B4_V57_RxArrived(uint16_t pending)
{
    uint32_t now = Clock_getTicks();
    if (pending == 0u &&
        (!B4_V57_Arrived ||
         (uint32_t)(now - B4_V57_LastArrival) >= (B4_V57_IDLE_MS * 1000u) / Clock_tickPeriod))
        B4_V57_GapSeq = B4_V57_GapSeq + 1u;
    B4_V57_LastArrival = now;
    B4_V57_Arrived = 1u;
}

/* NPI task: has an idle gap been reported since the last check? */
static uint8_t B4_V57_GapPending(void)
{
    return (uint8_t)(B4_V57_GapSeq != B4_V57_GapSeen);
}

/* NPI task, before the collector reads the first byte after a gap. */
static void B4_V57_ResyncAfterGap(void)
{
    uint32_t now;
    B4_V57_GapSeen = B4_V57_GapSeq;
    if (state == NPIFRAMEMT_SOP_STATE) return;
    now = Clock_getTicks();
    if (B4_V57_Rx.resyncs == 0u)
    {
        B4_V57_Rx.firstResyncTick = now;
        B4_V57_Rx.firstState = state;
        if (state != NPIFRAMEMT_LEN_STATE)
        {
            B4_V57_Rx.firstLen = LEN_Token;
            if (state != NPIFRAMEMT_CMD_STATE1) B4_V57_Rx.firstCmd0 = pMsg[MTRPC_POS_CMD0];
            if (state == NPIFRAMEMT_DATA_STATE || state == NPIFRAMEMT_FCS_STATE)
            {
                B4_V57_Rx.firstCmd1 = pMsg[MTRPC_POS_CMD1];
                B4_V57_Rx.firstCollected = tempDataLen;
            }
        }
    }
    B4_V57_Inc(&B4_V57_Rx.resyncs);
    B4_V57_Rx.lastResyncTick = now;
    /* LEN_STATE has not allocated yet; every later state owns pMsg. */
    if (state != NPIFRAMEMT_LEN_STATE) OsalPort_msgDeallocate(pMsg);
    pMsg = NULL;
    state = NPIFRAMEMT_SOP_STATE;
}

static void B4_V57_Put32(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)value; out[1] = (uint8_t)(value >> 8u);
    out[2] = (uint8_t)(value >> 16u); out[3] = (uint8_t)(value >> 24u);
}

/* NPI owner context only (the same task as the collector): B1E8, op4 page6.
 * out[8..11] is the public source digest, written by the caller. */
__attribute__((noinline)) void B4_V57_RxFrameSnapshot(uint8_t *out)
{
    uint16_t j;
    for (j = 0u; j < B4_V57_EVIDENCE_SIZE; ++j) out[j] = 0u;
    out[0] = 'B'; out[1] = '1'; out[2] = 'E'; out[3] = '8';
    out[4] = 1u; out[5] = (uint8_t)B4_V57_EVIDENCE_SIZE;
    out[6] = (uint8_t)((B4_V57_Rx.seenOk ? 1u : 0u) | (B4_V57_Rx.resyncs ? 2u : 0u) |
                       (state != NPIFRAMEMT_SOP_STATE ? 4u : 0u));
    B4_V57_Put32(out + 12u, Clock_getTicks());
    B4_V57_Put32(out + 16u, B4_V57_Rx.framesOk);
    B4_V57_Put32(out + 20u, B4_V57_Rx.fcsFail);
    B4_V57_Put32(out + 24u, B4_V57_Rx.resyncs);
    B4_V57_Put32(out + 28u, B4_V57_Rx.oversize);
    B4_V57_Put32(out + 32u, B4_V57_Rx.junk);
    B4_V57_Put32(out + 36u, B4_V57_Rx.allocFail);
    B4_V57_Put32(out + 40u, B4_V57_GapSeq);
    B4_V57_Put32(out + 44u, B4_V57_Rx.firstOkTick);
    B4_V57_Put32(out + 48u, B4_V57_Rx.firstResyncTick);
    B4_V57_Put32(out + 52u, B4_V57_Rx.lastResyncTick);
    B4_V57_Put32(out + 56u, B4_V57_Rx.lastFcsTick);
    out[60] = B4_V57_Rx.firstState;
    out[61] = B4_V57_Rx.firstLen;
    out[62] = B4_V57_Rx.firstCmd0;
    out[63] = B4_V57_Rx.firstCmd1;
    out[64] = B4_V57_Rx.firstCollected;
    out[65] = state;
    out[66] = B4_V57_Rx.bootJunkCount;
    out[67] = (uint8_t)B4_V57_LEN_MAX;
    for (j = 0u; j < B4_V57_BOOT_JUNK; ++j) out[68u + j] = B4_V57_Rx.bootJunk[j];
    out[76] = (uint8_t)B4_V57_IDLE_MS; out[77] = (uint8_t)(B4_V57_IDLE_MS >> 8u);
}
"""

LOOP_HEAD = ("    while (NPIRxBuf_GetRxBufCount())\n"
             "    {\n"
             "        NPIRxBuf_ReadFromRxBuf(&ch, 1);\n")
LOOP_HEAD_NEW = ("    while (NPIRxBuf_GetRxBufCount())\n"
                 "    {\n"
                 "        /* B4_V57: the next byte arrived after an idle gap. */\n"
                 "        if (B4_V57_GapPending()) B4_V57_ResyncAfterGap();\n"
                 "        NPIRxBuf_ReadFromRxBuf(&ch, 1);\n")

SOP = ("                if (ch == MT_SOF)\n"
       "                {\n"
       "                    state = NPIFRAMEMT_LEN_STATE;\n"
       "                }\n"
       "                break;\n")
SOP_NEW = ("                if (ch == MT_SOF)\n"
           "                {\n"
           "                    state = NPIFRAMEMT_LEN_STATE;\n"
           "                }\n"
           "                else\n"
           "                {\n"
           "                    /* B4_V57: evidence only; TI discards the byte. */\n"
           "                    B4_V57_Inc(&B4_V57_Rx.junk);\n"
           "                    if (!B4_V57_Rx.seenOk && B4_V57_Rx.bootJunkCount < B4_V57_BOOT_JUNK)\n"
           "                        B4_V57_Rx.bootJunk[B4_V57_Rx.bootJunkCount++] = ch;\n"
           "                }\n"
           "                break;\n")

LEN = ("            case NPIFRAMEMT_LEN_STATE:\n"
       "                LEN_Token = ch;\n")
LEN_NEW = ("            case NPIFRAMEMT_LEN_STATE:\n"
           "                if (ch > B4_V57_LEN_MAX)\n"
           "                {\n"
           "                    /* B4_V57: no MT frame is this long, so this is not a\n"
           "                     * length. A repeated SOF starts the next candidate. */\n"
           "                    B4_V57_Inc(&B4_V57_Rx.oversize);\n"
           "                    state = (ch == MT_SOF) ? NPIFRAMEMT_LEN_STATE : NPIFRAMEMT_SOP_STATE;\n"
           "                    break;\n"
           "                }\n"
           "                LEN_Token = ch;\n")

ALLOC_FAIL = ("                else\n"
              "                {\n"
              "                    state = NPIFRAMEMT_SOP_STATE;\n"
              "                    return;\n"
              "                }\n")
ALLOC_FAIL_NEW = ("                else\n"
                  "                {\n"
                  "                    B4_V57_Inc(&B4_V57_Rx.allocFail);\n"
                  "                    state = NPIFRAMEMT_SOP_STATE;\n"
                  "                    return;\n"
                  "                }\n")

BULK = ("                /* Check number of uint8_ts left in the Rx buffer */\n"
        "                uint8_tsInRxBuffer = NPIRxBuf_GetRxBufCount();\n")
BULK_NEW = BULK + ("                /* B4_V57: bytes behind a reported gap are not this frame's\n"
                   "                 * data. Count first, then look: a gap reported after the\n"
                   "                 * count cannot have added to it. The loop head resyncs. */\n"
                   "                if (B4_V57_GapPending()) uint8_tsInRxBuffer = 0u;\n")

FCS_OK = ("                    if ( incomingFrameCBFunc )\n"
          "                    {\n"
          "                        incomingFrameCBFunc(MTRPC_FRAME_HDR_SZ + LEN_Token, pMsg, msgType);\n"
          "                    }\n")
FCS_OK_NEW = ("                    B4_V57_Inc(&B4_V57_Rx.framesOk);\n"
              "                    if (!B4_V57_Rx.seenOk)\n"
              "                    {\n"
              "                        B4_V57_Rx.seenOk = 1u;\n"
              "                        B4_V57_Rx.firstOkTick = Clock_getTicks();\n"
              "                    }\n") + FCS_OK

FCS_BAD = ("                    /* deallocate the msg */\n"
           "                    OsalPort_msgDeallocate(pMsg);\n")
FCS_BAD_NEW = FCS_BAD + ("                    B4_V57_Inc(&B4_V57_Rx.fcsFail);\n"
                         "                    B4_V57_Rx.lastFcsTick = Clock_getTicks();\n")


def apply(sdk):
    sdk = Path(sdk)
    path, rpc = sdk / FRAME, sdk / MT_RPC
    if any(p.is_symlink() or not p.is_file() for p in (path, rpc)):
        raise ValueError("V57_NPI_FRAME_FILES_REQUIRED")
    before = path.read_text()
    if MARKER in before:
        raise ValueError("V57_NPI_FRAME_ALREADY_APPLIED")
    if hashlib.sha256(before.encode()).hexdigest() != PRISTINE_SHA256:
        raise ValueError("V57_NPI_FRAME_REQUIRES_PRISTINE_TI_3615AD5D")
    # The bound is TI's own constant, not a locally invented number.
    if [line.split() for line in rpc.read_text().splitlines()
            if line.startswith("#define MT_RPC_DATA_MAX")] != [
                ["#define", "MT_RPC_DATA_MAX", str(LEN_MAX)]]:
        raise ValueError("V57_MT_RPC_DATA_MAX_DRIFT")
    text = once(before, INCLUDES, INCLUDES_NEW, "V57_INCLUDES")
    text = once(text, STATE_ANCHOR, STATE_ANCHOR + STATE, "V57_STATE")
    text = once(text, LOOP_HEAD, LOOP_HEAD_NEW, "V57_LOOP_HEAD_RESYNC")
    text = once(text, SOP, SOP_NEW, "V57_SOP_JUNK_EVIDENCE")
    text = once(text, LEN, LEN_NEW, "V57_LENGTH_BOUND")
    text = once(text, ALLOC_FAIL, ALLOC_FAIL_NEW, "V57_ALLOC_FAIL_EVIDENCE")
    text = once(text, BULK, BULK_NEW, "V57_BULK_READ_STOPS_AT_GAP")
    text = once(text, FCS_OK, FCS_OK_NEW, "V57_FRAME_OK_EVIDENCE")
    text = once(text, FCS_BAD, FCS_BAD_NEW, "V57_FCS_FAIL_EVIDENCE")
    if (text.count(MARKER) != 1 or
            text.count("#define B4_V57_IDLE_MS %du" % IDLE_MS) != 1 or
            text.count("#define B4_V57_LEN_MAX %du" % LEN_MAX) != 1 or
            text.count("#define B4_V57_EVIDENCE_SIZE %du" % EVIDENCE_SIZE) != 1 or
            text.count("if (B4_V57_GapPending()) B4_V57_ResyncAfterGap();") != 1 or
            text.count("void NPIFrame_collectFrameData(void)") != 1 or
            text.count("OsalPort_msgDeallocate(pMsg);") != 2 or
            text.count("state = NPIFRAMEMT_SOP_STATE;") != 3):
        raise ValueError("V57_NPI_FRAME_SCOPE_DRIFT")
    path.write_text(text, encoding="utf-8", newline="")
    return {
        "schema": "p7u-v57-npi-rx-resync-v1",
        "file": FRAME,
        "idle_resync_ms": IDLE_MS,
        "idle_resync_condition": "CHUNK_ARRIVED_AFTER_GAP_INTO_EMPTY_PARSER_BUFFER",
        "length_bound": LEN_MAX,
        "length_bound_source": "MT_RPC_DATA_MAX",
        "b1e8_query": "B1Q1 v1/8 op4 page6",
        "b1e8_size": EVIDENCE_SIZE,
        "arrival_hook_owner": "V50_STAGE_NPI_TASK_TRANSPORT_RX_CALLBACK",
        "valid_frame_stream_behaviour_changed": False,
        "changes_network_nv_or_security": False,
        "root_cause_proven": False,
        "flash_authorized": False,
        "before_sha256": hashlib.sha256(before.encode()).hexdigest(),
        "modified_sha256": hashlib.sha256(text.encode()).hexdigest(),
    }
