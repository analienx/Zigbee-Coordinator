# R4 source crosswalk (Deliverable C companion)

Every TI/herdsman/P10 claim below is cited as repo@sha path:line
from scout evidence. Gaps are explicit. No raw logs or credentials.

## TI SDK (`TexasInstruments/simplelink-lowpower-f2-sdk@3615ad5d3f4f271258d18a2f5ce1785064ff9a58`)

- `source/ti/zstack/mt/mt_sys.c:246` — `MT_SysCommandProcessing`
  defined (spans 246-398), switches on `pBuf[MT_RPC_POS_CMD1]` (:250).
- `source/ti/zstack/mt/mt_sys.c:252-387` — case labels RESET_REQ
  (0x00) through ZDIAGS 0x17/0x18/0x19/0x1A/0x1B (:371/:375/:379/
  :383/:387); no `0xF0` case label anywhere in file.
- `source/ti/zstack/mt/mt_sys.c:392-393` — default sets
  `MT_RPC_ERR_COMMAND_ID`; unassigned IDs (incl. 0xF0) land here.
- `source/ti/zstack/mt/mt.c:316` — `MT_BuildAndSendZToolResponse`
  defined (doc :305; decl in `mt.h`).
- `source/ti/zstack/mt/mt_sys.c:106` — `MT_SRSP_SYS` defined.
- `source/ti/zstack/mt/mt_rpc.h:131` — `MT_RPC_ERR_COMMAND_ID`
  (=2 invalid command ID).
- `source/ti/zstack/npi/npi_task.c:656` — `NPITask_sendToHost`
  defined (decl `npi_task.h:155`).
- `source/ti/zstack/npi/npi_task.c:758` — `NPITask_processStackMsg`
  (fwd decl :251; call :397).
- `source/ti/zstack/npi/npi_task.c:1069` — `NPITask_incomingFrameCB`
  (fwd decl :241; registered :307).
- `source/ti/zstack/npi/npi_task.c:850` — `NPITask_ProcessTXQ`
  (fwd decl :218; call :436).
- `source/ti/ti154stack/common/osal_port/osal_port.h:573/:585` —
  `OsalPort_enterCS`/`leaveCS` declared; definitions in
  `ti154stack/common/osal_port/osal_port_posix/osal_port.c:1223/:1240`;
  zstack call sites `npi_task.c:338,667,800,858,890`,
  `npi_tl.c:175,267,420`, `mt_sys.c:1890` (enter) and
  `npi_task.c:347,700,833,872,915`, `npi_tl.c:199,278,425,455`
  (leave). GAP: no zstack-namespaced osal_port copy exists at this
  sha (only `source/ti/zstack/osal/osal_nv.c/h`); the link-time
  provider the ZNP build resolves was not pinned — not guessed.
- `source/ti/zstack/npi/npi_tl.c:209` — `NPITL_checkNpiBusy`
  (decl `npi_tl.h:177`; call sites `npi_task.c:366,433`,
  `npi_tl.c:423`).
- `source/ti/zstack/npi/npi_tl_uart.c` — GAP: exact UART2 lines
  not pinned at this commit; UART2 semantics are a B0-implementation
  proof obligation, never a contract claim.

## herdsman (`Koenkk/zigbee-herdsman@0968f979d558874b17396c96b66382d4236bbdcd`, v10.9.1)

- `definition.ts` SYS block lines 20-422 — 40 entries, IDs 0-29,
  48-54, 128-130; max SYS ID 130 (`jammerInd` 417-418; `resetInd`
  128 line 399; `osalTimerExpired` 129 line 412; `nvCompact` 54
  line 392); zero hits for ID 240 — SYS 240 (0xF0) absent.
- `znp.ts` lines 235-242 — `request(...)` signature; 243-245 throw
  if not initialized; 252-270 SREQ waits matching SRSP with timeout
  (6000 ms default; 40000 ms for bdbStartCommissioning/
  startupFromApp); 272-277 reset AREQ waits resetInd 30000 ms;
  279-281 other AREQ fire-and-forget.
- `zpiObject.ts` lines 49-58 — `createRequest` throws when command
  NAME missing (rejects unknown custom MT SYS SREQ before any byte
  written); 74-79 unknown commandIDs throw in `fromUnpiFrame`.
- `zStackAdapter.ts` line 43 — `private znp: Znp`; no public raw-MT
  API (public surface sendZdo/sendZcl/permitJoin/backup/waitFor).
- `parser.ts` lines 27-33, 47-49; `frame.ts` 42-46; `znp.ts` 68-77 —
  UNPI framing-loss resync / debug-only drop / FCS throw / unknown
  commandID logged, never propagated.
- Z2M external-extension constructor evidence at Z2M master
  `344b6e03` (release 2.14.2, 2026-10-02; NOT a pinned acceptance
  baseline): same 8-arg construction; `zigbee.ts:17` private
  herdsman handle; no safe single-owner raw-MT API proven.
  GAP: Z2M docs page for external extensions not opened (source
  evidence sufficed for the reachability question).

## P10 F0 v2 ABI (PR60 head `b273044`, comparison donor only;
paths below are `firmware/t832/`-rooted)

- `firmware/t832/min/npi_diag_patch.py` L172-173/L177/L200/L208 —
  MT SYS 0xF0, version 2, 25 x u32 LE, reply `2+25*4`, SRSP via
  `MT_BuildAndSendZToolResponse`.
- `firmware/t832/min/npi_diag_decode.py` L22-23/L27/L31-32/L36-38 —
  `VERSION=2`, `SIZE=102`, 102-bytes-only, `flags & ~0x07`
  rejected (L31-32), flags bits 0-2 booleans (L36-38).
- 25 C names L15-23 + 25 decoder names L12-20 (reproduced verbatim
  in `R4_B0D_ABI_CONTRACT.md`).
- Five one-liner areas with files: alloc ledger
  (`NPI_ALLOC_OWNERSHIP` doc); TX retry 50 ms/x3 + busy latch
  (`npi_tx_recovery_patch.py`); RX overflow 32 B-scratch recovery
  (`npi_rx_overflow_patch.py`); SRSP-first 4:1 queue
  (`npi_srsp_fairness_patch.py`); 8 AF counters (`npi_af_status_patch.py`).

## Incident texts

- Issue #87 body (ISSUE-PROSE): 64 AF / 6 s SRSP, 6 ZDO
  mgmtPermitJoinReq, 69 TIMEOUT, SIGTERM 09:43:58, OTA 08:25-09:00.
- HA#73 comment 6139149384: on 13 Oct, F0 v2 showed async HWM 158, SRSP enqueue/accept 25 to 26, RTT 147-1549 ms, after a separate cold startupFromApp 40s timeout 06:07:57. The 2 Oct event had no contemporaneous F0 and must not be conflated.
- P7U logs were reviewed read-only in issue #85 comment 6211227402, but this source-only synthetic library has no raw logs. Per-waiter IDs, radio epoch and fitted board still unproven; STACKMSG v1/62B documentation is superseded.
