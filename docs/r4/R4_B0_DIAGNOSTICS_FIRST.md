# R4-B0 diagnostics-first taxonomy (Deliverable A, issue #87)

Status: CONTRACT ONLY (R4-B0 design, source-only). No firmware written.
R4-00 Wonder gate stays OPEN and gates any B0/B0-D implementation.
No causality claims beyond cited evidence.

## Confidence taxonomy (used on every item below)

- DIRECTLY OBSERVED: bytes/counts/timestamps quoted from the cited incident text.
- SOURCE PROVEN: exact repo@sha path:line anchor (see `R4_SOURCE_CROSSWALK.md`).
- SYNTHETIC INJECTION: fixture value in `tests/test_r4_01a_diag_contracts.py`, never a field claim.
- HYPOTHESIS: candidate mechanism, explicitly unproven.
- NOT MEASURED: quantity the incidents never captured.
- PHYSICAL UNVERIFIED: no authorized live/radio/hardware run under this issue.

## Failure layers

- L1 host/bridge (Z2M, herdsman, serial owner, USB/bridge path).
- L2 radio/firmware (NPI TX/RX queues, MT SYS dispatch, AF confirm path).

## Items 1-6 (issue #87 2-layer taxonomy)

### 1. AF data-request burst with no SRSP window (L2 fault, L1 witness)

- DIRECTLY OBSERVED: issue #87 body: 64 AF data-request SRSP timeouts at 6000 ms each ("ISSUE-PROSE" per scout prior result 1; the 6 s figure is the per-request timeout, not a measured burst window).
- DIRECTLY OBSERVED: 69 TIMEOUT lines and 6 ZDO mgmtPermitJoinReq in the same body.
- SOURCE PROVEN: SREQ waits for matching SRSP with per-command timeout (default 6000 ms); status checked against expectedStatuses — herdsman `znp.ts` lines 235-270.
- Distinction: SRSP-absence (no sync response within timeout) is NOT an AF-confirm failure; it fires before any AF confirm/ZCL exchange exists.
- NOT MEASURED: NPI TX queue depths, srspDepth/asyncDepth, HWMs at the time (no F0 counter read existed on P7U).
- HYPOTHESIS (unproven): TX-path saturation vs bridge stall — cannot separate without counters.

### 2. ZCL timeout cascade (L1 symptom of item 1)

- DIRECTLY OBSERVED: 69 TIMEOUT lines in #87 body after the AF burst.
- Distinction: ZCL timeout means the end-to-end transaction never completed; it does NOT locate the fault (SRSP vs AF-confirm vs route loss look identical at ZCL level).
- NOT MEASURED: per-hop AF confirm statuses for the 64 requests.

### 3. SIGTERM shutdown during fault (L1 host event, not a radio verdict)

- DIRECTLY OBSERVED: SIGTERM 09:43:58 in #87 body.
- Distinction: SIGTERM is a host-process event; any in-flight SRSP/AF state after it is host-teardown artifact, never radio evidence.
- NOT MEASURED: whether queues drained before termination.

### 4. OTA stall correlation window 08:25-09:00 (NOT trigger proof)

- DIRECTLY OBSERVED: OTA activity 08:25-09:00 precedes the incident in #87 body.
- HYPOTHESIS ONLY: OTA correlation is NOT trigger proof. No counter, log line, or source hook ties OTA traffic to the later SRSP absence. Recorded as temporal correlation, never causation.

### 5. P10 comparators (NOT same-root as P7U)

- DIRECTLY OBSERVED (external comment HA#73 `6139149384`): P10 F0 v2 live read on 13 Oct showed asyncHWM 158,
with SRSP enqueue/accept advancing from 25 to 26, RTT 147-1549 ms; separate 13 Oct `startupFromApp` 40 s timeout at 06:07:57.
- P10-2Oct vs P10-12Oct-USB-drop vs P10-13Oct-cold-start are three DISTINCT P10 episodes; the USB-drop and cold-start episodes implicate bridge/host path, the F0 live read implicates async-queue pressure on that P10 unit.
- P7U is NOT same-root as P10: different board/radio/firmware lineage; P10 evidence is comparator only, never P7U diagnosis.

### 6. What B0-D must separate (requirements, not claims)

B0-D counters must let a future reader distinguish, per incident:

| Signal | SRSP-absence | AF-confirm failure | ZCL-timeout-only |
|---|---|---|---|
| srspEnqueued / srspTxAccepted | may stall or move | may move | UNKNOWN absent radio telemetry |
| txImmediateRejects / txRejectedDrops | may move | flat | flat |
| afDirect*/afSource* + afConfirm* | flat | move | ambiguous |
| rxOverflowEvents | independent flag | independent flag | independent flag |

All counter semantics: SYNTHETIC INJECTION until B0-D firmware exists and hosted CI + authorized reads prove them.

## Evidence matrix

| Episode | Key signal | Confidence | Gap |
|---|---|---|---|
| P7U-16Oct (#87 body) | 64 AF/6 s, 6 ZDO, 69 TIMEOUT, SIGTERM 09:43:58, OTA 08:25-09:00 | DIRECTLY OBSERVED (prose counts) | raw Z2M logs uninspected; no counters (NOT MEASURED) |
| P10-2Oct | progressive AF to ZDO to SYS, NO contemporaneous F0 | DIRECTLY OBSERVED | no radio counters at failure |
| P10-13Oct after cold start | F0 async HWM 158, SRSP 25 to 26, RTT 147-1549 ms | DIRECTLY OBSERVED | captured after failure, not causal |
| P10-12Oct-USB-drop | bridge/host path implicated | DIRECTLY OBSERVED (comment) | no byte-level bridge trace |
| P10-13Oct-cold-start | startupFromApp 40 s timeout 06:07:57 | DIRECTLY OBSERVED (comment) | host vs radio split unknown |

Supervisor separately inspected Z2M log chronology read-only
(issue #85 comment 6211227402). No raw private logs or keys are
committed. Native P7U radio counters are still NOT MEASURED.


## Four-incident synthetic replay clarification

The hosted offline recorder suite models four strictly synthetic
episodes separately: P7U 16 Oct AF/ZDO/OTA/SIGTERM chronology,
P10 2 Oct progressive AF/ZDO/SYS, P10 12 Oct USB detach, and P10
13 Oct ZDO startup timeout followed by F0 responsiveness. Every
classification stays UNDETERMINED for root cause. P7U's 64 AF
failures across ~44 minutes do not alone establish an 8-in-120s
cluster. Synthetic illustrative event times are not private Z2M
logs and are not evidence of real radio queue state.
