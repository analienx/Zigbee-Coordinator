# R4 host recorder contract (Deliverable C)

Status: CONTRACT ONLY. R4-00 Wonder gate stays OPEN.
No serial/MQTT/hardware actions authorized.

## Options verdict (from scout evidence)

- Option A — passive-only stock-compatible recorder (parse existing
  ZNP/ZCL traffic, never send custom MT): ADOPT FIRST. Zero firmware
  dependency, zero MT/herdsman risk, works against stock 20260310.
- Option B — opt-in F0 poll via the one existing ZNP owner: ADOPT
  SECOND, only after B0-D exists and the gate closes. Path is the
  scoped herdsman/adapter addition through the single serial owner
  (`Znp` solely owns serialPort/unpiWriter behind AsyncMutex):
  verdict VIABLE per scout prior result 3.
- Option C — external Z2M extension reaching raw MT on its own:
  REJECTED. No safe existing single-owner request API exists
  (herdsman `Znp`/`znp` private, adapter exposes no raw-MT API;
  only path is `(adapter as any).znp.request` with a foreign
  definition entry — visibility bypass + sequence race). Scout
  prior result 3 verdict: REJECTED.

Recorder ships A first; B is opt-in behind an explicit flag and
requires the B-side plumbing (Z2M + herdsman, heavier — POSSIBLE
BUT HEAVIER per scout).

## Schema fields (per sample)

- `ts_wall`, `ts_monotonic`, `boot_epoch` (host-stamped; v2 has no
  on-wire epoch/seq).
- `transport`: serial port id, baud, USB path if known.
- `srsp_outcome` per SREQ: ok / timeout / status-mismatch, with
  `waiterId` and timeout ms (mirrors `znp.ts` SREQ semantics).
- `zcl_outcome` per transaction: ok / timeout (never a fault locus).
- `f0_present` bool + `f0_counters[25]` (u32, UNKNOWN sentinel where
  unmeasured) + `f0_rtt_ms`.
- `fault_label` from classifier below + `confidence` from the
  Deliverable A taxonomy.

## 24 h ring

- Append-only local ring, 24 h retention, size-capped; oldest samples
  evicted first. Survives recorder restart only as flat files; no DB.

## Backpressure / poll-suppression (incl. OTA)

- Passive parse never blocks the ZNP queue; on backpressure drop
  recorder samples, never adapter traffic.
- F0 polling (Option B only): fixed cadence (default >= 30 s),
  suppressed entirely while OTA in progress and while any SREQ is
  awaiting SRSP; single outstanding F0; poll failure never retries
  into the burst (one skip, then resume cadence).
- OTA correlation is recorded as temporal overlap, never causation.

## Last-good snapshot

- Recorder keeps the last fully-parsed sample + last good F0 read
  with wall timestamps, so a SIGTERM/teardown (cf. #87 09:43:58)
  leaves a readable pre-death state instead of a truncated tail.

## Redaction

- No raw logs stored; no IEEE addresses, network/TC keys, or tokens
  persisted. Counters and outcomes only. Anything looking like key
  material is dropped at parse time.

## Single-owner hard negatives (never do)

- Never open the serial port directly (passive tap reads Z2M/herdsman
  events or a tee, never the port).
- Never hand-build `UnpiFrame` + private `unpiWriter` (bypasses the
  `createRequest` name lookup that rejects unknown commands).
- Never `(adapter as any).znp` casts or foreign definition entries.
- Never send MT during OTA, during an open SREQ wait, or from more
  than one owner.

## Fault classifier + 4 synthetic incident fixtures

Classifier (passive + optional F0; all thresholds are defaults,
tunable; burst default N = 8):

0. Fail-closed guards (evaluated first, in order): SIGTERM/close →
   `host_teardown`; F0 read absent → `unknown_needs_counters`;
   boot-epoch changed across the sample pair → `unknown_needs_counters`
   (cross-reboot deltas are spurious); any input counter equal to the
   UNKNOWN sentinel → `unknown_needs_counters` (UNKNOWN is never a
   measurement; `delta(UNKNOWN, UNKNOWN) == 0` must not read as a
   stall). No radio-fault label is reachable through these guards.
1. `srsp_absence_burst`: >= N SREQ timeouts in window with F0
   showing srspEnqueued stall and flat AF confirms.
2. `af_confirm_failure`: SRSPs ok, afConfirm* deltas move with ZCL
   timeouts.
3. `host_teardown`: SIGTERM/close observed; samples after it ignored.
4. `unknown_needs_counters`: ZCL timeouts with no F0 (passive only).

Synthetic fixtures (inline in `tests/test_r4_01a_diag_contracts.py`,
synthetic-only, no secrets/hardware):

- F1 `synthetic_srsp_absence`: 64 AF SREQs, all SRSP-timeout, F0
  shows srspEnqueued frozen + txRejectedDrops rising.
- F2 `synthetic_af_confirm`: SRSPs ok, afConfirmOtherFailed rising,
  ZCL timeouts.
- F3 `synthetic_teardown`: samples stop at SIGTERM marker; tail
  samples absent, last-good snapshot asserted.
- F4 `synthetic_ota_overlap`: OTA flag overlaps burst; classifier
  still returns burst label with `ota_causal=false`.
