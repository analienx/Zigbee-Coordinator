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

- Wall and monotonic timestamp, host_process_epoch, and a separately
  sourced radio_boot_id (UNKNOWN for V2). Host restart is NOT proof of
  radio restart or radio continuity.
- `transport`: serial port id, baud, USB path if known.
- `srsp_outcome` per SREQ: ok / timeout / status-mismatch, with
  `waiterId` and timeout ms (mirrors `znp.ts` SREQ semantics).
- `zcl_outcome` per transaction: ok / timeout (never a fault locus).
- f0_present, F0 ABI version, 25 u32 counter fields, RTT;
  V3 additionally has an explicit validity bitmap and qualified
  radio boot identity. V2 has no UNKNOWN sentinel or boot ID.
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

- Never open serial directly OR via independent serial tee. Passive
  mode needs one audited in-process Z2M/herdsman callback that cannot
  block the actual ZNP owner. That callback is NOT PROVEN yet.
- Never hand-build `UnpiFrame` + private `unpiWriter` (bypasses the
  `createRequest` name lookup that rejects unknown commands).
- Never `(adapter as any).znp` casts or foreign definition entries.
- Never send MT during OTA, during an open SREQ wait, or from more
  than one owner.


## Offline fault classification, not a deployed recorder

Reference model r4_diag_reference.py returns HOST observations with
root_cause=UNDETERMINED, never an asserted radio root cause. An AF
SREQ burst requires >=8 independent timed-out waiter IDs in <=120s.
The model consumes already deduplicated counts; source-verified
host event ingestion and IDs are NOT implemented and are a gate.

AF SREQ, ZDO SREQ, ZCL timeouts, USB loss and SIGTERM may all coexist.
A later SIGTERM does not erase earlier AF failure evidence and does
not indicate a spontaneous crash. OTA overlap is temporal only.
V2 counter deltas remain UNKNOWN without independently verified
radio continuity; V3 needs source-verified boot identity, monotonic
uptime/sequence, and validity on both counters.

Offline synthetic tests include short/overlong frames, invalid flags,
valid 0xFFFFFFFF counters, v3 validity bitmap, cross-radio boot,
USB/SIGTERM, OTA temporal overlap and bounded timeout windows.
These do not qualify a production recorder, an active firmware
extension or a safe external API. Production host hooks, explicit
waiter-ID correlation, atomic bounded rotation, crash recovery,
redaction and backpressure require their own independent review.


## Source-only passive recorder (NOT installed)

An inert, stdlib-only reference implementation now lives in
firmware/slzb-06p7u/r4/tools/r4_passive_recorder.py. It does NOT
subscribe to Z2M, access HA, open USB/serial, publish MQTT or issue ZNP.

- Future integration must audit a nonblocking in-process Z2M/herdsman
  callback. Until then, events enter ONLY via synthetic Python fixtures.
- Ingress offer() never performs disk IO, and strictly allowlists
  kind, monotonic at_ms and synthetic per-process waiter_id numbers
  for AF/ZDO timeouts. Unexpected fields, raw device identifiers,
  keys, log strings and payloads are rejected.
- Finite pending queue and event ring (default 128/256), last 24h
  retention, overflow drops only recorder samples, not adapter data.
  Worker drain() deduplicates waiter completions; clock reversal
  is discarded. No Zigbee work takes place in this library.
- Worker persist() atomically replaces a bounded sanitized snapshot
  in a preexisting directory using flush, fsync, os.replace.
  Previously valid snapshot survives failure before replace;
  POSIX files use mode 0600. Windows ACL review remains a
  deployment gate. No raw request IDs or secrets persisted.
- Future hook MUST provide per-host-process unique request waiter ID.
  NWK/IEEE addresses must NOT be used as IDs.
- For P7U 16 Oct, 64 timeouts across ~44 min do not prove >=8
  different waiter IDs in any 120s window. The negative synthetic
  replay rejects that inference. Actual timestamps and per-waiter
  dedup from a sourced callback remain a required integration gate.
- Hosted GitHub Actions runs all synthetic tests. No actual B0
  firmware, host collector or live HA integration is implied.
