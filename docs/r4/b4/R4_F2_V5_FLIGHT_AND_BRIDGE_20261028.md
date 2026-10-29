# R4 P7U — F2 v5 evidence pages / root-cause diagnosis contract

**Candidate, source-only. NOT deployed to hardware/HA. No reset, flash, network
formation, UART second owner, NV/security/CCFG mutation or bridge modification.**

## Why the new pages exist

The Oct 22/27 incidents had AF→ZDO→UTIL→SYS SRSP timeouts; the 27-Oct
non-destructive ROM BSL entry+exit restored the same application and network
after normal radio/ESP restarts failed. That isolates a reversible execution,
UART forwarding, reset-sequencing or runtime state class, **not** a proven
specific cause. The last known valid F2 was many hours old, so a richer
single late query cannot resolve the incident. See issues #143, #144, #180.

### Wire protocol — backward compatible

The existing `SYS F2` request with exactly **8 nonce bytes** returns the
unchanged **248-byte minor4** body. New opt-in `SYS F2` with **9 bytes**
(`uint8 page`, followed by the existing 8-byte nonce) requests:

* **Page 1**: 160-byte `R4D5` / major5/page1, boot entropy if sourced,
  sequence, monotonic tick, NPI task wake/progress, MT command entry/exit,
  3-slot v4.5 reserve use/exhaustion/release fault/occupancy, all-SRSP
  allocation/framing/TL rejected, physical UART callback OK/error and RX
  byte counters from existing v4.3 hooks.
* **Page 2**: 160-byte `R4D5` / major5/page2 with the **same snapshot**
  sequence/tick/boot/nonce and the 16 latest **task-side events**, oldest
  first: MT enter/exit, NPI framed enqueue, TL submit and accept/reject,
  static reserve exhausted. Each record = tick32, command16,
  stage8, outcome8. Command codes are decoded to subsystem for evidence
  output; raw frames, keys, IEEE addresses, PAN and payloads are never saved.

Both page requests must run through the **existing herdsman ZNP queue and
waitress**. Page 1 atomically caches page 2 into fixed RAM, with exactly one
nonce-bound page2 retrieval; missing/stale/wrong-nonce page2 returns page255
as an explicit invalid response rather than another snapshot. Pages must
match 24-byte nonce+boot+sequence+tick header exactly. An 8-byte request
never switches to v5. Duplicate SYS IDs/competing raw serial owners are
forbidden. Each new page is read-only and contains no RF operation.

### Strict layout (both pages are 160B, little-endian)

| Bytes | Meaning |
| --- | --- |
| 0–3 | ASCII `R4D5` |
| 4, 5 | major=5, page=1 or 2 (255 means invalid) |
| 6–7 | payload length 160 |
| 8–15 | eight-byte request nonce, not exported |
| 16–23 | radio boot token or zero, not exported / not hardware proof |
| 24–27 | common RAM snapshot sequence |
| 28–31 | common radio tick |
| 32–143 (page1) | see `p7u_f2_v5_pages.FIELD_OFFSETS`; includes NPI handoff requests, UART write accepted/rejected, UART state flags, first UART fault kind/tick and B1 first failure |
| 144–151 (page1) | First-anomaly preceding event (8B; zero if absent) |
| 152–159 (page1) | Frozen first anomalous event (8B; zero if absent) |
| 32–159 (page2) | 16 packed 8-byte records; unused entries zero |

Page1 validity bits at offset104: bit0 boot entropy sourced, bit1 cached
page2 valid, **bit2 indicates a frozen first anomaly**. All higher bits
MUST be zero. The anomaly latch captures the first observable NPI UART TL
rejection (stage 8) or reserved SRSP pool exhaustion (stage 9), along with
the immediately preceding recorded event. This latch does **not** magically
detect a silent MT handler or CPU deadlock: those require interpreting
progress deltas from the last successful sample and external host data.
The ring still retains the latest 16 task-side events, independently of
the immutable first-anomaly pair. Neither status authorizes a reset. In particular, none of these
are claimed as measured until source-qualified separately: global free
heap bytes, contiguous block/low-water, arbitrary Zigbee stack task
heartbeats, task stack high-water, ESP UART forwarding in USB-direct mode.
Old v4.3 progress and response allocation failure counters remain valid,
so explicit failure-stage evidence is useful without inventing heap bytes.

## Instrumentation safety

* Fixed 16×8-byte event ring, two additional 8-byte first-anomaly
  records and fixed 160-byte second-page cache;
  no dynamic allocation, logging, RF, NVS or host serial writes in hooks.
* NPI wake pulse is updated without spamming the event ring; event records
  are only task-side transition points. Existing UART callback counters
  are reported verbatim, not relabeled as host receipt.
* V5 C declarations are emitted before all NPI call sites; cross-TU V4
  boot-token symbols are explicitly declared from the pinned V4 source.
  New NPI queue/TX hooks decode command tags **only** from complete
  frames of at least 5 bytes; NULL/short frames get an invalid-frame
  sentinel without reading CMD0/CMD1. Native full-TU build remains required.
* Capture command tags only (CMD0/CMD1), no payloads. Skip diagnostic F2
  events so sampling does not erase the incident ring.
* The v4.5 reservation's static frames are still scrubbed after TL copy.
  Event staging reads local copies before queue wakeup, avoiding UAF.
* Unrecognized page selector returns an explicit nonce-bound invalid-page
  response (`R4D5` page=255), never 160 zero bytes. Both host decoders
  check boot-token validity, frozen-event presence, stage/result shape
  and reject recent-looking future timestamps with half-range uint32
  modular arithmetic; a tick just before uint32 wrap and snapshot just
  after wrap is valid. Very old timestamps beyond half a tick wrap are
  **unqualified**, not a proven failure cause.
* V4.3 UART progress is sampled while V5's outer OSAL CS is held. The
  V4.3 getter uses its own nested OSAL CS and restores the outer state;
  radio event-ring and progress acquisition are now mutually protected.
  The count still represents discrete update sites rather than a single
  hardware-instant attestation.
* The 16-entry ring uses a separate modular write cursor. Its lifetime
  `eventTotal` saturates at UINT32_MAX, but new events continue replacing
  the oldest entries indefinitely; tested at saturation without billions
  of writes.
* Old V4 F2 remains unchanged, including its original nonce location,
  protocol and validity mask.
* Direct source/host regression tests and exact-current-SHA two native
  ARM builds are mandatory. Hosted tests are **NOT** physical proof.

## Independent boundary evidence

The currently selected **USB-direct** transport must not be credited with
ESP UART RX/TX metrics unless a vendor-board source and physical trace
prove the ESP is actually on that data path. `p7u_boundary_evidence.py`
accepts only independently authenticated, mode-specific observations and
rejects invented ESP counters in USB mode. Existing-owner host UNPI
bytes/valid frames, OS USB detach/reenumeration and qualified radio
TX callback samples are distinct. A positive radio→host or radio→ESP
gap attribution now requires the **same audited host-monotonic interval**
for both independent counters, uninterrupted observer counter epochs and
authenticated source/mode visibility. Absent any such evidence the result
is `INSUFFICIENT_TO_LOCATE_SILENT_HANG`, never a fabricated zero-byte gap.
Classifier output is **correlation** only, not automatic recovery authorization.

SMLIGHT's public manual distinguishes Ethernet serial-over-TCP from USB
direct serial; the installed SLZB-OS proprietary build's exact data-mux
instrumentation is **not source-qualified here**. No ESP firmware patch
or unsafe USB monitor is being claimed or deployed.

## Sampling and forensic acceptance

1. Complete exact-source TS compile for the existing-owner 9-byte query,
   negative nonce/page/sequence tests and one ABI-fail-closed packet.
2. Offer healthy host-only samples at a low rate (existing 60–90s adaptive
   collector), with **no extra F2 during OTA, busy adapter/Waitress
   or a pending timeout cooldown**. An admitted V5 read is one nonce-bound
   page1/page2 pair, without immediate retries. A matching F2 reply timeout
   uses the proven V4 bounded consecutive-timeout counter, 60-second cooldown
   and owner-progress requirement; after repeated timeouts the owner
   quarantines. Unknown transport/invalid response errors quarantine immediately.
3. Persist a bounded redacted **sanitized** pair through the existing
   hash-chained worker using its strict allowlist. A V5 read that reached
   owner submission but timed out or failed validation records a `FAILED`
   record with `SENT_OR_UNCERTAIN`, never `SKIPPED / NONE`; a veto
   before submission remains `SKIPPED / NONE`. A successful `FLIGHT`
   includes the HMAC-SHA256 truncated keyed radio boot-epoch tag derived
   in-process using the **same secret as V4**; raw boot bytes, keys and
   nonce are dropped *before IPC*. The companion owner-only `hostEvidence`
   is captured **after the page pair**, not magically simultaneous with
   the radio snapshot. Independent ESP observations require their separate
   attested comparable time-window provenance.
4. The collector should act on the **first passive SRSP failure** to
   preserve what already exists, never bypassing the owner queue to force
   another F2. The live Z2M installation remains unchanged until a
   reviewed, paired deployment.
5. End-to-end hardware proof requires three consecutive coherent pairs
   while healthy, current-owner epoch continuity, and an incident
   during which the last good pair and independent host evidence explain
   the first missing boundary. A frozen in-flight MT event is *not*
   automatically a deadlock: completion may have happened after the last
   sample. The Oct 27 ROM/BSL recovery is not a firmware cure.

**Scope limitation:** The new radio hook records NPI loop and MT dispatch
progress, but cannot independently count a Zigbee background stack thread
unless a separately pinned safe task-loop hook is validated. Global heap
low-water and task stack margin remain unknown (not fabricated).

## 29 October 2026 code-review repairs and remaining physical gates

Seven independent review findings addressed in source: submitted V5 timeout
classification, coherent progress and event acquisition, live/worker reserve
counter parity, privacy-safe cross-sample boot tag with passive post-pair host
evidence, comparable observer windows, V4 shared timeout budget, and permanent
ring write continuation at UINT32 lifetime count saturation. Source-level and
compiled native-host regressions are part of the PR head. 

**NOT FLASH READY:** a native compiler/linker success is distinct from a
bootable, safely erasable real-image profile. Existing guard receipts report
protected CCFG erase-sector collision and an unqualified stock20260311 boot
handoff; do not weaken the CCFG/NV/security gates to make a green build look
like flash authorization. Hardware validation is still separate from the F2
code fixes and can be performed only once the boot/protected-sector profile
and same-unit backups are source-and-device qualified. The user’s objective
remains root-cause evidence and firmware correction, not rollback proof.
