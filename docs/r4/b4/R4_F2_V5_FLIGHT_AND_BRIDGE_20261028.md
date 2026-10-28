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
| 144–159 (page1) | reserved, all zero |
| 32–159 (page2) | 16 packed 8-byte records; unused entries zero |

Page1 validity bits at offset104: bit0 boot entropy sourced, bit1 cached
page2 valid. **All other bits MUST be zero.** In particular, none of these
are claimed as measured until source-qualified separately: global free
heap bytes, contiguous block/low-water, arbitrary Zigbee stack task
heartbeats, task stack high-water, ESP UART forwarding in USB-direct mode.
Old v4.3 progress and response allocation failure counters remain valid,
so explicit failure-stage evidence is useful without inventing heap bytes.

## Instrumentation safety

* Fixed 16×8-byte event ring and fixed 160-byte second-page cache;
  no dynamic allocation, logging, RF, NVS or host serial writes in hooks.
* NPI wake pulse is updated without spamming the event ring; event records
  are only task-side transition points. Existing UART callback counters
  are reported verbatim, not relabeled as host receipt.
* Capture command tags only (CMD0/CMD1), no payloads. Skip diagnostic F2
  events so sampling does not erase the incident ring.
* The v4.5 reservation's static frames are still scrubbed after TL copy.
  Event staging reads local copies before queue wakeup, avoiding UAF.
* Only one bounded source snapshot under OSAL CS; old V4 F2 remains
  unchanged, including its original nonce location and validity mask.
* Direct source/host regression tests and exact-current-SHA two native
  ARM builds are mandatory. Hosted tests are **NOT** physical proof.

## Independent boundary evidence

The currently selected **USB-direct** transport must not be credited with
ESP UART RX/TX metrics unless a vendor-board source and physical trace
prove the ESP is actually on that data path. `p7u_boundary_evidence.py`
accepts only independently authenticated, mode-specific observations and
rejects invented ESP counters in USB mode. Existing-owner host UNPI
bytes/valid frames, OS USB detach/reenumeration and qualified radio
TX callback samples are distinct. Classifier output is **correlation**
only, never automatic recovery authorization.

SMLIGHT's public manual distinguishes Ethernet serial-over-TCP from USB
direct serial; the installed SLZB-OS proprietary build's exact data-mux
instrumentation is **not source-qualified here**. No ESP firmware patch
or unsafe USB monitor is being claimed or deployed.

## Sampling and forensic acceptance

1. Complete exact-source TS compile for the existing-owner 9-byte query,
   negative nonce/page/sequence tests and one ABI-fail-closed packet.
2. Offer healthy host-only samples at a low rate (existing 60–90s adaptive
   collector), with **no extra F2 at an active OTA, busy adapter/Waitress
   or after diagnostic timeout**.
3. Persist a bounded redacted **sanitized** pair through the existing
   hash-chained worker using its strict allowlist; independent host/ESP
   evidence uses a separate provenance code. Never persist raw nonce/boot
   identifiers or unredacted data.
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
