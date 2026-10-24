# SLZB-06P7U — target: verified USB firmware cutover in <60 seconds

**Status 2026-10-24:** transport optimization, sparse capture and timing gate are
source-implemented/tested and HA runtime **code-only** staged. The complete
60-second production deployment is **NOT YET HARDWARE QUALIFIED**.
No additional BSL entry, erase, write or Zigbee outage was made for this work.

## Clock and goal

T0 = first service-impacting step (stop original Zigbee2MQTT).
T1 = new firmware booted, resumed original coordinator state 9 and Zigbee2MQTT
is fully started on USB, with retained network identity attested.
**Goal: T1 - T0 < 60 seconds**. Fresh RF topics and further F2 diagnostics
are independently checked afterward; don't report recovery based solely on
a successful flash CRC or vendor web UI 'DONE'.

All expensive preparation (hosted CI/release, full baseline image, provenance,
owner authorization, canonical plan, firmware hash and backups) must happen
**before** T0. If release hasn't been prepared, the one-minute timer is not
possible. Never skip security gates to meet this target.

## Why prior method cannot meet it

24-Oct live session: 2x full 704 KiB ROM readbacks took **397.65 s**
including setup/security HOLD (approximate wall clock). Raw dual full capture
alone transfers 1,441,792 bytes. At 115200 bps, 8N1 line framing makes the
*physical lower bound* ~125.2 s for only those bytes, excluding checks,
erase/program, reset and Z2M. Repeating both full reads in each cutover is
mathematically incompatible with 60 seconds at 115200.

TI SWRA466E says ROM UART BSL auto-baud can support up to 1.6 Mbaud on
CC26x2-family silicon. **The actual P7U USB path is ESP32-S3 CDC**, and the
ESP-to-TI side's UART baud cannot be assumed to follow the CDC line-coding
setting. SMLIGHT's documented higher Zigbee/Thread serial modes do NOT
qualify a P7U ROM BSL at 460800 or 921600. Default remains 115200 until
both halves of this specific gateway path are measured, with a fail-closed
read-only profile. No production speed switch is authorized by this note.

## Two release lanes

### A — safe full admission, first install / unknown current state

Keep original duplicate 704 KiB image capture, genuine native security reader,
independent candidate/CCFG/security SHA admission, exact sector delta,
last-vector boot and full 88-sector final parity. No one-minute SLA.
Use only if the installed radio image has no previously qualified exact baseline,
if previous write was ambiguous, or if NV records cannot be reconciled.

### B — incremental 60-second *candidate*, only after lane A has proven baseline

**Prepare, live (before T0):** hosted build and exact source/ELF/HEX/handoff
attested, baseline proven fully and linked to previous `flash-result.json`;
external identity, network-key, original IEEE inventory and monotonic
security floors approved. Freeze source-specific APP+AC000 delta and rollback
plan, stage binaries and HA Python interpreter dependencies outside Git.

**Cutover:**
1. Prove owner Z2M stopped, watchdog false and no other UART holder.
2. ESP keeps USB mode 2 and web management; enter TI BSL once.
3. Run one Python ROM writer directly on HA's exact
   `/dev/serial/by-id/usb-SMLIGHT_...` path, not Windows->TCP->socat.
   No restart/DTR reset or baud change.
4. For the *known-good installed image only*, compute 88 ROM per-sector CRCs,
   verify original APP/boot/CCFG unchanged, read all six 8KiB sectors in
   `0xA0000..0xABFFF` freshly and byte/ROM-CRC check each.
   `p7u_usb_sparse_capture.py` reconstructs a current-image SHA and an
   **explicit SPARSE** receipt. This is not falsely marked a double capture.
5. The genuine TI-native security preflight MUST validate the refreshed NV
   against current keys, counter floors, APS and **all 107 historic identities**.
   The current 106/107 and persisted TC mismatch from 24-Oct still BLOCK this
   step. **Do not skip or auto-repair NV.**
6. A **new, reviewed sparse-admission transition contract is still required**.
   Only after that code and independent negative tests are approved may the
   prepared delta be admitted; do not feed a sparse receipt into an API that
   requires full dual-capture proof. Recheck sector CRC before every mutation.
7. Erase/write only differing planned APP/AC000 sectors, keep boot vector
   last, journal/fsync before erase, retain all per-written-sector byte readbacks
   and final full-device CRC parity. Full 88-sector SHA admission is retained
   for first-use and unknown-state lane A; lane B needs separate evidence
   proving that its CRC delta is consistent with the pinned complete snapshot.
8. Boot once, start original Z2M once, check state9/identity and record T1.
   A failure or uncertain write is HOLD, never blind retry, auto full erase,
   stale NV restore, factory reset or re-pair.

### Timing contract

`p7u_usb_cutover_budget.py` returns a release-specific estimate from real
measured bytes-per-second, erase and ROM CRC costs, **per-sector byte readback**,
fresh protected NV read, stop/boot/start and an explicit safety margin.
- Measure **real** throughput through HA USB, not theoretical UART rate.
- Pre-admit only if estimated total fits 60 seconds, leaving margin.
- A large 25-sector replacement likely misses the SLA at 115200; a small
  source-localized delta may fit. Different images have different dirty sectors.
- Before first erase, reject over-budget plans. **After first erase never
  abort mid-sector merely because the deadline elapsed**; finish safely,
  record SLA miss, do not pretend success.
- Firmware size, sector layout, first startup and native security PASS remain
  hard gates independent of performance.

## Components, revision and testing

- `p7u_usb_fast_rom.py`: exact USB device whitelist + 115200; counted
  MEMORY_READ with one GET_STATUS every 32 successful read-only frames,
  explicit final status fence. Irreversible commands inherit original audited
  BSL status, poison latch and no NV/CCFG write windows.
- `p7u_usb_sparse_capture.py`: six fresh protected NV sectors and all
  88-ROM CRC consistency checks; no mutation or security admission claim.
- `p7u_usb_cutover_budget.py`: fail-closed predictive release budget.
- `r4_stock20260311_transition.py`: exact-type whitelist for retaining the
  audited per-packet GET_STATUS after SEND_DATA on this new subclass;
  all other injected ROM types keep conservative status behavior.
- HA source-only staged under `/share/p7u-usb-flasher-runtime/` with
  `pyserial==3.5`, `pyserial-asyncio==0.6`; runtime imported correctly.
  **No radio port was opened in this new development pass.**
- Hosted GH Actions test job verifies source, ROM framing, negative write,
  capture and timing constraints. No public flash secrets or raw device dumps.

**Do not call this an operational sub-minute flasher** before sparse
security-admission is integrated, the HA single-owner operator exists and
real live one-minute results pass. The original Zigbee network stays online
during these changes.
