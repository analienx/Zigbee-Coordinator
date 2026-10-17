# R4 B4 — read-only coordinator diagnosis (issue #98)

Source branch `feat/p7u-r4-b4-issue98` branches from **exact B0 `1baefbee8e4de2c9d28c5e1a7c339cf2025a2afe`**. Draft PR #100 targets sealed B0, not main or sibling B1/B2/B3. Explicit stage: **EXPERIMENTAL; NOT SOURCE_READY, NOT INSTALLED, PHYSICAL_UNVERIFIED**.

## Actual code and the trust boundary

- `b4_protocol.py`: finite offline UNPI SYS F0 framing/strict P10 v2 and proposed R4 v3 decoders. No serial access.
- `b4_native_patch.py`: **experimental** hash-guarded source patch to disposable exact-TI-SHA `/tmp` checkout. Instruments both verified TI SRSP enqueue producers in existing NPI critical sections for five static-RAM metrics: sync/async NPI TX queue depths and HWM plus `srsp_enqueued`. Exposes 132-byte v3 with validity bits 0–4 when NPI_SREQRSP is compiled (else async-only bits 2–3), boot cap 0 and boot ID 0; never claims missing metrics.
- `b4_native_link_audit.py`: native manifest+real ELF+TI nm symbol check. Both real CCS native builds, B0 CCFG and real ELF symbol verification have now passed (run 39000883442); image reproducibility checked separately (run 39002075430).
- `b4_verify_source.py`: checks exact TI/herdsman pins, F0 collision, stock SYS Ping/Version, NPI-specific `npi_client_mt.c` and owner/Waitress.
- `host/r4-b4/herdsman_overlay.py`: separate opt-in experimental patch for pinned herdsman. The default is **no polling**, no serial sidecar. Calls the existing `ZStackAdapter.znp.requestWithReply` through Znp mutex, skip while genuinely ZNP-mutex-busy/OTA, 30s cooldown; opt-in bounded metadata-only AF/ZDO/SYS timeout capture, no synchronous disk writes.
- `../tools/r4_passive_recorder.py`: reused #87 offline forensic model; no production hook or host install.
- `b4_hosted_c_probe.py`: real B4 function text compiled with hosted GCC ASan/UBSan and an invalidity mutant that must fail; this is not TI native linkage.
- `b4_inference.py`: strict offline evidence classifier and source-qualified-only UART interval oracle; no attribution or external data source.
- `host/r4-b4/b4_verify_z2m_source.py`: pins upstream Zigbee2MQTT 2.14.0 release SHA and its herdsman 10.9.1 dependency/public extension API; NOT an installed-version check.
- `b4_replay.py`: four time-labeled synthetic incident replays with observed counts where available. Unknown remains unknown.

## Verification gates

`b4_artifact_parity.py` accepts only a documented volatile CCS XML linker timestamp mismatch after proving byte-identical ELF/HEX/BIN; `b4_elf_budget.py` measures real B0/B4 allocated ELF sections (+156 bytes FLASH, +8 RAM; task/IRQ runtime stack unknown). `.github/workflows/test-r4-b4.yml` runs offline hostile Python tests and checks/patches *actual* pinned TI and herdsman source in disposable checkouts. `test-r4-b4-native.yml` attempts two independent CCS 12.8/Clang 3.2.2 full native links and B0 artifacts+board checks; if toolchain or artifacts missing, **fails closed**. `test-r4-b4-host.yml` attempts real herdsman 10.9.1 Node/TypeScript compile and tests. **Workflow presence or queued run does not equal PASS.** See `docs/r4/b4/ACCEPTANCE_RECEIPT.md`.

## Restrictions

Do not run on an HA device, active coordinator, live Z2M process, EMQX, or actual USB/UART. Do not flash, restart, alter Zigbee NV/security, open another serial port, build a persistent service or merge without explicit independent review. B1 hold, B2 route and B3 protected state remain externally owned; combined B5/R4-07 gates are separate.

The native experimental ABI is incomplete relative to issue #98: no verified minor version, source digest, trusted radio epoch, reset status, or verified UART TX_FINISHED; the source hook matrix records those as UNKNOWN. It must not be advertised as the full diagnostics feature.

## Code-review follow-up: host-only opt-in F0 quarantine

Direct self-review found that the v3 F0 reply has no request correlation ID, so a timed-out request followed by a delayed SRSP can impersonate a fresh sample. The pinned host overlay now quarantines **only the diagnostic command** after ambiguous errors and never automatically retries it; stock ZNP commands remain usable. It also checks both ZNP mutex idleness **and** the actual pending/timed-out Waitress registry, protects a synchronous writer-error waiter, rejects nonzero invalid counter slots and nonadvancing sequences. Full review: `docs/r4/b4/CODE_REVIEW_2026-10-17.md`; compiled Node success [39003959612](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39003959612). No production access or deployment occurred.

## New source-backed queue-pressure counters (staged, native verification pending)

The actual pinned TI NPI source has two synchronous and two asynchronous TX `Queue_enqueue` producers, and one consumer of each queue in `NPITask_ProcessSyncTXQ` and `NPITask_ProcessTXQ`. The updated guarded native overlay measures depths and high-water in **existing critical sections**, without extra Queue API calls, scheduler changes, NV writes, transmission probes, or independent UART ownership. Disabled `NPI_SREQRSP` builds mark synchronous fields invalid and serialize zero; host validation accepts exactly `0x1F` or `0x0C`, rejects invalid slots and depths exceeding recorded HWM. This measures **NPI TX queued records**, not UART FIFO occupancy, true TX_FINISHED, USB receipt, MAC confirmation or radio root cause. Firmware compiled images and live load/stack safety still require new receipts; earlier B0 +156B FLASH/+8B RAM budget belongs to previous one-counter image only.

## SRSP-in-general-queue correction, not NPI transport migration
The stock pinned P7U projectspec does **not** define `NPI_SREQRSP`, so the old generated native ELF showed validity `0x0C`; sync counters were symbols without running producers. Do not equate native symbol linkage with executable telemetry. Updated experimental source leaves all original TI compilation options and network processing intact and identifies SRSP framed command type (`MT_RPC_CMD_SRSP`) in the existing general NPI queue, adding logical SRSP pending/HWM and enqueue observations beside general-queue depth/HWM. On this stock build general TX includes SRSP; it is not an exclusive asynchronous-only queue. No synchronously prioritized queue/watchdog activation is merged. New native artifact proof pending; no build/flash or live coordinator access.
