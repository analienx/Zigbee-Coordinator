# R4 B4 — read-only coordinator diagnosis (issue #98)

Source branch `feat/p7u-r4-b4-issue98` branches from **exact B0 `1baefbee8e4de2c9d28c5e1a7c339cf2025a2afe`**. Draft PR #100 targets sealed B0, not main or sibling B1/B2/B3. Explicit stage: **EXPERIMENTAL; NOT SOURCE_READY, NOT INSTALLED, PHYSICAL_UNVERIFIED**.

## Actual code and the trust boundary

- `b4_protocol.py`: finite offline UNPI SYS F0 framing/strict P10 v2 and proposed R4 v3 decoders. No serial access.
- `b4_native_patch.py`: **experimental** hash-guarded source patch to disposable exact-TI-SHA `/tmp` checkout. Links one O(1) static-RAM `srsp_enqueued` counter to the real NPI sync queue. Exposes 132-byte v3 with only validity bit 4, boot cap 0 and boot ID 0; never claims missing metrics.
- `b4_native_link_audit.py`: native manifest+real ELF+TI nm symbol check. Hosted linker + full B0 CCFG/NV/board tests required before native evidence.
- `b4_verify_source.py`: checks exact TI/herdsman pins, F0 collision, stock SYS Ping/Version, NPI-specific `npi_client_mt.c` and owner/Waitress.
- `host/r4-b4/herdsman_overlay.py`: separate opt-in experimental patch for pinned herdsman. The default is **no polling**, no serial sidecar. Calls the existing `ZStackAdapter.znp.requestWithReply` through Znp mutex, skip while busy/OTA, 30s cooldown.
- `../tools/r4_passive_recorder.py`: reused #87 offline forensic model; no production hook or host install.
- `b4_replay.py`: four time-labeled synthetic incident replays with observed counts where available. Unknown remains unknown.

## Verification gates

`.github/workflows/test-r4-b4.yml` runs offline hostile Python tests and checks/patches *actual* pinned TI and herdsman source in disposable checkouts. `test-r4-b4-native.yml` attempts two independent CCS 12.8/Clang 3.2.2 full native links and B0 artifacts+board checks; if toolchain or artifacts missing, **fails closed**. `test-r4-b4-host.yml` attempts real herdsman 10.9.1 Node/TypeScript compile and tests. **Workflow presence or queued run does not equal PASS.** See `docs/r4/b4/ACCEPTANCE_RECEIPT.md`.

## Restrictions

Do not run on an HA device, active coordinator, live Z2M process, EMQX, or actual USB/UART. Do not flash, restart, alter Zigbee NV/security, open another serial port, build a persistent service or merge without explicit independent review. B1 hold, B2 route and B3 protected state remain externally owned; combined B5/R4-07 gates are separate.

The native experimental ABI is incomplete relative to issue #98: no verified minor version, source digest, trusted radio epoch, reset status, or verified UART TX_FINISHED; the source hook matrix records those as UNKNOWN. It must not be advertised as the full diagnostics feature.
