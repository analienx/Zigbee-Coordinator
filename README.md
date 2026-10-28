# Zigbee Coordinator

> **Current operational override (2026-10-20):** Active hardware for the R4 flash work is the **one SMLIGHT SLZB-06P7U R1.73 / CC2652P7**, currently restored to stock in **Ethernet mode**; its USB cable terminates at **Home Assistant**, *not* at the Windows Zephyrus. Keep Ethernet for remote BSL flash/readback (only with the guarded network transport) and switch to HA USB only after verified R4 boot. **GitHub Actions builds/tests first, native Windows only for direct hardware operations, never WSL.** Start with the [P7U transport and flash quickstart](firmware/slzb-06p7u/r4/release/P7U_TRANSPORT_AND_FLASH_QUICKSTART.md). The MR4U/P10 "current" statements below are historical and **do not describe the active Oct 2026 P7U task**.

Shared firmware, migration, recovery, diagnostics and acceptance tooling for the Zigbee coordinators used by this Home Assistant / Zigbee2MQTT installation.

This repository is intentionally **hardware-neutral at the top level**. Coordinator-specific work must identify the physical coordinator, radio silicon and host adapter stack explicitly.

## Coordinator registry

| Coordinator ID | Hardware | Zigbee radio / stack | Role |
|---|---|---|---|
| `slzb-06p7u` | SMLIGHT SLZB-06P7U | TI CC2652P7 / Z-Stack ZNP | **Primary development/reliability target: R4 (not production-qualified)** |
| `mr4u-p10` | SMLIGHT SLZB-MR4U | TI CC2674P10 / Z-Stack | Preserved finalized P10 reference/fallback and historical diagnosis |
| `sonoff-mg24` | SONOFF Dongle Max / Dongle-M | Silicon Labs EFR32MG24 / Ember | Previous production coordinator, rollback/reference platform and historical firmware experiments |
| `slzb-06p7` | SMLIGHT SLZB-06P7 | TI P7-class / Z-Stack | Legacy historical entry; do not conflate with the SLZB-06P7U R4 board |
| `mr4u-mg26` | SMLIGHT SLZB-MR4U secondary radio | Silicon Labs EFR32MG26 | **Not the current Zigbee coordinator target**; keep separate from the P10 Zigbee work |

See [`coordinators/README.md`](coordinators/README.md) and [`docs/COORDINATOR_REGISTRY.md`](docs/COORDINATOR_REGISTRY.md) for the canonical naming and status map.

## First response to a confirmed P7U hard hang

**Priority #1 operational restoration:** [guarded TI ROM/BSL round-trip → unchanged existing R4 APP → one Zigbee2MQTT start → fresh device-MQTT verification](coordinators/slzb-06p7u/HANG_RECOVERY_RUNBOOK.md). This physically **restored the sole SLZB-06P7U on 27 October 2026**, without a power cycle, reflash, NV/security replay or re-pairing, after both normal Zigbee-only and ESP-only restarts failed. [Dedicated operator/agent skill](skills/p7u-rom-bsl-recovery/SKILL.md).

**Distinguish priorities:** restore interrupted household service first via the proven, single-owner, one-shot method; continue **firmware-first source diagnosis/fix** separately. Recovery does not prove or close the defect. Never perform BSL while Z2M owns the radio, automatically replay consumed intents or use an unverified SMLIGHT control command.

## Current focus — P7U / R4

**Current engineering priority (25 October 2026): repair and prove the R4 firmware/ZNP command-handling failure, not repeat stock restoration.** Root cause, source repair, exact-SHA native qualification and physical acceptance come before recovery work; restoration is a last-resort network-safety fallback and never closes a firmware incident. The firmware and previous image have both shown post-startup loss of replies, so distinguish firmware, ESP/USB and host causes instead of assuming a single image is responsible. See the [P7U firmware-first policy](coordinators/slzb-06p7u/FIRMWARE_FIRST_POLICY.md). This priority shift grants no new authorization to reset, flash, alter NV or pair devices.

**Primary engineering target as of 16 October 2026: `slzb-06p7u` (SMLIGHT SLZB-06P7U, CC2652P7).** The P7U R4 design aims at an observable, network-safe ZNP with dense-mesh reliability; it is **not yet approved for physical production flashing**.

- [R4 master plan #85](https://github.com/analienx/Zigbee-Coordinator/issues/85) and [R4-00 provenance draft #86](https://github.com/analienx/Zigbee-Coordinator/pull/86).
- [R4-01a diagnostics #87](https://github.com/analienx/Zigbee-Coordinator/issues/87), [R4-B0 native build #90](https://github.com/analienx/Zigbee-Coordinator/issues/90), [R4-B1 NV safety #92](https://github.com/analienx/Zigbee-Coordinator/issues/92) and [draft PR #93](https://github.com/analienx/Zigbee-Coordinator/pull/93).
- Active R4 work is on isolated `feat/p7u-r4-*`, `feat/r4-*`, and `review/p7u-r4-*` branches, not automatically deployed by `main`.
- Vendor P7U ZNP `20260310` is a behavior/rollback reference, **not** proven source-equivalent or stable in a 100+-device mesh. Native CCS build success is not a physical acceptance.
- Preserve the original coordinator identity, NV/security/counters, rollback evidence, and exactly one serial owner; no live firmware/recovery operation follows from these documentation updates.

The **finalized MR4U/P10 work remains retained** as a separate reference and potential recovery path, but it is no longer the primary active engineering direction. Historic P10 and SONOFF P009/P013/P015 docs are retained for traceability, not current-work priorities.

See [P7U coordinator overview](coordinators/slzb-06p7u/README.md) and [coordinator registry](docs/COORDINATOR_REGISTRY.md).

## Repository layout

### P7U/R4 development (unmerged work)

- `firmware/slzb-06p7u/r4/` — R4 source/design/CI on preserved feature branches; refer to the R4 issue and PR chain for current status.
- `coordinators/slzb-06p7u/` — primary target identity and safety gates.

### Retained P10 compatibility paths

- `deploy/p10_*.py` — existing **MR4U / CC2674P10** migration, restore, evidence and cutover tooling.
- `tests/test_p10_*.py` — tests for the same MR4U/P10 tooling.
- `docs/P10_*.md` — MR4U/P10 migration and recovery documentation.
- `skills/p10-zstack-restore-recovery/` — P10/Z-Stack restored-network recovery specialization.
- `docs/ISSUE-7-ARCHITECTURE-REVIEW.md` — historical **SONOFF MG24 / P009** architecture review.

The `p10_*` paths are retained for backward compatibility. **They mean CC2674P10/P10, primarily the MR4U Zigbee radio; they do not mean the repository is P10-only.**

### Coordinator metadata

New coordinator-specific documentation belongs under:

`coordinators/<coordinator-id>/`

New implementation work should use explicit coordinator names where practical rather than introducing more ambiguous chip-only prefixes.

## Naming rules

Use these terms consistently:

- **`mr4u-p10`** — the MR4U CC2674P10 Zigbee coordinator.
- **`sonoff-mg24`** — the SONOFF EFR32MG24 Ember coordinator.
- **`slzb-06p7u`** — active SMLIGHT CC2652P7 R4 development target (distinguish from legacy `slzb-06p7`).
- **`slzb-06p7`** — legacy SMLIGHT coordinator entry, not interchangeable with the P7U R4 board.
- **P009 / P013 / P015** — SONOFF MG24 firmware experiment generations.
- **20240705 / 20260310 / similar** — P10 ZNP build/revision identifiers, not hardware names.
- Avoid **Radio 1 / Radio 2** as identity. MR4U numbering has been a source of confusion; identify a radio by chip and protocol.
- Avoid saying only **P10** when a distinction between MR4U, 06P10/06P10U or another CC2674P10 board matters.

## Safety invariants

Across all coordinators:

- Never clear NVM or factory-reset a production coordinator as a diagnostic shortcut.
- Preserve coordinator IEEE, PAN ID, extended PAN ID, channel, network key and security state during same-network recovery/migration.
- Keep a fresh, verified coordinator/Zigbee2MQTT recovery point before destructive firmware work.
- Never power two active coordinators carrying the same copied network identity.
- Exactly one Zigbee2MQTT/ZHA owner may control a coordinator serial endpoint.
- Do not re-pair devices merely to hide an unresolved coordinator restore or startup fault.
- Hash and identify every firmware image before flashing.
- Keep rollback hardware/image/state independently recoverable.

## Home Assistant access

For live Home Assistant diagnostics, Zigbee2MQTT inventory, NWK/address mapping or route-error investigation, use the canonical [Home Assistant read-only skill](https://github.com/analienx/config/blob/main/skills/home-assistant-readonly/SKILL.md) from `analienx/config`.

Do not copy credentials or HA connection helpers into this repository.

## Retained MR4U P10 migration / recovery (not primary)

For an existing-network USB replacement or P10 recovery, start with:

1. [P10 USB cutover quickstart](docs/P10_USB_CUTOVER_QUICKSTART.md)
2. [full Python migration workflow](docs/P10_PYTHON_MIGRATION_WORKFLOW.md)
3. [P10 Z-Stack restore recovery skill](skills/p10-zstack-restore-recovery/SKILL.md)

For the validated failure class where restore succeeds but the P10 hangs at `ZDO_STARTUP_FROM_APP`, preserve the restored state and use the reviewed BDB restored-network resume path rather than reforming the network.

## Historical SONOFF MG24 work

The SONOFF EFR32MG24 line remains valuable as:

- previous production evidence;
- rollback/reference hardware;
- P009/P013/P015 firmware experiments;
- Ember-vs-Z-Stack comparison evidence.

Retained historical branches keep their original names. Obsolete local and remote branches may be pruned only after identifying protected R4 dependencies, open PR heads/bases, worktrees, unmerged changes and the finalized P10 reference; do not erase unmerged history without an immutable recovery ref.
