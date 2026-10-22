# Zigbee Coordinator

> **Current operational override (2026-10-20):** Active hardware for the R4 flash work is the **one SMLIGHT SLZB-06P7U R1.73 / CC2652P7**, currently restored to stock in **Ethernet mode**; its USB cable terminates at **Home Assistant**, *not* at the Windows Zephyrus. Keep Ethernet for remote BSL flash/readback (only with the guarded network transport) and switch to HA USB only after verified R4 boot. **GitHub Actions builds/tests first, native Windows only for direct hardware operations, never WSL.** Start with the [P7U transport and flash quickstart](firmware/slzb-06p7u/r4/release/P7U_TRANSPORT_AND_FLASH_QUICKSTART.md). The MR4U/P10 "current" statements below are historical and **do not describe the active Oct 2026 P7U task**.

Shared firmware, migration, recovery, diagnostics and acceptance tooling for the Zigbee coordinators used by this Home Assistant / Zigbee2MQTT installation.

This repository is intentionally **hardware-neutral at the top level**. Coordinator-specific work must identify the physical coordinator, radio silicon and host adapter stack explicitly.

## Coordinator registry

| Coordinator ID | Hardware | Zigbee radio / stack | Role |
|---|---|---|---|
| `mr4u-p10` | SMLIGHT SLZB-MR4U | TI CC2674P10 / Z-Stack | **Current primary coordinator and active investigation target** |
| `sonoff-mg24` | SONOFF Dongle Max / Dongle-M | Silicon Labs EFR32MG24 / Ember | Previous production coordinator, rollback/reference platform and historical firmware experiments |
| `slzb-06p7` | SMLIGHT SLZB-06P7 | TI P7-class / Z-Stack | Historical predecessor / recovery reference |
| `mr4u-mg26` | SMLIGHT SLZB-MR4U secondary radio | Silicon Labs EFR32MG26 | **Not the current Zigbee coordinator target**; keep separate from the P10 Zigbee work |

See [`coordinators/README.md`](coordinators/README.md) and [`docs/COORDINATOR_REGISTRY.md`](docs/COORDINATOR_REGISTRY.md) for the canonical naming and status map.

## Current focus

The active coordinator investigation is **`mr4u-p10`**.

Current work includes:

- SMLIGHT 2024 P10 baseline / rollback testing;
- recovery of the existing Z-Stack network without re-forming it;
- failure analysis for coordinator-wide SRSP degradation / terminal ZNP hangs;
- the planned TI CC2674P10 reference-ZNP A/B control experiment.

The TI planning work lives on branch:

`plan/mr4u-p10-ti-znp-control`

The older P009/P013/P015 work belongs to **`sonoff-mg24`**. Those labels are firmware experiment identifiers, **not coordinator models**.

## Repository layout

### Current stable paths

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
- **`slzb-06p7`** — the older SMLIGHT Z-Stack coordinator.
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

## MR4U P10 migration / recovery

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

Historical branches keep their original names for traceability. They should not be renamed merely for cosmetic consistency.
