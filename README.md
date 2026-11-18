# Zigbee Coordinator — R4 firmware for the SMLIGHT SLZB-06P7U

**A stable Z-Stack ZNP for dense Zigbee networks.** R4 is TI Z-Stack (SimpleLink SDK 8.33) rebuilt for the SLZB-06P7U / CC2652P7. It fixes the defects that made the coordinator stop answering Zigbee2MQTT on a 100+ device mesh, and it can show you its own health while it runs. It runs in production on a 106-device network (57 routers) under the official Zigbee2MQTT app.

> **Status, 18 November 2026: R4 V58 is stable.** No coordinator hang and no SRSP timeout since 13 Nov. Five nightly cold starts in a row connected on the first attempt. 65 of 65 route discoveries succeeded. [Field evidence](coordinators/slzb-06p7u/STATUS_2026-11-18.md) · [Release notes](coordinators/slzb-06p7u/RELEASE_NOTES.md)

## What R4 fixes

| Problem on a dense mesh | Stock / TI reference behaviour | R4 | Result in production |
|---|---|---|---|
| **Coordinator stops answering** (AF/ZDO/SYS SRSP timeouts, Zigbee2MQTT restarts) | The active network key is read from NV on **every secured frame**: a ~10 ms linear flash search. The Stack task saturates and starves the host link. | RAM read cache in front of NV, invalidated by every write (V53/V54) | NV time 304 s → 0.9 s per 10 min; 99.5–99.9 % cache hits; **no runtime hang since 31 Oct** |
| **Cold start fails** (`SYS ping after 6000ms`, 10 min to come up) | MT parser waits forever after a stray `0xFE` and accepts impossible lengths | 500 ms idle resync, length bound 250 (V57) | **5 / 5 first-attempt cold starts** (before: 4 of 11 mornings failed) |
| **Route repair refused** (`NWK_TABLE_FULL` on `extRouteDisc`) | 8-entry route-discovery table | 40 entries (V58) | **0 refusals in 65 discoveries** (before: 6 in 37.5 h) |
| **MAC queue overflow** under bursts | Queues 5 / 8 / 5 | 50 / 80 / 50 (V55) | 0 refused MAC requests in every sample |
| **Tables sized for small networks** | TI defaults | Routing 128, source routes 192, neighbors 64, address manager 406 | Room for a 100+ device mesh |
| **Silent failures** | No internal visibility | Live RAM-only health pages: scheduler, heap, timers, NV cost, parser, route discovery, UART errors | Diagnosed through the running Zigbee2MQTT, no outage |
| **Risky NV and security state** | Standard NV | Fail-closed NV with read-back verification; IEEE, PAN, keys and frame counters preserved across upgrades | Every upgrade kept the same network, no re-pairing |

SMLIGHT firmware engineers: the full root-cause analysis of the hangs, with TI source references and suggested fixes, is in [**docs/SMLIGHT_HANG_ROOT_CAUSE.md**](docs/SMLIGHT_HANG_ROOT_CAUSE.md).

## Live numbers (V58, 18 Nov 2026, 9 h after a cold start)

| | |
|---|---|
| Joined devices | 106 (57 routers, 49 end devices) |
| Stack task busy | 1.5 %, 0 saturated windows |
| OSAL heap | 89.5 KB free of 97 KB, low water 86.2 KB |
| NV | 0 failures, 99.49 % read-cache hits |
| MAC | 0 / 61,523 requests refused |
| Host link | 43,814 valid frames, 0 checksum errors |

This is one installation's field data, not a controlled benchmark against every stock build.

## How it is built and delivered

- **Reproducible source:** about 25 guarded Python stages edit a pristine TI SDK (`3615ad5d`). Each stage checks exact pre-image hashes and runs compile-and-mutate harnesses under ASan/UBSan. [`tools/p7u_compose_source_locally.sh`](tools/p7u_compose_source_locally.sh) rebuilds the full composed patch without the TI toolchain.
- **CI builds every image:** GitHub Actions builds twice, checks the two builds are byte-identical, audits the linked ELF and runs the hosted test suite (990 tests).
- **Guarded flashing:** the [delivery runner](coordinators/slzb-06p7u/OFFICIAL_OWNER_DELIVERY.md) checks the package, the serial owner and NV headroom, then compares the radio's live security state with the pre-flash capture. Anything unexpected holds the flash **before any write** and puts Zigbee back on the old firmware. The owner authorizes each flash by operation id; nothing is ever auto-retried.
- **Recovery:** a tested [ROM/BSL round trip](coordinators/slzb-06p7u/HANG_RECOVERY_RUNBOOK.md) restores a hung radio without reflashing or touching NV.

More: [R4 vs stock, layer by layer](docs/R4_VS_STOCK.md) · [P7U overview and feature matrix](coordinators/slzb-06p7u/README.md) · [Operator reliability](docs/P7U_OPERATOR_RELIABILITY.md)

## Coordinator registry

| Coordinator ID | Hardware | Zigbee radio / stack | Role |
|---|---|---|---|
| `slzb-06p7u` | SMLIGHT SLZB-06P7U | TI CC2652P7 / Z-Stack ZNP | **Production coordinator on V58 since 16 Nov 2026; stable, no hang since 13 Nov. See [field evidence](coordinators/slzb-06p7u/STATUS_2026-11-18.md).** |
| `mr4u-p10` | SMLIGHT SLZB-MR4U | TI CC2674P10 / Z-Stack | Preserved finalized P10 reference/fallback and historical diagnosis |
| `sonoff-mg24` | SONOFF Dongle Max / Dongle-M | Silicon Labs EFR32MG24 / Ember | Previous production coordinator, rollback/reference platform and historical firmware experiments |
| `slzb-06p7` | SMLIGHT SLZB-06P7 | TI P7-class / Z-Stack | Legacy historical entry; do not conflate with the SLZB-06P7U R4 board |
| `mr4u-mg26` | SMLIGHT SLZB-MR4U secondary radio | Silicon Labs EFR32MG26 | **Not the current Zigbee coordinator target**; keep separate from the P10 Zigbee work |

See [`coordinators/README.md`](coordinators/README.md) and [`docs/COORDINATOR_REGISTRY.md`](docs/COORDINATOR_REGISTRY.md) for the canonical naming and status map.

## If the coordinator hangs

Restore service first with the [ROM/BSL runbook](coordinators/slzb-06p7u/HANG_RECOVERY_RUNBOOK.md) ([agent skill](skills/p7u-rom-bsl-recovery/SKILL.md)); it restored the radio on 27 Oct 2026 without a power cycle, reflash or re-pairing. Recovery does not close a firmware defect: capture the evidence and open an issue. Never enter BSL while Zigbee2MQTT owns the serial port.

## Repository layout

### P7U/R4 firmware (installed V58 lineage)

- `coordinators/slzb-06p7u/` — identity, safety gates, [status](coordinators/slzb-06p7u/STATUS_2026-11-18.md), [release notes](coordinators/slzb-06p7u/RELEASE_NOTES.md), [review](coordinators/slzb-06p7u/REVIEW_V53_2026-10-31.md) and the hang runbook.
- `firmware/slzb-06p7u/r4/` — B0/B1 sources, qualification, release, ROM writer and fixtures. [Overview](firmware/slzb-06p7u/r4/README.md).
- `tools/r4_*.py` — the stages that turn TI SDK `3615ad5d` into the image, in the order set by `tools/r4_b0_b4_composite_stage.py`, plus their compile-and-mutate harnesses.
- `tools/p7u_ha_flash_driver.py`, `host/flash/` — single flash driver and the sealed HA operator.
- `host/r4-b4/`, `host/recovery/` — custom P7U host apps, uninstalled on 31 Oct 2026; kept as source of record.
- `docs/r4/` — R4 design contracts and per-stage engineering notes (F2 v4.2–v6, V43–V45).
- `tests/` — repository tests (`python -m pytest tests`); 990 passed, 31 skipped at the installed V58 operator; operator-specific hosted tests and physical checks are tracked separately.

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
