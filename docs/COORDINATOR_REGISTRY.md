# Coordinator Registry

This file is the canonical repository-level map of coordinator hardware, radio silicon, host stack and experiment naming.

## Coordinator IDs

### `slzb-06p7u` — PRIMARY R4 ENGINEERING TARGET

- Hardware: SMLIGHT SLZB-06P7U (board R1.73 per current R4 evidence).
- Zigbee chip: TI CC2652P7; stack: Z-Stack / ZNP.
- Verified board-contract evidence used for current source work: UART RX DIO12, TX DIO13, 115200 baud, hardware flow control off. Board-specific RF, CCFG, boot and NV equivalence still require independent physical qualification.
- **Current engineering role as of 16 October 2026: primary firmware/reliability development target, R4.** This statement is not proof of live healthy state or release authorization.
- **Production state (31 October 2026): R4 V53 installed, USB to Home Assistant, official Zigbee2MQTT app as host; not yet qualified.** See [status](../coordinators/slzb-06p7u/STATUS_2026-10-31.md) and [review](../coordinators/slzb-06p7u/REVIEW_V53_2026-10-31.md).
- Vendor `20260310` is a known-booting and previously responsive behavioral/rollback reference, **not a proven stable dense-mesh release or source-equivalent donor**.
- Source on `main` since 31 October 2026, latest version only: `firmware/slzb-06p7u/r4/` and `tools/r4_*.py`. The installed image's exact commit is `8ec1439` (PR #195) and its delivery `ed42122` (PR #196). Coordinator README: `coordinators/slzb-06p7u/README.md`.
- R4 tracking: [master #85](https://github.com/analienx/Zigbee-Coordinator/issues/85), [R4-00 #86](https://github.com/analienx/Zigbee-Coordinator/pull/86), [diagnostics #87](https://github.com/analienx/Zigbee-Coordinator/issues/87), [native B0 #90](https://github.com/analienx/Zigbee-Coordinator/issues/90), [NV-safe B1 #92](https://github.com/analienx/Zigbee-Coordinator/issues/92), [B1 draft #93](https://github.com/analienx/Zigbee-Coordinator/pull/93).
- Source-only work and independent review proceed separately from explicit flash, live network restore and production qualification. Do not change live HA/Z2M, serial owner, coordinator image, NVM or security counters as part of repo cleanup.

### `mr4u-p10` — FINALIZED REFERENCE / FALLBACK (RETAIN)

- Hardware: SMLIGHT SLZB-MR4U.
- Zigbee radio: TI CC2674P10; stack: Z-Stack / ZNP.
- Role: preserve finalized P10 evidence, migration/restore tooling and diagnostics as a separate recovery/reference line, **not the primary current R4 engineering target**.
- Keep finalized P10 artifacts/refs and tested rollback/recovery instructions intact.
- Existing compatibility namespace (do not rename during branch cleanup):
  - `deploy/p10_*.py`
  - `tests/test_p10_*.py`
  - `docs/P10_*.md`
  - `skills/p10-zstack-restore-recovery/`
- Historical TI planning branches were retired during the 16 October 2026 cleanup. Their ref history is in the verified pre-cleanup Git bundle; they are not current branch targets.

The `P10` identifier describes the TI CC2674P10 family, not all SMLIGHT coordinators; `P7U` is not the same chipset or firmware target.

### `sonoff-mg24`

- Hardware: SONOFF Dongle Max / Dongle-M.
- Zigbee radio: Silicon Labs EFR32MG24.
- Host stack: Ember / EZSP.
- Current role: previous production coordinator, rollback/reference platform, historical firmware research.
- Historical experiment generations:
  - P009
  - P013
  - P015
  - R60-related feasibility/baseline work
- Representative branches:
  - `p009-debug-capture-20260909`
  - `p009-hardening`
  - `p009-mg24-broadcast-headroom`
  - `p009-staging`
  - `assistant/p009b-build-recovery-20260930`
  - `assistant/p013-concentrator-ab-20260916`
  - `assistant/p013-route-health-20260912`
  - `assistant/p015-bidirectional-rf-shaping-20260917`
  - `assistant/mg24-emergency-fallback-20260930`

P009/P013/P015 are firmware experiment labels. They are not coordinator hardware names and must not be used to refer to MR4U/P10 work.

### `slzb-06p7` — LEGACY ID

- Historical predecessor/reference entry; distinct from the **active `slzb-06p7u` CC2652P7** R4 target.
- Never infer a P7U board pinout, CCFG layout, RF/PA, NV region or flash recipe solely from a legacy `slzb-06p7` entry.
- Preserve provenance when classifying old evidence; promote only after a hardware identity check.

### `mr4u-mg26`

- Hardware: the MR4U secondary EFR32MG26 radio.
- Current role in this installation: separate from the P10 Zigbee coordinator work; primarily reserved for Thread/secondary-radio use and experiments.
- It must not be selected accidentally by P10/ZNP tooling.

Do not identify MR4U radios by only "Radio 1" or "Radio 2". Use chip + protocol.

## Experiment ID rules

The repository contains three kinds of identifiers that must not be mixed:

| Identifier type | Examples | Meaning |
|---|---|---|
| Coordinator ID | `slzb-06p7u`, `mr4u-p10`, `sonoff-mg24` | Physical coordinator + radio family |
| Firmware experiment ID | P009, P013, P015 | A specific experimental firmware/config generation |
| Vendor/build revision | 20240705, 20260310 | A firmware build/revision identifier |

When writing a new issue, branch, report or artifact, include the coordinator ID first.

Preferred examples:

```
slzb-06p7u / R4-B0 (native source build only)
slzb-06p7u / R4-B1 (draft, do not flash)
mr4u-p10 / FINALIZED-REFERENCE
mr4u-p10 / SMLIGHT-2024
sonoff-mg24 / P009
sonoff-mg24 / P015
```

Avoid:

```
P10 issue
P009 coordinator
Radio 1 problem
new dongle
```

when the specific hardware matters.

## Branch naming going forward

Preferred:

```
<type>/<coordinator-id>-<topic>
```

Examples:

```
feat/p7u-r4-stock-derived-redesign
feat/p7u-r4-b0-native-issue90
feat/r4-b1-direct-nv-safety-20261016
feat/p7u-r4-b0-native-issue90
exp/mr4u-p10-ti832-kctrl-r0
fix/mr4u-p10-znp-resource-leak
exp/sonoff-mg24-p015-rf-shaping
docs/slzb-06p7-recovery-notes
```

Existing retained branches keep their original names. Branch pruning is permitted after verifying R4 branch/PR/worktree dependencies and finalized P10 retention. Do not delete unmerged history without an independently recoverable ref, and do not delete a checked-out branch or a dependency of an open PR.

## Shared invariants

Regardless of coordinator:

1. A production network has one active coordinator identity at a time.
2. Destructive firmware work requires a fresh recovery point.
3. Network identity/security preservation and firmware flashing are separate gates.
4. Coordinator firmware version is not proof of compiled table capacity.
5. Device database state is not proof of live RF reachability.
6. A route failure on one device is not equivalent to coordinator-wide ZNP failure.
7. Do not re-pair devices as a substitute for establishing coordinator correctness.
