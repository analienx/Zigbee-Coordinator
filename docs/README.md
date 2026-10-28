# Documentation Index

Repository-level documentation is organized by **coordinator scope**, even where older filenames are retained for compatibility.

## Shared

- [Coordinator Registry](COORDINATOR_REGISTRY.md) — canonical hardware/stack/naming map.
- Root [README](../README.md) — repository purpose, safety invariants and current focus.
- [16 October 2026 branch-prune audit](BRANCH_PRUNE_AUDIT_2026-10-16.md) — verified pre-cleanup recovery bundle, deleted branches and retained R4/finalized P10 dependency refs.

## Production service recovery: P7U hard hangs (start here)

- **[Priority #1: SLZB-06P7U ROM/BSL-to-existing-APP recovery runbook](../coordinators/slzb-06p7u/HANG_RECOVERY_RUNBOOK.md)** — source-pinned, one-shot, no-power-cycle/no-flash procedure that **restored the production network on 27 Oct 2026**.
- [P7U agent recovery skill](../skills/p7u-rom-bsl-recovery/SKILL.md) — how future agents choose this path, preserve counters and confirm real device traffic.
- [Physical recovery evidence #143](https://github.com/analienx/Zigbee-Coordinator/issues/143#issuecomment-6438517051) and [root-cause F2 follow-up #144](https://github.com/analienx/Zigbee-Coordinator/issues/144).

## slzb-06p7u — PRIMARY P7U / CC2652P7 / R4

- [P7U identity, R4 development and safety gates](../coordinators/slzb-06p7u/README.md)
- [R4 master design #85](https://github.com/analienx/Zigbee-Coordinator/issues/85), [R4 provenance PR #86](https://github.com/analienx/Zigbee-Coordinator/pull/86), [diagnostics #87](https://github.com/analienx/Zigbee-Coordinator/issues/87), [native B0 #90](https://github.com/analienx/Zigbee-Coordinator/issues/90), [NV safety B1 #92](https://github.com/analienx/Zigbee-Coordinator/issues/92)
- Implementation lives under `firmware/slzb-06p7u/r4/` **on draft feature branches**. It is not yet accepted/merged into `main` or physically production-qualified.

## mr4u-p10 — RETAINED FINALIZED REFERENCE / CC2674P10 / Z-Stack

Migration / restore / cutover:

- [P10 USB cutover quickstart](P10_USB_CUTOVER_QUICKSTART.md)
- [P10 Python migration workflow](P10_PYTHON_MIGRATION_WORKFLOW.md)
- [P10 upstream cutover runbook](P10_UPSTREAM_CUTOVER_RUNBOOK.md)
- [P10 cutover preparation](P10_CUTOVER_PREPARATION.md)
- [P10 migration backup](P10_MIGRATION_BACKUP.md)

Preflight / firmware evidence:

- [P10 preflight](P10_PREFLIGHT.md)
- [P10 firmware candidate manifest](p10_firmware_candidates.json)

Recovery specialization:

- [P10 Z-Stack restore recovery skill](../skills/p10-zstack-restore-recovery/SKILL.md)

The historical planning branch `plan/mr4u-p10-ti-znp-control` was retired on 16 October 2026. Its ref history is in the verified pre-cleanup bundle; the finalized P10 recovery/reference line remains preserved.

## sonoff-mg24 — SONOFF Dongle Max / EFR32MG24 / Ember

- [Historical Issue #7 architecture review](ISSUE-7-ARCHITECTURE-REVIEW.md)

P009/P013/P015 implementation history primarily lives on historical branches rather than current main.

## slzb-06p7 — legacy coordinator ID (not the P7U R4 board)

No active implementation docs for this **legacy ID** are on main; the **current P7U R4** implementation exists on separate unmerged branches.

See [`coordinators/slzb-06p7/README.md`](../coordinators/slzb-06p7/README.md) for scope and future naming guidance.

## Compatibility note

The existing `P10_*` documentation names and `p10_*` Python/test paths are intentionally retained to preserve the finalized P10 evidence and avoid breaking working tooling and cross-references.

New work should prefer explicit coordinator IDs in branch names and new top-level artifact names.
