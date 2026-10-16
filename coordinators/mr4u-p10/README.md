# mr4u-p10 — SMLIGHT SLZB-MR4U / CC2674P10

## Identity

- Product: SMLIGHT SLZB-MR4U
- Zigbee radio: TI CC2674P10
- Stack/protocol: Z-Stack / ZNP
- Repository coordinator ID: `mr4u-p10`

**Current repo role (16 October 2026): preserved finalized P10 reference/fallback and historical reliability/recovery evidence.** The primary engineering target has moved to [SLZB-06P7U / CC2652P7 R4](../slzb-06p7u/README.md). This status does not assert which coordinator is currently powered or that R4 has production flash approval.

## Retained finalized P10 and historical work

- SMLIGHT 2024 P10 baseline / rollback testing.
- Existing-network restore and startup recovery.
- Coordinator-wide SRSP/ZNP hang investigation.
- TI reference CC2674P10 ZNP control experiment planning.

The historical planning branch `plan/cc2674p10-ti-znp-control` was retired during the 16 October branch cleanup. Its original ref/history is preserved in the verified pre-cleanup Git bundle; do not cite the retired branch as the active planning branch.

## Existing stable namespaces

The following older paths are intentionally retained because scripts/tests/docs already depend on them:

- `deploy/p10_*.py`
- `tests/test_p10_*.py`
- `docs/P10_*.md`
- `skills/p10-zstack-restore-recovery/`

Here, `p10` means the CC2674P10/Z-Stack target family. It does **not** mean all repository content belongs to this coordinator.

## Important MR4U distinction

The MR4U is dual-radio hardware. Do not use "Radio 1" or "Radio 2" as durable identity. Select the Zigbee radio by:

- chip: CC2674P10;
- protocol: ZNP/Z-Stack;
- verified firmware;
- verified USB endpoint.

The EFR32MG26 radio is a separate role and must not be selected by P10 tooling.

## Recovery-specific rule

For the validated failure where a coordinator backup restore succeeds but the P10 hangs at the final `ZDO_STARTUP_FROM_APP` transition, use:

[`skills/p10-zstack-restore-recovery/SKILL.md`](../../skills/p10-zstack-restore-recovery/SKILL.md)

The reviewed recovery resumes the already restored network; it must not silently reform it.
