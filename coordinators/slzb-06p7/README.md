# slzb-06p7 — SMLIGHT SLZB-06P7

## Identity

- Product: SMLIGHT SLZB-06P7
- Stack family: TI Z-Stack
- Repository coordinator ID: `slzb-06p7`

This is a **legacy identity** kept for historical provenance. The current P7U R4 engineering target is the distinct [SLZB-06P7U / CC2652P7](../slzb-06p7u/README.md), not this legacy entry. Verify the physical model before applying firmware or restoration instructions.

## Repository status

The repo does not yet have a normalized active implementation namespace for this coordinator. Historical assumptions, backups or procedures for the 06P7 must not be silently treated as MR4U/CC2674P10 facts.

Even though both `slzb-06p7` and `mr4u-p10` are TI Z-Stack coordinators, keep separate:

- radio generation;
- firmware build lineage;
- table sizing;
- NVS layout;
- CCFG/boot behavior;
- board-level RF/UART wiring;
- migration/recovery evidence.

If new legacy 06P7-specific work is added, use the `slzb-06p7` coordinator ID explicitly in branch and artifact names. Use `slzb-06p7u` for the current R4 branch, source files and issues.
