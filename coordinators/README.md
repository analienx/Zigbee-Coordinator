# Coordinators

Each coordinator has its own identity, stack and operational history.

Current registry:

- [SMLIGHT SLZB-06P7U / CC2652P7](slzb-06p7u/README.md) — **production coordinator, R4 V54 since 1 Nov 2026** (installed, not yet qualified) and primary firmware engineering/reliability target.
- [MR4U / CC2674P10](mr4u-p10/README.md) — **retained finalized P10 reference/fallback**; do not discard the validated P10 lineage.
- [SONOFF / EFR32MG24](sonoff-mg24/README.md) — previous production coordinator and P009/P013/P015 firmware history.
- [SMLIGHT SLZB-06P7](slzb-06p7/README.md) — legacy coordinator ID; **do not conflate** with the active 06P7U R4 board.

The MR4U EFR32MG26 radio is intentionally not represented as a primary Zigbee coordinator here; in the current installation it is separate from the P10 Zigbee role. Identify it by chip/protocol, never only by "Radio 1/2".

See [Coordinator Registry](../docs/COORDINATOR_REGISTRY.md) for naming rules and branch conventions.
