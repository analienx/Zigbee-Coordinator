# slzb-06p7u — SMLIGHT SLZB-06P7U (primary engineering target)

## Identity and scope

- Hardware: SMLIGHT **SLZB-06P7U**, board R1.73 per R4 evidence.
- Zigbee SoC: **Texas Instruments CC2652P7**.
- Protocol/host interface: **Z-Stack / ZNP**; board UART evidence RX DIO12, TX DIO13, 115200 baud, hardware flow control disabled.
- Repository ID: `slzb-06p7u`; short name **P7U** (sometimes called P7 in conversation).
- Current role (16 October 2026): **primary engineering and coordinator reliability target**; preserve the existing network.
- Distinct from `slzb-06p7` (legacy entry) and `mr4u-p10` (CC2674P10).

## First-line recovery when the production ZNP interface hangs

**Use the [verified P7U ROM/BSL recovery runbook](HANG_RECOVERY_RUNBOOK.md) first**, not ordinary Zigbee/ESP reset loops or a speculative reflash. On **2026-10-27**, the source-verified TI BSL entry → read-only chip ID/ROM CRC → application boot of the unchanged R4 image → one Z2M startup **physically recovered** household service with independent fresh non-retained MQTT device messages. There was no power cycle, flash, NV/CCFG write or network re-commissioning.

This is a **service-restoration** priority for a *confirmed local SRSP/ZNP hard hang*, subject to exact USB/MAC/OS source checks, sole serial ownership, private backups, fresh operator authority and durable single-shot journal. The separate firmware-first **engineering** investigation remains open; BSL success is a clue, not a proven root cause.

## Current work: R4, not the older P7 R2/R3 line

**Effective 25 October 2026: [Firmware-first priority policy](FIRMWARE_FIRST_POLICY.md).** Investigate and fix loss of local ZNP responses; do not divert the primary engineering effort into restoring old firmware. Verified restoration is a contingency for preserving the network, not a permanent correction. A recent R4 candidate and the prior restored image both showed startup-response loss; investigate shared transport and host state as well as source defects. Preserve every existing physical-change and retained-security gate.

- [R4 master issue #85](https://github.com/analienx/Zigbee-Coordinator/issues/85): redesigned stock-derived CC2652P7 ZNP, network/security preservation and qualification.
- [R4-00 draft PR #86](https://github.com/analienx/Zigbee-Coordinator/pull/86): provenance and parity audit, **not an accepted source-equivalence proof**.
- [R4-01a issue #87](https://github.com/analienx/Zigbee-Coordinator/issues/87) and [draft PR #88](https://github.com/analienx/Zigbee-Coordinator/pull/88): diagnostic-first contracts.
- [R4-B0 issue #90](https://github.com/analienx/Zigbee-Coordinator/issues/90): native source build evidence, **not hardware approval**; preserve its branch and native build record.
- [R4-B1 issue #92](https://github.com/analienx/Zigbee-Coordinator/issues/92) and [draft PR #93](https://github.com/analienx/Zigbee-Coordinator/pull/93): fail-closed NV with observable management path; explicitly partial and **DO NOT FLASH**.
- Implementation prefix on R4 branches: `firmware/slzb-06p7u/r4/`. It is not on `main` while the relevant draft PRs remain unmerged.

The responding vendor firmware **20260310** is a behavioral/rollback reference only. Its source equivalence is unproven and it also exhibited loss of ZNP responsiveness under dense-mesh load. Do not label it a proven stable R4 donor.

## Non-negotiable acceptance gates

1. Protect active Z2M, radio serial ownership, and live Zigbee network; never assume permission to flash, reset, enter BSL, erase NVM, pair or migrate.
2. Preserve coordinator IEEE, PAN/extPAN, channel, network and link keys, TCLK/key tables, monotonically safe frame counters, CCFG and recoverable NV data.
3. Require exact source/toolchain/native-CI artifact/hosted workflow provenance, tests and independent review; **synthetic green or successful native compilation is not physical qualification**.
4. Validate target CC2652P7 board-specific RF, boot/CCFG, NVS and UART behavior separately; R4 must not silently form a new network on failed restore.
5. Qualify physical firmware deployment and rollback explicitly and independently before any production change.

Older P7/P7U R2/R3 branches are historical evidence, not the R4 source baseline. The finalized MR4U/P10 work is a separately preserved fallback/reference, not a reason to redirect the primary implementation away from P7U.

See [registry](../../docs/COORDINATOR_REGISTRY.md), [root README](../../README.md), and [documentation index](../../docs/README.md).
