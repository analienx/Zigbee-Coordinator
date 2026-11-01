# slzb-06p7u — SMLIGHT SLZB-06P7U (primary engineering target)

**Current state (1 November 2026):** V54 firmware is installed on the production coordinator, with the official Zigbee2MQTT app as the only serial owner. V54 is V53, which fixed the NV read storm behind the hangs, plus guards on that NV read cache. See the [status summary](STATUS_2026-11-01.md) for the install, review follow-ups and open items, the [official-owner delivery guide](OFFICIAL_OWNER_DELIVERY.md) for how to flash, and the [V53 long-term reliability review](REVIEW_V53_2026-10-31.md) for findings.

**Source of record (on `main`, latest version only):** `main` holds the V54 source and the official-owner delivery tooling. V53 stays retrievable through the PR #195/#196 refs and the tags below. A native rebuild embeds the build commit prefix in the evidence digest, so to reproduce an installed image byte for byte, build at its exact source commit.

| What | Where |
|---|---|
| Installed firmware source | V54 `20a2474a67c1` (native run 41284426604) |
| Delivery that installed it | official-owner runner [`tools/p7u_official_delivery.py`](../../tools/p7u_official_delivery.py), [guide](OFFICIAL_OWNER_DELIVERY.md) |
| Previous firmware | V53 `8ec1439786e3` (PR #195; tag `p7u-v53-firmware-source`), delivered by `ed42122d8149` (PR #196; tag `p7u-v53-delivery`) |
| Composition order of the image | [`tools/r4_b0_b4_composite_stage.py`](../../tools/r4_b0_b4_composite_stage.py), applied to TI SDK `3615ad5d` (`lpf2-8.33.00.16`) |
| V50–V54 Stack service, evidence, NV read cache and cache guard | [`tools/r4_v50_stack_service.py`](../../tools/r4_v50_stack_service.py) |
| V52 OSAL timers | [`tools/r4_v52_osal_timers.py`](../../tools/r4_v52_osal_timers.py) |
| B1 NV/management safety | [`firmware/slzb-06p7u/r4/b1/`](../../firmware/slzb-06p7u/r4/b1/) |
| Firmware tree overview | [`firmware/slzb-06p7u/r4/README.md`](../../firmware/slzb-06p7u/r4/README.md) |
| Composed C, reproduced locally | [`tools/p7u_compose_source_locally.sh`](../../tools/p7u_compose_source_locally.sh) |
| Flash driver and HA operator | [`tools/p7u_ha_flash_driver.py`](../../tools/p7u_ha_flash_driver.py), [`host/flash/`](../../host/flash/) |
| HA auto-recovery and SLZB Ethernet watchdog | [`ha/`](ha/), [`slzb/`](slzb/) |
| Retired custom host apps | [`host/r4-b4/`](../../host/r4-b4/), uninstalled on 31 Oct and kept as source of record |

Being on `main` is **not** qualification. The acceptance gates below still apply to V53, V54 and any later image.

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

**Host change (31 October 2026):** production runs the official Zigbee2MQTT app. Since 1 November the runbook's hang-evidence step works with it: `tools/p7u_official_delivery.py hang --stop-z2m` (review F1). Read the note at the top of the runbook before using it.

## Current work: R4, not the older P7 R2/R3 line

**Effective 25 October 2026: [Firmware-first priority policy](FIRMWARE_FIRST_POLICY.md).** Investigate and fix loss of local ZNP responses; do not divert the primary engineering effort into restoring old firmware. Verified restoration is a contingency for preserving the network, not a permanent correction. A recent R4 candidate and the prior restored image both showed startup-response loss; investigate shared transport and host state as well as source defects. Preserve every existing physical-change and retained-security gate.

- [R4 master issue #85](https://github.com/analienx/Zigbee-Coordinator/issues/85): redesigned stock-derived CC2652P7 ZNP, network/security preservation and qualification.
- [R4-00 draft PR #86](https://github.com/analienx/Zigbee-Coordinator/pull/86): provenance and parity audit, **not an accepted source-equivalence proof**.
- [R4-01a issue #87](https://github.com/analienx/Zigbee-Coordinator/issues/87) and [draft PR #88](https://github.com/analienx/Zigbee-Coordinator/pull/88): diagnostic-first contracts.
- [R4-B0 issue #90](https://github.com/analienx/Zigbee-Coordinator/issues/90): native source build evidence, **not hardware approval**; preserve its branch and native build record.
- [R4-B1 issue #92](https://github.com/analienx/Zigbee-Coordinator/issues/92) and [draft PR #93](https://github.com/analienx/Zigbee-Coordinator/pull/93): fail-closed NV with observable management path; explicitly partial and **DO NOT FLASH**.
- Implementation: `firmware/slzb-06p7u/r4/` and the `tools/r4_*.py` stages, on `main` since 31 October 2026 as the latest version only. The draft PRs listed above are historical.

The responding vendor firmware **20260310** is a behavioral/rollback reference only. Its source equivalence is unproven and it also exhibited loss of ZNP responsiveness under dense-mesh load. Do not label it a proven stable R4 donor.

## Non-negotiable acceptance gates

1. Protect active Z2M, radio serial ownership, and live Zigbee network; never assume permission to flash, reset, enter BSL, erase NVM, pair or migrate.
2. Preserve coordinator IEEE, PAN/extPAN, channel, network and link keys, TCLK/key tables, monotonically safe frame counters, CCFG and recoverable NV data.
3. Require exact source/toolchain/native-CI artifact/hosted workflow provenance, tests and independent review; **synthetic green or successful native compilation is not physical qualification**.
4. Validate target CC2652P7 board-specific RF, boot/CCFG, NVS and UART behavior separately; R4 must not silently form a new network on failed restore.
5. Qualify physical firmware deployment and rollback explicitly and independently before any production change.

Older P7/P7U R2/R3 branches are historical evidence, not the R4 source baseline. The finalized MR4U/P10 work is a separately preserved fallback/reference, not a reason to redirect the primary implementation away from P7U.

See [registry](../../docs/COORDINATOR_REGISTRY.md), [root README](../../README.md), and [documentation index](../../docs/README.md).
