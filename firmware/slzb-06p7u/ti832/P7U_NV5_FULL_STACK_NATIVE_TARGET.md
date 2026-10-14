# P7U production-like large-network NV5 target — native build only

**Status: candidate, NOT FLASHABLE.** This is a missing three-way intersection gate; it does not qualify real-device NV migration or authorize network cutover.

## Motivation

Before this patch we had two green *partial combinations*:

1. `p7u-f07-stock`: actual vendor P7U CCFG + G7/F07 + stock NV2.
2. `cap192-f07`: CAP192/NV5 + G7/F07 + TI LaunchPad default CCFG.

Neither proved **P7U vendor CCFG + CAP192/NV5 + G7/F07** in one image. This matters for our high-router-count network, because linker memory, CCFG, UART queue and nonvolatile storage interact.

## Implemented third native profile

`p7u-cap192-f07` reuses the genuine pinned CCS 12.8/TI SDK 8.32 project and applies in order:

- G3 NV5 5×8KiB reservation at `0xA4000..0xAE000`, zero initialized NV;
- G4 CAP192/TC192/NWK96 SysConfig;
- G5/G6 crash diagnostics and transport;
- latest merged G7 retained UART/F11/F12 callback and fail-closed fairness;
- F07 strict raw-NV NIB commit and restoration guards;
- SMLIGHT SLZB-06P7U vendor-reference CCFG DC/DC override (`enableDCDC=false`).

The P7U vendor CCFG override originates from the same manufacturer `20240710` **R1** reference and is reused solely as a radio-CCFG byte compatibility *oracle*. This **does not** imply the vendor ships or supports this R2/NV5 memory layout. In particular the vendor `20260311` beta's vector/flash layout conflicts with our NV5 reservation and must not be copied.

Independent `g6/verify_native.py --profile p7u-cap192` now requires **both**:

1. Entire 88-byte CCFG SHA256 exactly `1defedbd2f474ee8b7385476801a63de95f55c3dd51115e29f97c69196049af7`, preserving ROM-BSL settings; and
2. exact `NV5` memory map/ELF/HEX, 40KiB NOLOAD, zero initialized NV, CAP192 generated capacities, and no overlap of application/CCFG/NV.

On top, `g7/verify_native.py` proves genuine linked task→service→TL→UART2 path, and `f07/verify_composed_native.py` proves actual calls to the two persistence/restore guard functions. Any gap fails the job without publishing a flashable file.

## Remaining release-critical obligations

- Physical P7U board revision, TI application UART DIO/flow-control, PA/RF/clock and SLZB management-console erase/rollback semantics.
- A fresh **full coordinator NV and Z2M database backup** with preservation of IEEE, TC keys, NWK/APS/TCLK counters and complete device roster, independently verified.
- NV2→NV5 state migration: the layouts overlap physically. Do not place this image on a radio with valuable existing NV without a validated extraction/conversion/restore.
- Sudden power-loss NVOCMP compaction and monotonic frame-counter persistence tests on isolated hardware.
- Actual large-network runtime router/neighbor/source-route table occupancy and prolonged communication stress.

No live Zigbee/HA/Z2M operation, firmware flash, reset, or erase belongs to this PR. `flash_authorized=false` even if all native jobs are green.
