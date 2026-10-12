# slzb-06p7 — SMLIGHT SLZB-06P7

## Identity

- Original product: SMLIGHT SLZB-06P7 (not SLZB-06 legacy, 06P7U or MR4U/P10)
- Physical radio: TI CC2652P7 (SMLIGHT product reference; specific user's PCB not physically inspected)
- Stack family: TI Z-Stack / ZNP
- Repository coordinator ID: `slzb-06p7`

## Current development status (2026-10-12)

**G0 source-parity inventory: PASS. G1 static board/source research: PASS. G2 pristine TI 8.32 LP_CC1352P7_4 CCS compiler/link: PASS.**

**Physical SMLIGHT board qualification: BLOCKED. Firmware is REFERENCE_ONLY / NOT_FLASHABLE.**

- [G2 full native linker and artifact evidence](../../docs/SLZB_06P7_G2_TI832_REAL_CCS_BASELINE_2026-10-12.md)
- [G2 compiler/image auditor](../../firmware/slzb-06p7/ti832/g2/verify_vanilla.py)
- [G1 board contract and hardware blockers](../../firmware/slzb-06p7/ti832/board/README.md)
- [G0 pinned feature parity inventory](../../firmware/slzb-06p7/ti832/phase0/README.md)
- [Draft PR #61](https://github.com/analienx/Zigbee-Coordinator/pull/61)
- [Native CCS G2 build #38237644568 PASS](https://github.com/analienx/Zigbee-Coordinator/actions/runs/38237644568)

The G2 generated project is TI's **CC1352P7 LaunchPad** reference compiled with actual CCS, not a radio/PCB-qualified CC2652P7 SMLIGHT image. The source and binary audit verifies a 176,396-byte app, 18,848-byte linked SRAM, 16KiB **UNINITIALIZED** reserved NVS with zero HEX payload, and 88 CCFG bytes at the final 8KiB flash sector. No P10 feature-parity behavior has yet been ported; all 36 G0 feature items remain unimplemented for P7.

Do not silently reuse P10/MR4U assumptions for P7: silicon generation, firmware build lineage, NV 8KiB sectors, actual CCFG recovery/BSL semantics, radio UART wiring, RF/PA settings, security counters and migration/restore are separate qualification domains.

No flash, network migration or original coordinator interaction is authorized by the P7 source or linker work.
