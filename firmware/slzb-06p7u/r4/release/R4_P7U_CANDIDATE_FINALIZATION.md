# SLZB-06P7U R4 qualification candidate

Target is the existing **SLZB-06P7U R1.73 / CC2652P7** profile, as confirmed by the owner. This package does not target SLZB-07P7.

The `p7u-r1-r5-qualification-candidate-<source SHA>` download is created only after the full native build's source prerequisites, two independent native replicas, reproducibility and the pinned B4 existing-owner host build/runtime checks pass at that exact source. Read `candidate.json` for the actual source, run and every bound file hash. A failed or skipped prerequisite cannot produce this download.

The full image has TC300, APS3, 96 direct children plus the parent slot, routing192/64/128, C/IRQ4096, stock20240716 board/CCFG and four-page NVS at A6000..ADFFF. The linked M4F task/Hwi context and archive are checked on this full image. B5 and automatic network formation remain off. Unjournaled coordinator NWK key update/switch remains disabled.

`P7U-R4-APP-ONLY.hex` contains only image-derived low APP sectors below A0000, with explicitFF padding. Its receipt lists sectors and orders vectors last. **It is input to the existing private, same-unit baseline binding/sector writer, not permission to program the HEX directly.** Do not program the full audit HEX/BIN or use whole-chip/bank erase. Preserve NV4, CCFG and the reserved upper sectors.

Use the current unit's fresh verified private baseline and existing bounded writer/admission procedure; do not repeat restore rehearsal or the old UART diagnostics. Check exact board identity, current APP/NV/CCFG parity, candidate hashes and sector list before the separately authorized hardware window. No private bytes belong in the public package. The previously installed minimum ZNP image and its successful SYS/UTIL/NV4 evidence remain historical bringup evidence.

The candidate is for isolated qualification, not household migration or release. Current native capacities do not prove300 live NV records fit through sustained compaction, opaque SSP/RF counter behavior, runtime free-heap headroom, commissioning or OTA. The remaining physical checks are the existing narrow security-persistence/reset/compaction observations from issue137; keep production traffic untouched. `full_b0_b4_sealed=false` and `flash_authorized=false` distinguish this engineering candidate from completed physical qualification or an authorized flash operation.

The accompanying host bundle is the pinned reviewed existing-owner source, default disabled. Its receipt proves hosted compile/runtime checks; it does not install or enable collection on the running host.
