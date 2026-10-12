# SLZB-06P7 / TI SDK 8.32 — G3 Five-Sector NV Engineering

**Date:** 2026-10-12. **Qualification:** G3 offline/native NV5 layout PASS; actual SLZB-06P7 physical board, NV compaction integrity and CAP192 runtime NOT QUALIFIED; FLASH / ERASE / RESET / MIGRATION NOT AUTHORIZED.

## Pinned evidence

Native TI ARM Clang 3.2.2.LTS / CCS 12.8 P7 build and G3 NV5 prototype: https://github.com/analienx/Zigbee-Coordinator/actions/runs/38281005531 (PASS). Native candidate artifact: https://github.com/analienx/Zigbee-Coordinator/actions/runs/38281005531/artifacts/11761661626. Downloaded archive SHA256: 2b14a991a0e6e0a59a3b4c9bbdfbc446dd140e4930a36b2ccb16b157b9354690, identical to the GitHub artifact digest; 12 of 12 internal manifest file hashes and sizes independently verified.

Original source authority: TI SDK 8.32 commit 6499c3f53fc5fb5806213be695450a7b43fbaf3d; TI ZNP example commit 87ff5b638b632050228a7504f35cf3b95581c278. The pristine G2 reference is compiled and sealed before any prototype changes; it is not patched. The separately isolated G3 UART warning correction is also compiled and sealed first, then reverted before creating the NV5 candidate.

## NV geometry and measured linker delta

| Property | Pristine G2 | NV5 prototype |
| --- | ---: | ---: |
| Application region | 0x00000–0xAA000, 696,320 B | 0x00000–0xA4000, 671,744 B |
| Application linked used | 176,396 B | **178,396 B** |
| Application unused | 519,924 B | **493,348 B** |
| Linked SRAM used | 18,848 B | **18,884 B** |
| Heap linker start | 0x20006030 | **0x20006054** |
| Heap linker end | 0x20023C00 | 0x20023C00 |
| Heap address span, NOT free heap | 121,808 B | **121,772 B** |
| Physical NV region | 0xAA000–0xAE000, 16,384 B | **0xA4000–0xAE000, 40,960 B** |
| Storage + compaction pages | 1 + 1 | **4 + 1** |
| Initialized HEX bytes in NV | 0 | **0** |
| Final CCFG sector | 0xAE000–0xB0000 | **unchanged** |
| Loaded CCFG | 88 B | **88 B, byte-identical to G2** |

The native CCS candidate actually compiled TI nvocmp.c with compiler option -DNVOCMP_NVPAGES=5, the linker with --define=NVOCMP_NVPAGES=5, and generated ti_drivers_config.c contains internal NVS regionBase=(void *)flashBuf0 with regionSize=0xa000. ELF32 ARM loadable segments and Intel HEX match byte-for-byte, with no bytes in the five-sector NV region. Only three pinned source inputs change in the isolated NV5 workspace: the TI P7 SDK linker, ZNP example projectspec and SysConfig. The final 8KiB CCFG sector is not moved.

The stricter effective-driver verifier checks the real compiler command and generated NVS driver rather than trusting declared options alone. Final follow-up CI (must PASS before closing that additional check): https://github.com/analienx/Zigbee-Coordinator/actions/runs/38282165176.

## Why five pages, and why link success is not enough

The pinned NVOCMP driver describes one sector dedicated to compaction and NVPAGES−1 sectors for storage. CC13x2/CC26x2 page size is 8KiB. TI historical planning figures yield 192 × 27 + 96 × 23 + 298 × 19 + about 2,300 = 15,354 B of conceptual trust-center/NWK/address/other records, not a measured TI SDK 8.32 actual format or fragmentation limit. The original two-page NV layout has only one nominal 8KiB storage sector; the five-page candidate offers nominal 32KiB storage plus 8KiB compaction sector. That alone does not prove 192-key endurance, compaction correctness, CRC recovery or free-space margin.

Official TI NV guide: https://software-dl.ti.com/simplelink/esd/simplelink_cc13xx_cc26xx_sdk/8.30.00.121/exports/docs/zigbee/html/zigbee/flash_memory-cc13xx_cc26xx.html ; TI confirms CC2652P7 and CC1352P7 2.4GHz source compatibility: https://software-dl.ti.com/simplelink/esd/simplelink_cc13xx_cc26xx_sdk/6.10.01.01/exports/docs/zigbee/html/cc13xx_cc26xx/software-on-cc2652p.html . Neither statement proves custom SMLIGHT board wiring or RF power configuration.

## Firmware implementation

- Exact source-overlay generator + nine mutation controls: https://github.com/analienx/Zigbee-Coordinator/blob/feat/slzb-06p7-ti832-p10-parity/firmware/slzb-06p7/ti832/g3/nv5_layout.py
- Independent native ELF/HEX/linker audit + seven malicious fixtures: https://github.com/analienx/Zigbee-Coordinator/blob/feat/slzb-06p7-ti832-p10-parity/firmware/slzb-06p7/ti832/g3/nv5_verify_linked.py
- Compiled driver/HWAttrs proof + eleven mutation fixtures: https://github.com/analienx/Zigbee-Coordinator/blob/feat/slzb-06p7-ti832-p10-parity/firmware/slzb-06p7/ti832/g3/nv5_effective.py
- Actual CCS build/publish sequence: https://github.com/analienx/Zigbee-Coordinator/blob/feat/slzb-06p7-ti832-p10-parity/.github/workflows/slzb-06p7-g2-vanilla-ccs.yml

## Explicit stop conditions — never flash this image

1. **Old NV base moves.** Existing two-page NV occupies different logical indexes within new five-page partition. A normal firmware update may look like an erased or invalid coordinator network. Layout change is a migration, not preservation by default.
2. **Original network security unknown.** Genuine per-sector flash backups, coordinator IEEE/PAN/network keys, outgoing frame counters and a verified counter-monotonic rollback must exist privately before any isolated migration. No raw keys, serials or coordinator backups belong in Git.
3. **Real SLZB-06P7 board unknown.** Original non-U physical PCB, ESP↔radio GPIO, RF switch/power, original CCFG/BSL backdoor and recovery protocol remain unverified. TI LaunchPad CCFG is not product CCFG. Byte-identical TI CCFG to G2 does not show a flasher preserves erase sectors.
4. **Runtime capacity not tested.** Multi-page TI NVOCMP wear/compaction, 192 keys + 96 NWK entries + 298 theoretical addresses, churn, corruption, repeated cold restarts, interruption and security counter continuity need actual driver fault tests and later spare-hardware validation.
5. **CAP192 stack behavior not implemented.** Existing stock P7 ZNP source still contains MAX_DEVICE_TABLE_ENTRIES=50 in native compiler commands; all 36 P10 CAP192/R7–R12 feature-parity flags remain unimplemented for P7. G4 must port and independently qualify actual table/route/diagnostic/transport behavior.

**Final G3 source qualifier:** NV5 source/layout/native linker PASS; effective-driver/compiled-options follow-up CI pending until full run success; real NV endurance and SMLIGHT physical/BSL/RF/CCFG qualification BLOCKED. Draft PR #61 is unmerged. No radio, HA, Zigbee2MQTT, serial, bootloader, erase or flash action has been performed.
