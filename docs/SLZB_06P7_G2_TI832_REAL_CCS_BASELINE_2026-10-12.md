# G2 — SLZB-06P7 firmware project: genuine TI 8.32 vanilla ZNP reference build

Date: 2026-10-12. **Gate: G2`_TI_REFERENCE_LINKED_PASS` / G2 actual SMLIGHT hardware qualification BLOCKED.**

This report is a verified **compiled, linked and independently audited TI LP_CC1352P7_4 reference binary**, **not** an SLZB-06P7 deployable firmware, and is not permission to run any radio/flash/restore or disrupt Zigbee2MQTT.

## Evidence and provenance

- [Code and CI workflow on draft PR #61](https://github.com/analienx/Zigbee-Coordinator/pull/61). G2 source code commit `4e7e2a0796b52c8d26d1ea16f965a6514540f364`; GitHub pull_request event compile merge SHA `3d3eba98cb981b1f2a79778e4427324e96e6b06c`. Distinguish PR branch HEAD from tested merge commit.
- **[Actual GitHub-hosted CCS run #38237644568 — PASS](https://github.com/analienx/Zigbee-Coordinator/actions/runs/38237644568)**, with source tests and native compile/link/artifact auditing each PASS.
- [G2 job artifact (reference-only)](https://github.com/analienx/Zigbee-Coordinator/actions/runs/38237644568/artifacts/11740664769) — ID 11740664769; expires Nov 11 2026; contains binary, Intel HEX, linker map, generated TI CCFG/RF/UART/RTOS code, build log, source hashes, independent boundary evidence and a per-file SHA manifest.
- ZIP bytes `1,276,936`; SHA-256 **`55758249dc5dc05a44958eec787e487a70dee3a44018a4ca62542b9282810595`**. Independently downloaded; ZIP and **all 15 inner files** agree with their published SHA-256 digests (no mismatch).
- Project `znp_LP_CC1352P7_4_tirtos7_ticlang`, TI ZNP LaunchPad source **unmodified**. SDK `TexasInstruments/simplelink-lowpower-f2-sdk` @ `6499c3f53fc5fb5806213be695450a7b43fbaf3d`; examples `TexasInstruments/simplelink-zstack-examples` @ `87ff5b638b632050228a7504f35cf3b95581c278`.
- Genuine toolchain installed and executed: TI CCS **12.8.0.00012**, TI ARM Clang **3.2.2.LTS**, SysConfig **1.21.1.3772**, XDCTools **3.62.01.16**; Cortex-M4F hard-float TI-RTOS7. Built P7-target `tirtos7_m4f`, `drivers_cc13x2x7`, `display_cc13x2x7`, `driverlib_cc13x2x7_cc26x2x7`, `spiffs_m4f_cc26xx` native SDK libraries from pristine source, then imported untouched CCS projectspec and linked full real ZNP.
- Source preflight checked pinned upstream Git commits, pristine git diff, exact project/SDK linker/CCFG/options hashes; imported CCS `znp_cnf.opts` hash matches pristine SDK. No CAP192/R7–R12 patches included. Existing `feature-parity.json` **36 feature items remain not implemented for P7**.

## Verified ELF, HEX and linker measurements

| Output | Bytes or address | Exact meaning |
| --- | ---: | --- |
| Application flash capacity | 696,320 B | Reference `FLASH 0x00000..0xAA000` |
| Linked application flash used | **176,396 B** | `FLASH used`; 519,924 B unused by linker |
| Ordinary SRAM capacity | 147,456 B | Reference `0x20000000..0x20024000` |
| Linked SRAM used | **18,848 B** | `SRAM used`; 128,608 B unused in linker configuration |
| GPRAM used | 0 B | Additional 8,192 B cache/GPRAM alias is **not** proved safely available to application |
| NVS linker allocated | **16,384 B** | `.TI.bound:flashBuf0`, at `0xAA000..0xAE000`, **UNINITIALIZED** |
| **Actual NVS bytes in Intel HEX** | **0 B** | Independent checksummed address parsing; neither NV 8KiB sector receives initialized image bytes |
| CCFG bytes in HEX | **88 B** | `.ccfg` `0xAFFA8..0xAFFFF`, within final `0xAE000..0xB0000` flash sector |
| Total unique initialized HEX bytes | 176,484 B | 176,396 app + 88 CCFG |
| App sector size | 8,192 B | Offline sector-boundary audit only; **no erase or flash permitted** |

**Important audit correction:** The first native CCS run compiled/linked successfully but the new verifier rejected `FLASH_NV.used=16384`, assuming any linker allocation was initialized flash. Independent examination of the real map identifies the `.TI.bound:flashBuf0` 16KiB region as **UNINITIALIZED**; the image's Intel HEX has **zero** data records there. The audited distinction, not a blind waiver, is now enforced: NVS HEX writes and CCFG-crossing records are rejected; NV `used` records reservation, not image payload. The corrected full hosted CCS run #38237644568 completed **PASS**.

### Exact binary hashes

| Artifact | SHA-256 |
| --- | --- |
| `TI-LP-CC1352P7_4-REFERENCE-NOT-FLASHABLE.out` (2,368,644 B) | `90b44e59af383d79dd90ae63a8d00013a07017343611a34afb52dcb587c04d24` |
| `TI-LP-CC1352P7_4-REFERENCE-NOT-FLASHABLE.hex` (496,495 B ASCII) | `5b19e5a3cac13349b30188bc1e5dcf78f544019516b43181f4cf126aeb47de13` |
| `TI-LP-CC1352P7_4-REFERENCE-NOT-FLASHABLE.map` (618,193 B) | `d25124890813a25cc3da3d4a0948b27615c9b6459cb1cdc81eaee6fa0bf95365` |
| `G2-LINKED-EVIDENCE.json` | `5082cb1e2eea1fbc57c5ec75a6fcdf8db2a17a4992c0efb4a9e34bc7bf92a85b` |
| Full zipped evidence | `55758249dc5dc05a44958eec787e487a70dee3a44018a4ca62542b9282810595` |

The ~128.6 KiB *unused linked SRAM* is not proven available for P10-sized OSAL heap or extra device tables. Dynamically allocated heap, ISR/RTOS stack high-water and all runtime resources are unmeasured; capacity feasibility requires later RAM profiling, not just subtracting linker sections.

## Real generated configuration findings (new; not G1 guesses)

The artifact includes actual `ti_devices_config.c`, `ti_drivers_config.c/.h`, `ti_radio_config.c/.h`, `ti_sysbios_config.c`, `ti_zstack_config.h`.

**Effective generated TI example CCFG (not SMLIGHT CCFG):**
- `SET_CCFG_BL_CONFIG_BOOTLOADER_ENABLE=0xC5`; `SET_CCFG_BL_CONFIG_BL_ENABLE=0xC5`; `SET_CCFG_BL_CONFIG_BL_PIN_NUMBER=0x0F` (**DIO15**); `SET_CCFG_BL_CONFIG_BL_LEVEL=0x00` (**active low**).
- `SET_CCFG_IMAGE_VALID_CONF_IMAGE_VALID=0x00000000`, LF XOSC setting `0x02`, GPRAM disabled `0x01`.
- This differs from the **fallback defaults** in TI's `startup_files/ccfg.c`, which have disabled bootloader/backdoor unless SysConfig-generated macros override them. G1's documentation of those fallback defaults is still valid; G2 proves the **effective example build** overrides them. Neither reveals the real SLZB-06P7's original CCFG/BSL wiring.

**TI LaunchPad generated UART/RF pins (NOT the 06P7 pin map):**
- UART `CONFIG_GPIO_DISPLAY_UART_TX = DIO13`, RX `DIO12`.
- RF `CONFIG_RF_24GHZ = DIO28`, `CONFIG_RF_HIGH_PA = DIO29`, `CONFIG_RF_SUB1GHZ = DIO30`.
- The project targets **CC1352P7 LaunchPad**; the actual SMLIGHT uses **CC2652P7**, with a different host/antenna/front-end and no warranted assumption about matching connections. The generated TI example even carries sub-GHz RF concepts absent from a 2.4GHz-only CC2652P7 appliance.
- Do **not** copy these DIO assignments, RF tables or CCFG into any unit-specific firmware until verified against authentic P7 board/schematic/original-image evidence.

## Tests and reproducibility

- [Verifier](https://github.com/analienx/Zigbee-Coordinator/blob/feat/slzb-06p7-ti832-p10-parity/firmware/slzb-06p7/ti832/g2/verify_vanilla.py) performs source `git rev-parse`/tracked-diff proof, actual P7 SDK memory/CCFG ref checks, strict Intel HEX checksums/record grammar/no overlapping addresses/no NV or out-of-flash bytes, ARM ELF32 little-endian machine check, exact real linker region checks, and SHA-256 artifact provenance.
- [Workflow](https://github.com/analienx/Zigbee-Coordinator/blob/feat/slzb-06p7-ti832-p10-parity/.github/workflows/slzb-06p7-g2-vanilla-ccs.yml) runs actual native CCS on GitHub-hosted Ubuntu; source-only selftests and fail-closed G1 checks precede compile.
- [G0 source-inventory workflow](https://github.com/analienx/Zigbee-Coordinator/actions/runs/38237644658) PASS; [G1 pinned-source board audit](https://github.com/analienx/Zigbee-Coordinator/actions/runs/38237644627) PASS; [repository Python tests](https://github.com/analienx/Zigbee-Coordinator/actions/runs/38237644670) PASS.

**No radio, hardware, HA/Z2M, coordinator flash, host UART, network key/NV access, factory reset, migration or re-pairing was used.** The manifest explicitly has `flash_authorized=false`, `hardware_qualified=false`, `actual_slzb_ccfg_verified=false` and `original_pinmap_verified=false`.

## G2 acceptance and G3 prerequisites

**G2 compiler baseline PASS**: the vanilla TI 8.32 P7 source builds real native ELF/HEX/MAP, pinned source/toolchains and produced artifacts are hash-verified, HEX contains no NV payload, CCFG occupies known last-sector range, ARM identity and resource totals have been independently checked. Audit code and build job remain in the draft PR, not merged to main.

**Still hard-blocked:** Physical SLZB-06P7 qualification; exact PCB/radio UART DIOs, recovery BSL pin/reset wiring, factory CCFG bytes, real NV sector content/compatibility, host ESP bridge and RF power. A visually similar SMLIGHT board, TI LaunchPad, and P10/MR4U are not substitutes.

Next stage must be explicitly separate from this vanilla image:
1. **G3:** P7 board adaptation and *measured* memory/NV/capacity profiling, while retaining no-flash policy until real hardware board proof; do not transplant 2KiB P10 NVS or M33F/P10 CCFG.
2. **G4:** Port CAP192 plus R8–R12 safety/diagnostics under pinned source + actual patched-C fault injection, each ledger item separately qualified. Don't claim 36/36 implemented based on G2.
3. **Later isolated qualification:** genuine spare 06P7 full backup, CCFG/BSL proof, vendor RF comparison, controlled one-shot flash and restore evidence, only with explicit physical-use authorization. The running household network is never the G2 test fixture.

**Verdict: `G2_TI_REFERENCE_LINKED_PASS`; `SMLIGHT_06P7_HARDWARE_QUALIFIED=false`, `FLASH_AUTHORIZED=false`.**
