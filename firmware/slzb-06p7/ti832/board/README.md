# P1 / G1 — SMLIGHT SLZB-06P7 board and hardware-compatibility audit

**Audit date:** 2026-10-12. **Status:** `G1_STATIC_SOURCE_PROFILE_VERIFIED`, **`G1_PHYSICAL_BOARD_BLOCKED`**.
**Scope:** original **SLZB-06P7, CC2652P7**. This is **NOT** a P10/MR4U, legacy SLZB-06 CC2652P, or newer SLZB-06P7U ESP32-S3/W5500 profile.
**No Zigbee radio, HA instance, ESP, UART, reset, NV store, flash or network state was touched. No firmware has been built.**

This document accompanies `board-contract.json` (normative structured findings) and `verify_g1.py` (native pinned TI source verification and negative tests).
The development branch was created from clean repository `main`, with P10 source authority frozen during G0. P1 does not modify any existing P10 source or build.

## 1. Evidence hierarchy (strict)

- **Level A — pinned TI silicon / SDK:** TI [CC2652P7](https://www.ti.com/product/CC2652P7), [CC13x2x7/CC26x2x7 SDK linker](https://github.com/TexasInstruments/simplelink-lowpower-f2-sdk/blob/6499c3f53fc5fb5806213be695450a7b43fbaf3d/source/ti/zstack/boards/cc13x2x7_cc26x2x7/cc13x2x7_cc26x2x7_tirtos7_ticlang.cmd), [CCFG](https://github.com/TexasInstruments/simplelink-lowpower-f2-sdk/blob/6499c3f53fc5fb5806213be695450a7b43fbaf3d/source/ti/devices/cc13x2x7_cc26x2x7/startup_files/ccfg.c), [LP_CC1352P7_4 ZNP project](https://github.com/TexasInstruments/simplelink-zstack-examples/blob/87ff5b638b632050228a7504f35cf3b95581c278/examples/rtos/LP_CC1352P7_4/zstack/znp/tirtos7/ticlang/znp_LP_CC1352P7_4_tirtos7_ticlang.projectspec) and [SysConfig](https://github.com/TexasInstruments/simplelink-zstack-examples/blob/87ff5b638b632050228a7504f35cf3b95581c278/examples/rtos/LP_CC1352P7_4/zstack/znp/tirtos7/znp.syscfg). SDK `6499c3f53fc5fb5806213be695450a7b43fbaf3d`; example `87ff5b638b632050228a7504f35cf3b95581c278`.
- **Level B — actual SMLIGHT product family:** [SLZB-06P7 original product](https://smlight.tech/product/slzb-06p7/) lists CC2652P7 radio, ESP32 host, LAN8720 Ethernet, CP2102 USB bridge, 5 dBi antenna; [06P7U product](https://smlight.tech/products/slzb-06p7u) lists **different** ESP32-S3/W5500 host and must not be conflated. Model/revision on *this specific device* remains unobserved.
- **Level C — functional compatibility references:** [Zigbee2MQTT's SLZB-06p7 entry](https://github.com/Koenkk/zigbee2mqtt.io/blob/master/docs/guide/adapters/zstack.md) explicitly links the `CC1352P7_coordinator_20250321.zip` family; [Koenkk build instructions](https://github.com/Koenkk/Z-Stack-firmware/blob/master/coordinator/Z-Stack_3.x.0/COMPILE.md) build `znp_LP_CC1352P7_4_tirtos7_ticlang` with SDK 8.30.01.01. **Our build remains pinned to SDK 8.32; the known release is not proof of its behavior.**
- **Level D — indicative, never a pin authority:** [SMLIGHT open ESPHome example](https://github.com/smlight-dev/slzb-06-fw-esphome/blob/main/configs/zb-bt.yaml) uses ESP32 RX GPIO5, TX GPIO17, 115200 baud, TCP/6638. This cannot prove which **CC2652P7 DIOs** the PCB connects; similarly older SLZB-06 pinouts are for a different SoC/board.
- **Level E — real unit measurements:** **NOT OBTAINED.** No photographed PCB revision/netlist, original P7 firmware CCFG readback, original radio flash image, chip identity, user-installed firmware version, boot pin mapping, or model-specific ROM-BSL test exists in this P1 evidence set. No physical-board PASS may be issued.

### G1 observed vs reference status

| Property | Evidence-backed result | Status |
| --- | --- | --- |
| Target silicon | CC2652P7, Arm Cortex-M4F, 704KiB flash, 144KiB main SRAM with parity, additional 8KiB cache SRAM | **A: silicon documented** |
| P7 compiler baseline | TI's `LP_CC1352P7_4` ZNP project (chip ID CC1352P7; same P7 Z-Stack firmware family) | **A/C: only reference** |
| Original SMLIGHT bridge | ESP32 + LAN8720 + CP2102/CP2102N family, LAN/Wi-Fi/USB routes | **B: model docs, not unit proof** |
| P7 radio UART TX/RX | **UNKNOWN**, not inferable from ESP GPIO | **E: blocked** |
| Hardware CTS/RTS/flow control | **UNKNOWN** | **E: blocked** |
| P7 BSL enable pin, polarity, serial pins | **UNKNOWN**; legacy DIO15 must not be guessed | **E: blocked** |
| User's physical P7 PCB revision | **UNKNOWN** | **E: blocked** |
| RF front-end pin routing / TX power table | CC2652P7 integrated PA capable up to +20 dBm, but SMLIGHT board-specific control and lawful power still need proof | **E: blocked** |
| TI example LEDs, buttons, XDS110 UART, MX25R8035F external flash | LaunchPad-specific references in the TI example; **not proof** of their availability on SMLIGHT | **A: source confirmed, adaptation blocked** |
| Physical P7 original CCFG / NVS location | **UNKNOWN**; pristine TI default is *not* a vendor-preservation baseline | **E: blocked** |

## 2. Correct memory geometry; do not reuse P10

Pin `CC13x2x7/CC26x2x7` linker. Its reference regions are:

| Region | Start (inclusive) | End (exclusive) | Size | Interpretation |
| --- | --- | --- | --- | --- |
| P7 TI reference application flash | `0x00000` | `0xAA000` | 680 KiB | Cannot overlap NV or last CCFG sector |
| P7 TI reference NVS | `0xAA000` | `0xAE000` | 16 KiB | **Two × 8KiB** erase sectors |
| P7 TI last flash sector | `0xAE000` | `0xB0000` | 8 KiB | Contains `.ccfg` at HIGH end; **whole-sector erase is destructive** |
| P7 TI reference SRAM | `0x20000000` | `0x20024000` | 144 KiB | Actual linked usage and allocator TBD |
| P7 conditional GPRAM alias | `0x11000000` | `0x11002000` | 8 KiB | Cache-as-RAM requires matching CCFG; not automatic heap |

Source: [TI pinned linker](https://github.com/TexasInstruments/simplelink-lowpower-f2-sdk/blob/6499c3f53fc5fb5806213be695450a7b43fbaf3d/source/ti/zstack/boards/cc13x2x7_cc26x2x7/cc13x2x7_cc26x2x7_tirtos7_ticlang.cmd). These are **unmodified TI example coordinates**, not verified legacy SMLIGHT layout.

**Flash-policy decision:** all release candidates default to `NOT_FLASHABLE`. The offline HEX audit must inspect actual records by sector, **model entire erase sectors**, reject address aliasing/hole/wrap/misaligned operations and distinguish writing individual `.ccfg` bytes from erasing the final sector. The default ROM BSL bank-erase operation **is not** safe preservation even if HEX contains no NVS records. An uploader's `eraseNVM=0` field is not proof of effective commands. CCFG and recovery controls must be compared to the exact original physical unit in private evidence before flash approval.

## 3. P7 TI stock CCFG is unsafe to use blindly

[TI pinned `ccfg.c`](https://github.com/TexasInstruments/simplelink-lowpower-f2-sdk/blob/6499c3f53fc5fb5806213be695450a7b43fbaf3d/source/ti/devices/cc13x2x7_cc26x2x7/startup_files/ccfg.c) has conditional defaults:

- `SET_CCFG_BL_CONFIG_BOOTLOADER_ENABLE = 0x00`: ROM bootloader **disabled by default**.
- `SET_CCFG_BL_CONFIG_BL_ENABLE = 0xFF`: ROM bootloader backdoor **disabled by default**.
- `SET_CCFG_BL_CONFIG_BL_PIN_NUMBER = 0xFF`: no known configured pin by default.
- The original SLZB unit might already have an enabled vendor backdoor, but **that does not make TI's stock generated CCFG safe**.
- SMLIGHT's [BSL tool documentation](https://github.com/smlight-tech/smlight-cc-flasher) describes required enabled BSL/backdoor and configured pin/polarity to preserve serial recovery; its support for a chip family is **not** proof of the actual P7 PCB signal.

**P1 decision:** preserve/compare board-original CCFG before ever deploying firmware, and reject any candidate that disables ROM BSL or removes vendor programming access. Do not hard-code DIO15 without original P7 evidence. Do not assume P10 separate CCFG at `0x50000000`.

## 4. The UART and RF mapping problem

The CC2652P7 ZNP UART uses chip DIO pin assignments generated by SysConfig for the TI **LaunchPad**. SMLIGHT's ESP/CP2102 board serial wiring is a different physical authority. ESPHome's `GPIO5`/ `GPIO17` is an **ESP32** mapping, not a P7 DIO pin mapping.

G2 may build the **unmodified TI reference** and inspect generated UART as a compiler sanity test. It must not emit a supposedly flashable SMLIGHT build until the P7 radio TX, RX, optional CTS/RTS, BSL control and reset-control nets are independently verified on the correct PCB.

RF: the P7 has a +20 dBm-capable integrated power amplifier. P10 has a different chip and TX table. Actual SMLIGHT PCB RF switch paths, antenna gain, output-power policy and applicable regional EIRP limit must be checked before enabling transmit. **Do not simply copy LaunchPad RF outputs or transmit at +20 dBm**.

## 5. Hardware verification work packet (without blind flashing)

**H1 — Physical provenance, no interface write:** Inspect a photographed label/PCB revision or manufacturer BOM/schematic that positively identifies CC2652P7 model/revision. Record only model, PCB revision, host SoC and digest of proof; do not put serial ID or network credentials in the public repo. Only an explicitly authorized, non-disruptive host-management read is permitted when an address/unit is known. No broadcast IP scanning, mode switch or BSL entry.

**H2 — Radio config and CCFG:** Obtain a **private read-only** verified native flash/CCFG snapshot from an isolated or already idle original P7 with validated tool semantics. Record SHA-256 of protected sectors privately and public sanitized BSL enabled/pin/level flags; confirm no read command triggers reset or BSL mutation. No CCFG patch yet.

**H3 — Hardware pin and bridge routing:** Verify actual CC2652P7 UART TX/RX, any hardware flow control, BSL backdoor and RESET wires using official board design, trustworthy unit PCB/netlist, or electrically verified spare. Cross-check against actual fitted host/bridge and reference firmware.

**H4 — RF & clocks:** Confirm oscillator / DC-DC / high-PA RF design settings, GPIOs, TX power table, antenna and regulation. If undocumented, explicit `BLOCKED`; **never use an unvalidated output power just to smoke-test**.

**H5 — Physical NV extent and recovery:** Establish original image/NVS pages and safe flash geometry from original radio. Preserve exact identity, 802.15.4 IEEE address, keys and frame counters privately; do not copy content into public CI. Demonstrate a **restore path on expendable hardware** before considering any network-hosting device.

### Hard STOP rules

Missing original firmware readback, mismatch in chip/model/revision, BSL disabled, missing CCFG or incomplete loader command evidence, unverified RF front-end, unacceptable erase coverage, or detected secret data in CI -> **STOP**. No automatic retries or fallback to another SLZB model. Keep P10/MR4U and Home Assistant untouched.

## 6. G2 compiler handoff

**Next technical work:** build a *vanilla TI 8.32 P7 reference* in hosted CCS first; no P10 patches, no RF transmit or flash. Exact pinned:
- TI SDK `6499c3f53fc5fb5806213be695450a7b43fbaf3d`
- TI examples `87ff5b638b632050228a7504f35cf3b95581c278`
- TI CCS `12.8.0.00012`, ARM Clang `3.2.2.LTS`, SysConfig `1.21.1.3772`, XDC `3.62.01.16`
- `examples/rtos/LP_CC1352P7_4/zstack/znp/tirtos7/ticlang/znp_LP_CC1352P7_4_tirtos7_ticlang.projectspec` only as a **compiler target**.
- Real output evidence: CCS, .out/.hex/.map, generated SysConfig pin list, effective CCFG, linker geometry, boot settings, source provenance. **Mark image `REFERENCE_ONLY / NOT_FLASHABLE`.**
- Only after that, introduce board-specific source changes behind the `board-contract.json` verified-pin gates, keeping P10 feature port separate.

### CI gates

```sh
python3 firmware/slzb-06p7/ti832/board/verify_g1.py --selftest
python3 firmware/slzb-06p7/ti832/board/verify_g1.py --sdk <pinned-ti-sdk> --examples <pinned-ti-examples> --selftest
```

`.github/workflows/slzb-06p7-g1-board-audit.yml` independently clones both immutable TI sources on a GitHub-hosted runner and checks the actual linker, CCFG defaults, device target, heap macros, SysConfig LaunchPad dependencies, and 12 negative controls.

**G1 verdict:** `SOURCE_PROFILE_ANALYZED` can pass on public proof alone; **`PHYSICAL_BOARD_BLOCKED` must not be promoted to PASS** until H1–H5 evidence exists. This is a genuine remaining hardware-input limitation, not a request to flash first.
