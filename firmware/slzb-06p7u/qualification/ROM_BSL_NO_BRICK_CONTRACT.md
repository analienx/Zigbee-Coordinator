# P7U first-radio-flash / ROM BSL recovery contract — 2026-10-14

**Target only:** SMLIGHT SLZB-06P7U CC2652P7 radio, with a separate ESP32-S3 running SLZB-OS. Source/image preflight does not program either chip. The parent #61 stays draft. Nothing here can promise an unbrickable product without a real isolated-target end-to-end BSL recovery demonstration.

## Reprioritization requested by the user

Rebuilding a Zigbee network from an **independently verified, complete, usable** `zigpy/open-coordinator-backup` plus Z2M device roster is an acceptable fallback to perfect source NV2→NV5 migration. It does not make backup restoration guaranteed (coordinator IEEE, Trust Center, keys and counter floors remain compatibility requirements). For an **isolated spare P7U test**, Zigbee network re-pair risk is not the same as losing the ability to flash the CC2652P7 radio. We prioritize **never locking ourselves out of the radio bootloader** and proving an actual rollback before shipping/deploying.

## Two independent chips — never confuse flash targets

1. **ESP32-S3 core/SLZB-OS**, Ethernet, USB device bridge and web management: do **not** invoke an ESP32 flash, OTA core update, erase partitions, ESPHome takeover or manual ESP flash while testing custom CC2652P7 radio firmware.
2. **CC2652P7 radio**: its internal ROM serial bootloader remains accessible only when the CCFG ROM enable/backdoor DIO/polarity and physical ESP→radio BSL/reset routing work. A bad ZNP application may still be fully recoverable via ROM BSL. But changing `BL_CONFIG`, `ERASE_CONF`, flash protector fields, CCFG or the bridge/console can make an ordinary USB/LAN rollback impossible.

Official independent hardware reference (not fitted-board proof): `smlight-tech/slzb-esphome/hw_defs/06xu/r1_73.yaml` maps ESP UART TX GPIO17, RX18, RTS14, CTS15; radio BSL GPIO16 and RESET GPIO21, both inverted, and host USB selector GPIO47. **These are ESP pins, not the TI ZNP UART application DIO assignments**. Fitted PCB revision and installed SLZB-OS remain to be established.

**Manufacturer warning:** never select a flasher option to disable the CC26xx bootloader; that can require a debug probe. `smlight-tech/smlight-cc-flasher` documents `BOOTLOADER_ENABLE = 0xC5`, `BL_ENABLE = 0xC5`, matching physical backdoor pin/level and enabled `BANK_ERASE`. Its network BSL route explicitly sends `Commands.CMD_ZB_BSL` through `pysmlight.Api2` and may require unauthenticated API access. This establishes an available implementation, **not** that the particular SLZB-OS build on our unit supports it or that native USB CDC DTR/RTS maps correctly.

## Current source-image fail-closed gate

`firmware/slzb-06p7u/qualification/p7u_rom_bsl_image_gate.py` accepts native TI CCS Intel HEX generated in the actual P7U CI profiles. It:

- validates every Intel HEX length, checksum, address window, EOF, record type, no duplicate/overlap/truncation and total bounds;
- enforces exact model/profile, app load strictly below the NV2 base `0xAA000` or NV5 base `0xA4000`; **zero initialized bytes in NV**; disallows any load in the unmodeled CCFG-sector bytes or beyond P7 704 KiB;
- requires **all 88 loaded CCFG bytes** at `[0xAFFA8,0xB0000)`, matching the pinned actual manufacturer `20240710` CCFG SHA-256 `1defedbd2f474ee8b7385476801a63de95f55c3dd51115e29f97c69196049af7`;
- decodes real CC13x2x7 `BL_CONFIG` at byte offset `0x30` in that 88-byte record: ROM enable `0xC5`, backdoor enable `0xC5`, TI **DIO15** active low, plus `ERASE_CONF.BANK_ERASE_DIS_N=1`; checks `IMAGE_VALID_CONF` vector start, loaded SP/reset-vector plausibility;
- can optionally compare an **independent privately obtained installed 88-byte CCFG snapshot** byte-for-byte; mismatches stop (do not silently overwrite per-unit IEEE/CCFG).
- emits only hashes/counts/bounded diagnostics; always `flash_authorized=false`. It contains no serial, MQTT, HA, shell flasher, erase or write capability.

Synthetic hostile tests reject disabling BSL, changed DIO/level, disabled bank-erase, malformed HEX, NV overlap and missing/changed CCFG. Actual pinned CCS builds must additionally pass this same parser on the final P7U HEX.

### CCFG-free application-only derived artifact (safer candidate, not flash authorization)

After validation of the **full** ELF-derived P7U HEX, the gate can emit `--app-only-out P7U-APP-ONLY-SOURCE-NOT-FLASHABLE.hex`. The output is independently reparsed and byte-for-byte compared against the original address map below the selected NV start; the entire CCFG sector and NV2/NV5 are absent. Both stock NV2 and CAP192/NV5 native CI paths produce and hash this alternative.

This avoids carrying generic vendor CCFG bytes into a radio application update payload, protecting the potential per-device installed CCFG and its ROM backdoor **only if the selected physical flashing mechanism proves it erases/writes application sectors exclusively**. A backend that performs full-bank erase would still wipe CCFG and NV even when the HEX contains none. **DO NOT USE this derived artifact with a bank-erase/full-chip-erase command** or an updater whose sector plan has not been independently demonstrated.

### Fundamental limitation: erase semantics

**No initialized bytes in NV does not prove that an underlying flashing tool will avoid erasing NV**. A flashing backend may issue chip/bank erase, sector-erase the last CCFG sector or reprogram the 88-byte record. `smlight-cc-flasher -ewv` examples include erase/write/verify and can use ROM bank erase. For a first test, never assume `-ewv` is non-destructive to security/NV; a full bank erase can clear all NV, and a failed last-sector write could lose the bootloader configuration. The gate cannot infer what a particular SLZB-OS console firmware actually erases.

## Confirmed dangerous stock CLI behavior (source-proven)

At SMLIGHT flasher source commit `9a1d33571c1cdaedc9dfcdcf2df5b5a5fece0b1c`, `smlight_cc_flasher/device.py` method `CC26xx.erase()` invokes `erase_bank()`, which sends the TI ROM `BANK_ERASE` operation and reports "Erasing all main bank flash sectors". For non-M33 P7 the method does **not** subsequently call `erase_ccfg()`; that does **NOT** rescue NV in the erased main bank or prove last-sector safety. The commonly documented `smlight-cc-flasher -ewv` therefore must not be used as a presumed NV-preserving/BSL-safe method on the target.

The same pinned library exposes `cmdEraseSector(addr)` separately in `smlight_cc_flasher/command.py`, and reads chip identity/flash size during `CC26xx.async_init`. **Design the future writer around a bounded explicit application-sector allowlist**, real ROM `GET_CHIP_ID`/wafer ID, verified installed CCFG, precise before/after CRC and rollback. Never call `CC26xx.erase()`, `erase_bank()`, `erase_ccfg()`, `disable_bootloader()`, `set_ieee_address()` or `--force` for this project. A custom sector-only writer cannot be called proven until tested end-to-end on the spare radio.

## Physical preflight and rollback qualification (isolated P7U only)

**Read-only evidence required before any write:**
1. Observe actual label, board revision, management SLZB-OS version, target USB VID:PID/path, physical radio chip identity, stock firmware `SYS_VERSION`. Confirm **this is the spare P7U, not production MR4U/P10**.
2. Save a complete off-device factory radio image/CCFG + NV/IEEE snapshot *if ROM read access is available*, with hash and offline protected storage. Keep an unmodified verified stock radio firmware file, its official provenance, version/baud and a tested offline recovery procedure. Never publish private keys, TC seeds or IEEE identity words.
3. Prove independent **re-enter ROM BSL repeatedly after normal stock ZNP boots**, via actual SLZB-OS bridge/USB or isolated Ethernet; verify TI `GET_CHIP_ID`, `PING`, read-only safe sector fingerprint/CRC if supported, then return to stock ZNP with no configuration or NV change. Some of these access checks reset the **spare** radio; coordinate with its owner. They are not permitted on active network.
4. Verify original installed CCFG 88 bytes; if per-device identity differs from the vendor template, **do not flash** a generic CCFG without an audited machine-specific preservation strategy.
5. Inspect the actual selected flash backend's **sector erase plan**, prohibit full-bank/mass erase unless original complete radio state is backed up and deliberately accepted as disposable. Enumerate sectors `0xA4000..0xADFFF` and `0xAE000..0xAFFFF` explicitly.
6. On isolated unit only after separate authorization: prove re-enter-BSL and **restore the exact original stock image** after a deliberately invalid/nonfunctional *application-only* candidate while leaving bridge/ROM backdoor intact; confirm stock `SYS_PING`/`SYS_VERSION` again. If original-image rollback was not physically demonstrated, do not use the active coordinator.

## Recovery paths, not assumptions

- **Normal:** custom radio image ZNP valid -> stock SLZB-OS ESP bridge still operational -> manage TI BSL through verified mode -> flash original CC2652P7 vendor image back -> verify stock ZNP. Do not switch OS/core images as part of this.
- **Broken ZNP but working BSL:** recover through TI ROM, provided CCFG and bridge routes have been proved on the actual unit.
- **Radio ROM backdoor unavailable / CCFG disabled or corrupted:** USB/network route may fail; **CC26xx JTAG/debugger hardware** recovery may be necessary, if device debug and hardware access allow it. Never promise software recovery in this state.
- **Broken ESP32-S3/SLZB-OS:** separate manufacturer's recovery path exists for xU using USB boot-mode and correct xU ESP firmware, **not the same as radio flash**. This does not establish the full ESP32 bootloader access on our board/revision.
- **Zigbee network not restored:** a valid coordinator_backup + independent roster can enable migration/re-pair strategy; still prove IEEE/Trust Center/key frame counters and actual restoration. This does not alter the CC2652P7 BSL safety requirements.

## Outstanding gates outside pure code

Physical stock handshake, fitted board TI UART mapping, RF/PA + oscillator, BSL entry/reentry/return without destructive writes, actual selected SLZB-OS management-console erase policy, installed CCFG identity readback, original image rollback proof, APS/TCLK security state, cold power-cut and full-scale (>100 devices) load soak. Work that fundamentally requires hardware cannot be credibly marked COMPLETE via GitHub CI.

There is deliberately **no flash command or production migration implementation** in this tranche.
