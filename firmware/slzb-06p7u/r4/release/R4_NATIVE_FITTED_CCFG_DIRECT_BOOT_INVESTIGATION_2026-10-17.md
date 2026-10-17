# R4 P7U native ROM-direct boot: fitted CCFG and recovery investigation

17 October 2026. PREPARATION ONLY — DO NOT FLASH. Owner has ONE coordinator.

## Verified binary facts

- The working P10 T832 A1 native build uses vector table 0 and IMAGE_VALID_CONF 0 in separately mapped CCFG (P10 0x50000000); no handoff trampoline. Its native reset handler is 0x2B311.
- The P7U R4 native binaries similarly link a valid reset vector 0x25C69 at 0 and have compiled IMAGE_VALID_CONF=0.
- But the original fitted P7U factory CCFG at physical address 0xAFFEC has IMAGE_VALID_CONF=0xAC000. Two physical R4 app+boot-handoff flashes CRC-verified yet produced NO ZNP SYS_PING, including after manual reset and full power cycle. That does not prove which stage failed.
- The fitted P7U factory CCFG compared with R4 native generated CCFG has exactly THREE different 32-bit fields:

| Register | Fitted factory | Compiled R4 |
| --- | --- | --- |
| MODE_CONF_1 | 0xFFC00010 | 0xFF800010 |
| MODE_CONF | 0xF1B9C1FF | 0xFFB9C1FF |
| IMAGE_VALID_CONF | 0x000AC000 | 0x00000000 |

- These differences show that R4 inherited the older 20240710 DC/DC/boost settings; its config is NOT vendor-20260311 equivalent. Fitted MODE_CONF has DCDC_ACTIVE and DCDC_RECHARGE bits 26,27 cleared (enabled), VDDR_EXT_LOAD bit25 cleared; MODE_CONF_1 selects alternate VMIN 0xC rather than 0x8. Vendor clock, BL_CONFIG=0xC5FE0FC5 (DIO15-low ROM BSL), erase configuration, protection and remaining factory CCFG bytes match. IEEE fields are private and are not exposed.
- TI ROM DOWNLOAD/SEND_DATA can program a flash address range; this DOES NOT physically qualify a four-byte CCFG program on the actual board.

## Minimally invasive, offline candidate

Preserve original fitted factory CCFG and other 8KiB top-sector bytes EXACTLY, changing only four bytes at 0xAFFEC: 00 C0 0A 00 to 00 00 00 00. In reality only two bytes lose one or more bits. This is 1-to-0 NOR flash programming in principle and does not need erasure for the forward change, provided the TI ROM accepts and verifies that specific program operation.

Two original full 704KiB captures must match SHA256 ba654310cef8f1543a96c9bb6d5ef4f17411829642bcbe8249e91de6ae5b38f3. Two real independently extracted native APP-only HEXs must match SHA256 38fe3b5ddf06d79d4d9cbe90900c770d1b6042c9f7f4bd0216d292d966ca11e6.

Original fitted 8KiB top-sector CRC32 3c032e08, SHA256 39a6d353b9e3b2f729863416640c834d11e85bf5f4ace505a9b40b6789e4cc57. Predicted direct-boot top-sector CRC32 f99fdfff, SHA256 14951403dc11b5b1adfedf97984473772888296a124e3e7985115cb99ed9aea9.

The new reproducible r4_fitted_native_direct_ccfg_offline.py produces the four-byte candidate patch, exact private factory 8KiB restoration image, predicted top-sector image and hash-only receipt. It has NO transport or hardware write. Every artifact explicitly says it is NOT flash-authorized.

## CRITICAL rollback blocker

Reversing IMAGE_VALID_CONF from 0 to 0xAC000 requires programming 0-bits back to 1-bits. This is IMPOSSIBLE by another ordinary flash program operation. It REQUIRES erase of the entire last 8KiB CCFG sector at 0xAE000 and exact-board original 8KiB rewrite.

TI specifically warns that top-sector erase has special SECURITY DEFAULT handling. The physically tested 23-application-sector stock rollback and 0xAC000 factory loader rollback DO NOT establish any ability to restore the last CCFG sector. The user's stock firmware update over SLZB web interface must not be assumed to reset this physical boot word: stock image restoration is a different operation from CCFG restoration.

Release blockers: separately qualify 0xAFFEC 4-byte ROM programming and exact 0xAE000 8KiB restoration, preserve DIO15-low bootloader access and full manufacturer factory original, prove post-rollback factory SYS_PING, then start with an observable minimal TI ZNP baseline before enabling B1-B4. Never erase CCFG to test a theory without independent recovery proof on the actual hardware.

Do not send any BSL, reset, erase, program, stock update or power-cycle instruction to the current only coordinator in this investigation. Its installed R4/handoff remains silent.

## Sources

- TI CC2538/CC13xx/CC26xx serial ROM bootloader SWRA466E: https://www.ti.com/lit/an/swra466e/swra466e.pdf
- TI CC13x2x7 CC26x2x7 Flash API: https://dev.ti.com/tirex/explore/content/simplelink_cc13xx_cc26xx_sdk_8_32_00_07/docs/driverlib/cc13x2x7_cc26x2x7/driverlib/group__flash__api.html
- TI CC13x2x7 CCFG: https://software-dl.ti.com/simplelink/esd/simplelink_cc13xx_cc26xx_sdk/latest/exports/docs/driverlib/cc13x2x7_cc26x2x7/register_descriptions/CPU_MMAP/CCFG.html
- First R4 physical flash and factory rollback: https://github.com/analienx/Zigbee-Coordinator/issues/103#issuecomment-6239607921
- P7U R2 startup issue: https://github.com/analienx/Zigbee-Coordinator/issues/80
- P10 T832 native/physical boot reference: https://github.com/analienx/Zigbee-Coordinator/issues/53

Current gate: owner-bound offline plan PASS; physical CCFG transition/recovery NOT QUALIFIED; NOT FLASH READY.
