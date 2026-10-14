# P7U R1 stock/NV2 CCFG native-binding tranche

**Scope:** G6-enabled P7U R1 stock-compatible NV2 image. **Never flash this CI artifact.**
R1 board UART pinout, RF PA/clock, physical revision, working stock ZNP bridge,
actual installed CCFG and SLZB-OS console erase semantics are **not proven**.

## Evidence and source implementation

The accepted [vendor comparison](../board/VENDOR_CCFG_EVIDENCE.md) identifies
reported-current P7U `20240710` CCFG SHA256
`1defedbd2f474ee8b7385476801a63de95f55c3dd51115e29f97c69196049af7`.
It differs from the pinned native TI SDK 8.32 G6 CCFG only in the
`MODE_CONF_DCDC_RECHARGE` and `MODE_CONF_DCDC_ACTIVE` fields: the vendor
disables the two DC/DC settings, while TI's LaunchPad reference enables them.

The actual TI P7 SysConfig CCFG module has `enableDCDC` default true.
`p7u_stock_ccfg.py` applies exactly one `device.enableDCDC = false;`
after the original `ccfgSettings` loop on the pinned ZNP project.
That is a **source fact**, not a guess about physical P7U power circuitry.

The isolated `p7u-stock` native workflow track composes the original
G5/G6 patch first, applies this P7U override, and builds with the authentic
pinned CCS 12.8 / SysConfig 1.21.1 compiler pipeline. The independent G2 audit
still checks ELF/HEX initialized address equality, stock NV2 reservation, all
CCFG bytes and zero initialized NV. The G6 linker and UART symbol gates remain.

Unlike generic stock/CAP192 G6, whose 88 CCFG bytes must equal the TI
reference, the P7U track permits **only one known four-byte MODE_CONF change**
and requires the resulting entire 88 bytes to equal the vendor digest.
A different CCFG field, an unexpected byte, a changed bootloader field,
missing/duplicated source anchor, foreign device profile or flash-authorized
binding fails the hosted checks. The source/linked report remains
`NOT_FLASHABLE` with `hardware_qualified=false`.

## CI proof and expected result

Workflow: `.github/workflows/slzb-06p7-g6-native.yml`.
New matrix job: `native-base-vs-diag (p7u-stock)`; the preexisting
`stock` and `cap192` jobs must also stay green.
Unit test: `tests/p7u-ccfg-host/test_ccfg_overlay.py`.
The output artifact contains only the normal G6 `NOT_FLASHABLE`
payload plus `P7U-R1-CCFG-SOURCE-ONLY.json` and
`G6-BINARY-EVIDENCE.json`. The two evidence records distinguish a known
vendor image from a verified **installed** image; nothing claims fitted
board serial/keys/IEEE or actual original-unit readback.

## Deliberate exclusions

- No TI application UART DIO or RF matching from ESP32-S3 GPIO assumptions.
- No startup/restore/NV write semantics modified; F07 is separate.
- No change to original P7 or CAP192/NV5 CCFG.
- No firmware OTA/serial/SLZB-OS call, reset, erase or production operation.
- No assertion that CCFG byte equality proves console-flasher rollback.
- The `20260311` vendor beta's `0xAC000` vectors/NV overlap are **not** adopted.

**Remaining R1 evidence:** fitted PCB, app UART DIO & RTS/CTS, RF
path/clock/power, stock `SYS_PING/SYS_VERSION`, management-console
bootloader/erase preservation, and isolated physical first boot.
