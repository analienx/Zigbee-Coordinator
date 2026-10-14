# P7U G7 + F07 native integration acceptance — 14 October 2026

**Status: implementation candidate; NOT FLASHABLE.** This is a matrix of genuine pinned TI SDK 8.32 compiler artifacts, not a release image and not evidence of installed hardware behavior. Parent #61 remains draft.

## Why this exists

The existing G7 transport CI tested stock and CAP192 **without the merged F07 persisted-NIB/startup-restore guards**. The existing G6/F07 CI tested the F07 hooks **without G7 retained queue and fairness**. The previous P7U native binding proved vendor CCFG parity **without both together**. Independently green workflows cannot establish that the production feature set composes.

## New native matrix

- `p7u-f07-stock`: G5/G6/G7 transport + F07 commit-and-restore guards + SMLIGHT P7U `20240710` CCFG (`enableDCDC=false`) + stock NV2/16 KiB. `verify_native.py --profile p7u-stock` requires exact full vendor CCFG SHA256 `1defedbd2f474ee8b7385476801a63de95f55c3dd51115e29f97c69196049af7`.
- `cap192-f07`: G5/G6/G7 transport + F07 guards + CAP192/NV5/40 KiB linker profile. `verify_native.py --profile cap192` requires zero initialized NV, native capacity/region checks and original TI reference CCFG. **Not P7U-specific yet**: this track deliberately does not assume that an NV5 layout is safe to flash with a P7U factory image, or that existing NV2 state is automatically migratable.

Both must prove authentic pinned CCS 12.8/SysConfig 1.21.1 builds; exact PT_LOAD ELF-to-HEX; NV reservations, CCFG, RAM/flash accounting; G6 clock call edge; G7 service/UART write chain and fairness ownership; and additionally F07 **native un-inlined** function bodies and the direct coordinator-ready and restore call edges. `noinline` on each F07 guard is solely to make its linked use independently auditable.

## Fail-closed source and host gates

`test_g7_f07_integration.py` checks the actual pinned SDK `zd_app.c` with both F07 source overlays and deliberately mutates key read paths and call guards. The new fast workflow composes the actual pinned TI G5, G6, G7 and F07 modifications before native build and revalidates the exact guards against that composed source.

- Requested existing-network restore: fail-closed `DEV_HOLD`, never silently initialize defaults / clear keys after a failed read or restore, regardless of Touchlink.
- Coordinator-ready: NIB requires raw NVINTF update/read `SUCCESS` before `DEV_ZB_COORD`.
- G7 retained queue: original G7 verifier independently verifies linked task-to-service and UART2 implementation provenance.
- No build track or artifact claims `flash_authorized=true`. Any unexpected CCFG change, initialized NV contents or missing guard linkage fails CI.

## Critical exclusions

1. **No full F07 certification.** No proof yet that NWK/APS/TCLK frame counters cannot regress, that Trust Center/device/security tables are complete, or that buffered NVOCMP writes survive sudden power loss.
2. **No on-device migration or wipe.** NV2 physical layout at `0xAA000` and NV5 at `0xA4000` overlap; switching from stock NV2 to NV5 must not happen until a cryptographically preserved backup and separately qualified migration and rollback exist.
3. **No board acceptance.** ESP32-S3 bridge pins from the ESPHome 06xU profile are **not** TI application UART DIO assignments; physical UART/RF/clock/path, real `SYS_PING`, management-console erase scope and actual CCFG/IEEE/security readback remain unverified.
4. **No production action.** No flash, reset, erase, Zigbee network cutover, HA or Zigbee2MQTT operation is authorized by a green CI result.

**Next strict gate:** Isolated real P7U board bring-up with verified pin configuration and physical power-loss security-state tests; then migrate NV2 to NV5 only with a proven preservation and rollback design.
