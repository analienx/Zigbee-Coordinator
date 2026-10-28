# R4 SLZB-06P7U — Emergency First-Flash Incident and Recovery (2026-10-17)

> **SAFE STATE:** Original stock P7U restored, `STOCK_RECOVERY_SYS_PING_PASS`. First R4 boot failed. **DO NOT FLASH R4 AGAIN** until its MCUboot trust/signature and bootloader acceptance have been independently validated. The household MR4U, HA, and Zigbee network were not touched.

## Actual physical evidence

| Gate | Outcome |
| --- | --- |
| Isolated target | SLZB-06P7U R1.73 / CC2652P7, reported radio 20260311 |
| Original complete backups | 2 independent, byte-identical 704KiB images; matched previously retained manifest |
| Before-flash ROM safety | Original application CRC **23/23 PASS**; protected `0xAC000` boot and `0xAE000` top/CCFG CRC match |
| No-write BSL exit | Original ZNP `SYS_PING` **PASS** |
| Physical R4 app-only programming | **23/23** 8KiB app sectors individually CRC verified; no bank/chip erase, no legacy NV, boot/CCFG write |
| First R4 reboot | **FAIL**; no valid ZNP `SYS_PING` |
| Automatic exact-original rollback | **PASS**; 22 sectors restored (1 already matched), original `SYS_PING` **PASS** |
| Release authorization | **FALSE**; source/native CI passing is not a boot-success signal |

Pilot source image: native `fa8c62feb34ed7e7fbb856491a1d83c02d030193`, app-only HEX SHA256 `106a63bb5456664cee2dc850692835f13b0357a31fb6de6db029114f341c86fa`. The current draft PR head at incident review: `0d7986c8cab28d7d33f98b903ad0fc57ad08ddc4`. Later commits changed CI/checkers, not firmware source. All eight later CI workflows passed; this **does not** override failed physical boot.

## Root-cause investigation: stock firmware is signed MCUboot

Verified locally from private factory flash; do not upload full flash or actual key/signature bytes.

- MCUboot header magic `0x96F3B83D`; XIP load 0; header size `0x80`; payload size `0x2AD58`; header image version `1.0.0+0` (NOT radio 20260311).
- Normal TLV at `0x2ADD8`, magic `0x6907`, total length **151 bytes**.
- TLV `0x10`: 32-byte SHA256. **Independently matched** SHA256 of entire header + firmware body.
- TLV `0x01`: 32-byte KEYHASH.
- TLV `0x22`: 71-byte ECDSA signature.
- The flashed R4 package was constructed with magic, size and 0x80 vectors but **NO authenticated MCUboot TLV trailer**.

**Most likely explanation:** resident MCUboot rejected unauthenticated R4 before jumping to firmware. This remains a **strong hypothesis**, not a proof of the sole fault: actual installed bootloader validation mode, trusted public key, anti-rollback and any potential runtime faults require independent analysis. No authenticated boot trace was captured.

### Official references

- https://github.com/mcu-tools/mcuboot/blob/main/docs/design.md
- https://github.com/mcu-tools/mcuboot/blob/main/docs/signed_images.md
- https://docs.mcuboot.com/imgtool.html
- https://github.com/mcu-tools/mcuboot/blob/main/boot/bootutil/src/image_validate.c
- https://software-dl.ti.com/simplelink/esd/simplelink_cc13x2_26x2_sdk/4.40.00.44/exports/docs/driverlib_cc13xx_cc26xx/cc13x2_cc26x2/register_descriptions/CPU_MMAP/CCFG.html

Copying the original signature, inserting SHA-only TLVs, or signing with any random new key **will not** pass an enforced, existing vendor-key trust chain.

## Why the R4 memory layout fix should be retained

- Fitted original `IMAGE_VALID_CONF` selects resident loader at `0xAC000`; changing CCFG was deliberately avoided.
- Previous R4 NVOCMP NVS base `0xAA000`, size `0x4000`, overlapped the loader sector.
- Same-device verified original images show `0xA0000` and `0xA2000` fully erased.
- PR #132 moves internal two-page NV to `0xA0000..0xA3FFF`, app base to `0x80`, preserves everything `0xA4000..0xAFFFF`.
- The safe app-only programmer targeted `0x00000..0x2DFFF` (23 sectors); **verified CRC alone does not certify signed boot or ZNP**.

## Lessons learned and mandatory future gates

1. **Check the complete MCUboot header, TLV SHA, KEYHASH, ECDSA signature and public-key trust chain before any physical flash.** Header magic and offset checks are insufficient.
2. **CI native success is source/build evidence, not verified startup.** Require independent signed-package validation and actual `SYS_PING`/`SYS_VERSION` hardware gate.
3. **Two readbacks and a rehearsed exact-stock rollback prevented board loss.** Never waive the full backup or matched CCFC/sector guards.
4. **Protect loader and CCFG at erase-sector granularity**, not just per-loaded HEX byte; never bank/chip erase. Continue to make zero sector last.
5. **Windows `serial_asyncio` socket adapter needed `out_waiting` and bounded closure corrections**; verify read-only ROM entry/exit before writes.
6. **No repetitive probing by flash.** One failed pilot is enough to require evidence-driven correction.
7. **Keep firmware credentials/IEEE/full-flash/key material private**. Public GitHub stores bounded geometric evidence, hashes and outcomes only.
8. **Rollback success and R4 failure are distinct outcomes.** The deliberate process failure `R4_FIRST_BOOT_FAILED_AND_STOCK_RESTORED` is correct reporting.

## Forward plan (priority order)

**P0 — stop/retain stable state.** Original firmware is running. Keep verified two-pass backups and immutable incident log. No additional R4 writes, no production changes. Mark PR draft/release receipts NOT FLASHABLE.

**P1 — fitted signed-boot policy offline.** Parse the original header/TLV via pinned upstream MCUboot tooling; statically trace actual resident loader's signature and image-validation path; verify original ECDSA with the bootloader's trusted public key if recoverable; check image slot, security counter, version, signed payload boundaries. Add a fail-closed unsigned-package gate.

**P2 — preferred signing route.** Contact the legitimate SMLIGHT signing custodian for an authorized developer-signed R4 image, signing service or approved development workflow. Build image with correct 0x80 header, slot bounds, digest and ECDSA signing parameters. Verify independently against the *installed trusted key*. Never expect a newly generated key to work without a correspondingly re-provisioned bootloader.

**P3 — bounded re-pilot only if P2 is proven.** Verify stock `SYS_PING`, 23 CRC originals, two-pass complete backup, protected loader/CCFG, ROM BSL exit. Only flash hash-pinned signed app-only HEX; validate signed startup, `SYS_PING`, `SYS_VERSION`, UART, identity/NV, uptime and isolated routing. Automatic exact-stock rollback on any failure.

**Fallback if vendor signing impossible:** separately engineer an owner-controlled signed MCUboot on *replaceable, independently recoverable* spare hardware while keeping CCFG; replacing `0xAC000` is riskier. Changing CCFG to direct boot bypasses the existing signed-boot policy and requires a different risk/security decision; it is not the selected safer route.

## Absolute stop conditions

No more unsigned R4 physical flashes, arbitrary ECDSA keys, copied vendor signatures, high-level flasher bank erase, boot-stage/CCFG writes, production MR4U intervention or exposing private images in CI.

### Definitive console markers

```text
ROM_PREFLIGHT_PASS stock_sector_crc=23/23 boot_ccfg_protected=2/2
R4_APP_SECTOR_WRITE_VERIFIED 23
R4_ZNP_NO_PING_AUTOMATIC_EXACT_STOCK_ROLLBACK
RESTORE_ORIGINAL_BYTES_WRITTEN 22
STOCK_RECOVERY_SYS_PING_PASS
RuntimeError: R4_FIRST_BOOT_FAILED_AND_STOCK_RESTORED
```

**Incident trace:** [issue #103](https://github.com/analienx/Zigbee-Coordinator/issues/103#issuecomment-6237649355). **Draft branch:** [PR #132](https://github.com/analienx/Zigbee-Coordinator/pull/132#issuecomment-6237650022). **Physical pilot ended in successful recovery, not deployment.**