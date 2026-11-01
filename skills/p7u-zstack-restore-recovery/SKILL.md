---
name: p7u-zstack-restore-recovery
description: Recover the existing 107-device Zigbee2MQTT network on the single SLZB-06P7U CC2652P7 after stock or R4 APP-only flashing. Use for completed NV restoration followed by stalled ZDO/BDB startup, board-specific firmware/CCFG, USB-versus-Ethernet ownership and secure R4 handoff.
---

# SLZB-06P7U existing-network restore and R4 handoff

> **Historical (20 October 2026 stock-firmware incident).** The production P7U has since moved to R4 firmware over USB, and runs **V53 under the official Zigbee2MQTT app since 31 October 2026** ([status](../../coordinators/slzb-06p7u/STATUS_2026-10-31.md)). The Ethernet transport, the stock `20260311` boot-layout block and "STOP APP-only R4 flashing" below describe that earlier state. Keep the invariants and the restore-versus-startup distinction. For a hang on the current firmware use [p7u-rom-bsl-recovery](../p7u-rom-bsl-recovery/SKILL.md) and the [runbook](../../coordinators/slzb-06p7u/HANG_RECOVERY_RUNBOOK.md).

Scope this procedure to the household's **one** SLZB-06P7U (not MR4U/P10). Review [R4 hardware #103](https://github.com/analienx/Zigbee-Coordinator/issues/103), [B3 security #97](https://github.com/analienx/Zigbee-Coordinator/issues/97) and [R4 review #137](https://github.com/analienx/Zigbee-Coordinator/issues/137) before work. The [P10 recovery skill](../p10-zstack-restore-recovery/SKILL.md) offers a **comparison** for BDB mode 0 but its MR4U/USB radio details are not applicable.

## Invariants

1. Preserve the original `coordinator_backup.json`, `database.db`, cold evidence, and unmodified encrypted/private captures. Never publish network keys, device inventory/IEEE identities, HA secrets or raw NV.
2. Do not delete backups, re-form the PAN, re-pair devices, rotate network keys, issue BDB mode `0x04`, or repeat a restore solely because the **post-write network startup** timed out.
3. Stop Zigbee2MQTT and enforce a single ZNP client. The add-on's **USB** serial options do not prevent a separate, bounded **Ethernet** ZNP diagnostic on `tcp://192.168.50.59:6638` (observed 2026-10-20); keep HA USB settings unchanged until a deliberate final transport handoff.
4. Do not add manual TX-counter safety margin. Zigbee-herdsman 10.9.1 already restores extended NWK security material to `backup.frameCounter + 2500`. Never rewind past a counter emitted by any live holder of this network identity.
5. Use the versioned `firmware/slzb-06p7u/r4/release/rom_writer/` only when its **boot-layout gate passes**. The current vendor stock layout **does not pass**: do not bypass its CCFG gate or perform an APP-only R4 flash. Require a separately reviewed, explicitly authorized boot-layout migration first; retain private images/dumps outside Git worktrees.

## Physical evidence: 2026-10-20

- Operator manually flashed board-matched **SMLIGHT P7U stock 20260311**; `SYS_VERSION` shows product 1/revision `20260310`. Generic Koenkk `20250321` APP-only image previously failed to boot with the then-observed P7U CCFG. SMLIGHT `20240716` matched the earlier 88-byte CCFG; do not assume its contents after manual flashing without readback.
- Original coordinator backup SHA256: `8609d816976863702517d82bc80597b082e741e70747e008c0854b6c802f8de4`; **107 devices**, PAN `0x45A1`, channel 11. Re-validate backup hash and secret fingerprints locally before changes.
- A restore-only zigbee-herdsman **10.9.1** run completed provisional commissioning and `AdapterBackup.restoreBackup()` NV writes. The subsequent `ZDO_STARTUP_FROM_APP` timed out after **40 seconds**, leaving ZNP unresponsive. Reviewed **ROM-BSL reset-only** (no erase or download) brought normal ZNP back.
- Typed read-only ZNP/NV confirmed original NIB PAN/extended PAN/channel, coordinator IEEE and active NWK key; `BDBNODEISONANETWORK=1`, NIB NWK state 8, `UTIL_GET_DEVICE_INFO` state 0/short `0xFFFE`. The extended NWK security-material table already contained the upstream restored counter `350308152` (source +2500).
- Upstream restore did **not** update aligned legacy `ZCD_NV_NWKKEY` (ID `0x82`, 24-byte sequence/key/padding/counter) or `ZCD_NV_TRUSTCENTER_ADDR` (ID `0x71`, 8-byte coordinator IEEE). Both were stale. Exactly **two guarded NV writes** reconciled those logical records to the pinned backup and the **existing** extended-material counter, adding no new margin. Both readbacks verified.
- One deliberate **non-forming** `APP_CNF_BDB_START_COMMISSIONING(mode=0x00)` attempt on the stock firmware also **timed out at 40 seconds waiting for SRSP**. No coordinator state 9, production radio function or device traffic has been demonstrated. Do not repeat mode 0 blindly or generalize P10's successful Ethernet incident to P7U.
- A new **complete 704 KiB live ROM capture**, with ROM CRC match and duplicate reads of all four NV4 sectors, revealed the stock image's fundamental boot layout. Its `CCFG.IMAGE_VALID_CONF` is **`0x000AC000`** (formerly **`0x00000000`**), with a valid Cortex-M initial SP/reset vector at `0xAC000` but **not** at `0x00000`. The other CCFG bytes match the older capture (two changed bytes in the 88-byte region). TI documents such values as redirects to a boot image manager. The versioned R4 APP-only writer rejected the stock layout with `INSTALLED_ROM_VECTOR_NONZERO_NOT_QUALIFIED`; a separate fresh-BSL writer attempt was aborted **before any flash erase/write**. Changing this protected CCFG field requires erasing/reprogramming the last sector and possibly reassigning `0xAC000` (now boot code) to R4 NV4; this exceeds the APP-only preservation contract. Do not silently relax the guard.

## Decision procedure

1. With Zigbee2MQTT stopped, identify physical board, actual transport, firmware and one ZNP owner. Prefer a typed `Znp` client over raw MT frames. If unresponsive after a failed startup, choose a separately reviewed bounded ROM-BSL **reset-only** operation; never use flashing as an incidental reset.
2. Read back the protected backup identity plus NIB, extended NWK security material and counter, active/alternate key fingerprints, logical `NWKKEY`, trust-centre address, BDB on-network flag, coordinator IEEE, populated address/TCLK tables and normal UTIL state. Publish booleans/counts, not secrets.
3. Distinguish **`restoreBackup()` completed** from subsequent **`startupFromApp` failed**. A final startup timeout does not authorize another blind full restore.
4. Correct missing logical security records only with exact verified backup, ext-table counter, memory-alignment/length and IEEE guards. Require readback of each changed record. The 2026-10-20 alignment matched the upstream +2500 counter; this was **not a manual additional increment**.
5. **STOP APP-only R4 flashing on stock 20260311.** The current boot ROM selects address `0xAC000`, while R4 expects its vector at zero and NV4 uses the upper pages. Moving to R4 requires either a vendor-boot-manager-compatible signed/rebased package proven against the captured image, or an explicitly approved high-risk CCFG/upper-sector migration with verified restore of the production security state and ROM-BSL rollback. Do not rewrite CCFG or erase `0xAC000` under the existing APP-only authorization. Confirm the final boot strategy and rollback before programming.
6. For R4, require B1 no HOLD_NV, `ZDO_STATE_CHANGE_IND=9` (coordinator) or equivalent verified UTIL state, continuous SYS liveness, identical PAN/extended PAN/key/security state, then a post-restart check. An SRSP by itself is insufficient.
7. Only after live coordinator acceptance attach Zigbee2MQTT on the verified transport, changing **both Z2M YAML and HA add-on serial options** only when necessary. Verify inbound/outbound unicast, groups, metering and representative routing. Keep unavailable devices distinct from a coordinator startup failure.

## Sources and security notes

- [Zigbee-herdsman Z-Stack NV restore](https://github.com/Koenkk/zigbee-herdsman/blob/master/src/adapter/z-stack/adapter/adapter-backup.ts) does not write the legacy `NWKKEY` and `TRUSTCENTER_ADDR` records; reconcile only after independent hardware readback.
- [ZNP command definitions](https://github.com/Koenkk/zigbee-herdsman/blob/master/src/adapter/z-stack/znp/definition.ts) distinguish `ZDO_STARTUP_FROM_APP` and `APP_CNF_BDB_START_COMMISSIONING`. Avoid `mode=0x04`, which forms a network.
- Record source commit, writer version, private image SHA, reset context, actual state change and blocked acceptance gates in GitHub issues. Never claim network recovery based solely on NV writes, a live SYS ping or a provisional network.
