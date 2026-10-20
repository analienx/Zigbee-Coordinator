# P7U R4 P0: non-destructive herdsman startup containment

2026-10-20. Exact zigbee-herdsman **10.9.1**, commit **0968f979d558874b17396c96b66382d4236bbdcd**, used by Zigbee2MQTT **2.14.0**. This is an offline source overlay and GitHub-hosted compilation/test gate. It does not install software on HA or access the coordinator.

## Source-confirmed failure path

When the NIB/configured marker is absent, the pinned determineStrategy() can select restoreBackup when a backup matches configuration. beginRestore() first calls beginCommissioning() on a randomly generated provisioning network. beginCommissioning() invokes deleteItem(NIB) and clearAdapter(), which writes STARTUP_OPTION=0x03 and requests a ZNP reset. This can damage the saved network before backup replay. The initial cause of the first bad read/strategy on this particular radio remains unproven pending earlier debug logs.

## New startup contract

| Evidence | Action |
| --- | --- |
| Existing coherent configured NIB, PAN/extended PAN and keys | Resume existing network; no commissioning |
| NIB absent with backup, configured flag, active/alternate key, Trust Center record, BDB network-state or TCLK seed | HOLD before deleting NIB, setting startup flags or resetting |
| Configuration mismatch, incomplete NV read, or transport error | HOLD |
| Startup-option clear-state/config or frame-counter reset bit is present | HOLD |
| Truly virgin: no NIB, configured marker, backup, key or Trust Center evidence; no pending clear | New-network commissioning with single-use token |
| Direct or repeated destructive call without virgin token | HOLD |

Backup-based recovery is still possible only through separately reviewed, explicit offline recovery. This intentionally disables automatic restoration of a replacement coordinator. It does not suppress normal startup of coherent existing networks.

## Separate firmware/NV4 recovery gates

1. Preserve dual full-flash captures and compare current records with original 107-device backup and previous live captures privately. Check all NWK, TC keys, frame-counter maxima and page generations.
2. An inactive CRC-valid NIB is evidence, not authorization to toggle a flash validity bit. Verify TI NVOCMP record generation, page compaction, CRC and torn-power recovery on a cloned image; abort ambiguous cases.
3. Recover only verified original NIB and strictly necessary metadata, retaining newer security state and monotonic counter values. Independent offline reparse and security consistency are mandatory before boot.
4. Keep firmware HOLD_NV until complete original-network admission passes. If app updates are necessary, use GitHub Actions and only qualified APP/AC000 sectors; no collateral NV, CCFG or bootloader writes.
5. Issue #139 and draft PR #136 remain open. This patch executes no HA startup, mode switch, serial open, ROM BSL action, network formation, re-pair or flash.

References: [upstream herdsman pinned manager](https://github.com/Koenkk/zigbee-herdsman/blob/0968f979d558874b17396c96b66382d4236bbdcd/src/adapter/z-stack/adapter/manager.ts), [TI ZNP startup bits](https://software-dl.ti.com/simplelink/esd/plugins/simplelink_zigbee_sdk_plugin/2.20.00.06/exports/docs/zigbee_user_guide/html/zigbee/developing_zigbee_applications/znp_interface/znp_interface.html).
