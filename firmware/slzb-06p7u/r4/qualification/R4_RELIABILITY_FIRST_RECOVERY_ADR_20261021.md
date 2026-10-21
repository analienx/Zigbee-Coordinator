# R4 architecture decision — reliability first, backup-led recovery (21 October 2026)

**Decision:** Redirect P0 from incident-specific in-place NIB rescue to preventing repeat network loss. A deliberate network-state re-provisioning from a proven complete backup is the preferred current-incident recovery *if and only if* backup coverage, counter floors and the real P7U restore path are verified. No assumption that a firmware reflash alone restores Zigbee NV. No hardware/HA action authorized by this ADR.

## What the captures actually establish

The stock 20260311 P7U uses exactly four 8192-byte NVOCMP pages at 0xA4000..0xABFFF; the live incident contains an inactive CRC-valid original 116-byte NIB and destructive STARTUP_OPTION=0x03. The sole missing active identity is NIB. All NWK/TC identity/key material observed in the private comparison survived, while 104 of 300 TC table entries advanced outgoing frame counters (at most 11) and none regressed. This is not evidence that ordinary firmware compaction lost arbitrary records. The 10.9.1 herdsman **restore strategy's** destructive sequence is source-proven, but the initial trigger of that strategy on this radio is not proven. Do not misattribute all R4 startup HOLD symptoms to flash media corruption.

## Recovery options, ranked by *proof*, not by code size

1. **Clean Zigbee-NV provision from a verified, complete Z-Stack coordinator backup** under a one-time, explicitly authorized restore mode, while preserving factory CCFG, current IEEE identity, resident boot manager and all non-Zigbee sectors. Requires actual current-backup validation: PAN, extended PAN, channel, key/epoch, NWK counter, TCLK seed and per-device link-key/TCLK coverage against active device population. The stock ZNP may be a safer bootstrap than unqualified R4. Do not start unmodified herdsman automatically against inconsistent semi-provisioned NV.
2. **Full *known-good NV-region* restoration** only with an audited exact-geometry, stock-version-compatible private snapshot and a proven security counter forward-reconciliation policy against the later live capture. A historical 704-KiB readback or an old TCLK blob cannot simply be replayed. Retain the snapshot as fallback even if option 1 succeeds.
3. **Narrow two-record in-place NIB repair (draft PR #141)** only as fallback if backup completeness cannot be established and native crash-safe write behavior is qualified. This cannot be the primary firmware architecture or an excuse to retain incident-specific startup automagic.

**Never use whole-chip erase.** 0xAC000..0xADFFF is a resident executable boot manager, 0xAE000..0xAFFFF contains boot/CCFG, and stock 20260311 uses an MCUboot-signed app while no signing private key is available. The only candidate intentional erasure for a clean network reprovision is the *four verified NV sectors*, with the boot/CCFG/identity/BSL/APP restore path independently admitted. Distinguish application reflash (normally NV-preserving), deliberate NV reset, and destructive global erase.

## The actual firmware P0: suppress the class of failure

### P0-A: non-destructive network identity + explicit provision state machine

- **ESTABLISHED:** valid commissioned coordinator/NIB, PAN/E-PAN/channel, NWK security material and TCLK/TC invariants. Normal valid application/network/TCLK counter updates continue. Startup always attempts resume; never auto-factory-reset, delete NIB, execute clear-state/clear-config startup option, or form a second network just because an NV read fails.
- **RECOVERABLE_NV:** only documented TI NVOCMP journal transitions where complete original identity/security data are independently verified and recovery is supported by source-backed copy-on-write semantics. Permit narrowly bounded legitimate journal completion; do not blanket-deny recoverable boot-time writes. On unsafe/unknown structure, switch to HOLD.
- **HOLD:** malformed or ambiguous NV/security; radio network formation and destructive commands denied, read-only diagnostic available, no watchdog reboot/reset loop. Normal transport errors must be distinguished from persistent NV corruption. No automatic speculative key/counter repair.
- **EXPLICIT_RESTORE:** intentionally blank four-page Zigbee NV and a separately validated immutable backup/network identity, **one-time operator activation only**. Permit required TI first-format and herdsman Z-Stack backup replay; lock provisioning immediately after verified coherent formed state. A compile-time permanently enabled factory flag is not enough; restore needs an auditable one-shot admission mechanism.
- **VIRGIN_NEW:** truly empty never-provisioned coordinator, with explicit user authorization if a new network is intended. Presence of keys, configured marker, BDB, TCLK seed or saved backup invalidates virgin classification. Do not let 'NIB absent' mean virgin.

Defense in depth: apply sensitive-mutation policy in firmware's ZNP/NV entrypoints *and* the existing pinned herdsman #140 host guard. For formed networks reject NIB deletion, STARTUP_OPTION 0x03, factory clear and destructive commissioning before any flash mutation; legitimate NV updates (including counters and compaction) must not be globally blocked. Host #140's 'virgin/no-backup only' branch must be amended for the controlled **blank-with-backup** restore case or it will deadlock option 1.

### P0-B: flash/journal reliability, not universal HOLD

- Do not invent a second general NV database implementation. Keep pinned genuine TI NVOCMP with correct P7U 4-page A4000 geometry, stock-compatible record semantics and CRC.
- Audit and narrowly fix: page transition invariants, compaction interruption recovery and error paths; no destructive `NVOCMP_RECOVER_FROM_COMPACT_FAILURE` reformat; no false-success on NVS read/write/verify or low-voltage flash write; no status/header acceptance caused by OR in place of AND.
- On boot, classify `HEALTHY / RECOVERABLE_JOURNAL / UNSAFE`. Prove that acknowledged writes remain recoverable at every NOR interruption boundary; do not promise availability for truly corrupted media. The existing synthetic compaction harness exercises tiny synthetic tables, not the real 779-active-record / 300-TCLK-table workload. Focus qualification on this representative occupancy, normal churn and compaction; avoid another general test expansion.
- Monotonic NWK, APS and TC outgoing counters are independent security requirements. Fresh restore must set outgoing floors ahead of all previously transmitted frames, using independently proven existing-record or backup values and conservative non-overflow reservation. Herdsman's +2500 during backup restore is a policy in source, **not** proof it covers an arbitrarily old backup or all per-device entries.

### P0-C: reversible release boot and host behavior

- The boot topology is part of reliability: MCUboot signed app + resident AC000 stage + protected top/CCFG. Preserve exact CCFG and loader and do only preverified sector allowlist writes; a binary that compiles but cannot reach ZNP is a failure.
- Target the **current stock 20260311** geometry, never historic A6000..ADFFF. Current R4 draft contains incident-specific rescue code but does not establish production boot, native NV power-fail operation, authenticated state9 or RF stability.
- Keep Z2M stopped during intentional recovery. Verify write/readback and boot identity, then allow only one host owner and one bounded Z2M start. Normal Z2M's backup replay must not be allowed to begin accidentally against retained network evidence.

## Minimal evidence to decide backup-led reset versus fallback

1. Offline compare private `coordinator_backup.json`, Z2M `database.db` and source capture **without publishing keys**: same coordinator IEEE, E-PAN, PAN/channel, active NWK key/sequence, NWK frame counter and all required live 104+ TCLK/link-key entries. Report counts and missing identities, not bytes.
2. Determine latest observed NWK/APS/TCLK counter floors from the live capture. For each restored *outgoing* security context, use a verified advanced value; fail on overflow, missing floor or backup age incompatible with a safe bound. Preserve RX replay protections as appropriate; blindly adding a constant to all counters is not a proof.
3. Prove from pinned TI/native/herdsman code that a clean 4-page-only NV reset can be provisioned using the signed-stock boot chain, and that the protected host explicit-restore branch can replay the backup and return to ESTABLISHED.
4. Only one representative GH-hosted deterministic clean-restore integration plus populated-NV power-cut qualification (and native reproducible flash image). One controlled real boot + Zigbee end-device/router traffic and passive stability observation after.
5. If any gate fails, **do not erase**. Preserve current captures and use the ranked fallback rather than blindly starting commissioning.

## Priority disposition

- **Now:** P0-A (network identity gate and one-shot restore path), P0-B (normal runtime reliability under healthy/high-occupancy NV, compaction and counters), P0-C (real boot chain and host compatibility).
- **Demote:** PR #141's inactive-NIB source re-append to *fallback-only draft*, no premature merge or flash. It is useful research but not the fix for recurring startup loss.
- **Retain:** PR #140 host nondestructive containment, but adapt it for explicitly authorized blank-with-backup restoration.
- **Do not expand scope:** routing/capacity tuning comes **after** basic network continuity and startup reliability.

## Public technical anchors

- Original incident: issue #139; original NIB rescue: PR #141; host guard: PR #140; R4 core issues #136/#137.
- TI source: `TexasInstruments/simplelink-lowpower-f2-sdk` commit `3615ad5`, `source/ti/common/nv/nvocmp.c`.
- Zigbee2MQTT FAQ, firmware update/backup limits: https://www.zigbee2mqtt.io/guide/faq/
- Zigbee-herdsman Z-Stack backup restore code (per-device TX and NWK counters, +2500 and device records): https://github.com/Koenkk/zigbee-herdsman/blob/master/src/adapter/z-stack/adapter/adapter-backup.ts
- TI Z-Stack security state and persistent counters: https://software-dl.ti.com/simplelink/esd/simplelink_cc26x2_sdk/2.30.00.34/exports/docs/zstack/html/zigbee/z-stack-overview.html
- Historical TI interruption caution: https://e2e.ti.com/support/wireless-connectivity/bluetooth-group/bluetooth/f/bluetooth-forum/873501/

**Status: design decision only; no image flashed, no coordinator/HA modification, no backup verified during this ADR.**
