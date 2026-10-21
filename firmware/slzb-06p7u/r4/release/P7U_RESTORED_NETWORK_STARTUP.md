# P7U restored-network startup — 2026-10-21

The original 107-device network is **already restored in the single SLZB-06P7U stock coordinator NV**. The latest owner report verifies PAN, channel, extended PAN, active key, IEEE, Trust Center, NIB (116B, nwkState=8) and BDB on-network=1. The live network-specific counter is 350310652, above the initial post-restore value 350308152. Preserve the current value; do not replay the older backup or add a manual margin.

Both upstream zigbee-herdsman `ZDO startupFromApp` and a separate `APP_CNF BDB startCommissioning(mode=0x00)` hung synchronously for 40 seconds on stock. After reset-only recovery, ZNP is alive with device state **0**, not coordinator state **9**. Zigbee2MQTT must stay stopped. Do NOT reflash, re-erase, re-restore, form a PAN, or repair NIB again.

TI `mt_zdo.c` calls `bdb_StartCommissioning(NWK_FORMATION)` for coordinator on `ZDO_STARTUP_FROM_APP`. TI `bdb.c` invokes `ZDOInitDevice()` on first BDB initialization and `zd_app.c` restores NWK state and NWK security tables. **Both commands share this stack initialization path; replacing ZDO with BDB0 is necessary for non-forming startup but NOT sufficient to resolve the observed hang.**

## Review corrections and implemented firmware behavior

- The 106/107 discrepancy is a filtering detail: all 107 backup addresses are present; one row has no active user flag. It does not establish a lost device.
- Herdsman 10.9.1 prints TCLK, APS and security-table `usedCount` under the label `capacity`. A reported TCLK capacity 0 therefore does not prove missing allocated rows. Standard restoration writes unused rows too; no speculative relaxation of key/seed validation follows from this log.
- The retained MT ZDO entry requires admitted NV, cached full security validation, exact NIB and marker lengths, coordinator role and startup option 0. It invokes BDB0 only, and reports failure if initialization latches HOLD. Native qualification requires the actual guard in `mt_zdo.o`, not a reduced source fixture.
- Startup now propagates NV/security failure through `ZDApp_RestoreNetworkState`, `ZDOInitDeviceEx` and BDB. An explicit HOLD result cannot fall through to TI's new-network branch that clears `bdbNodeIsOnANetwork`. Guards after globals, NWK restoration and void security initialization stop network publication after failure.
- On the real coordinator transition with validated security and durable counter reservation, firmware publishes `ZNP_HAS_CONFIGURED_ZSTACK3=0x55` with readback. An existing correct marker is a no-op; a one-byte unconfigured value is completed without restoring network data. Wrong size or an unsuccessful read/commit holds startup. Ordinary Zigbee2MQTT needs no permanent HA/Herdsman fork. The optional protected host bundle remains diagnostic tooling.

## Remaining evidence boundary

The two stock timeouts do not identify an exact blocking function. Counter advancement is consistent with reaching NWK counter reservation; it does not prove that `NLME_RestoreFromNV` itself hung. The later path includes security-manager initialization and closed TI library code. These source fixes close confirmed R4 error-propagation and compatibility defects; they are not a demonstrated cure for the stock binary's hang.

Use exact-source GitHub-hosted native builds. Later physical acceptance requires healthy F1, actual `DEV_ZB_COORD=9`, continuous ZNP, identity/key/counter continuity and representative traffic. On the existing Ethernet path, a separately approved one-time retained startup precedes USB return and ordinary Zigbee2MQTT startup. No device operation is performed by these changes.

Upstream: TI SimpleLink CC13xx/CC26xx Z-Stack (mt_zdo.c, bdb.c, zd_app.c); zigbee-herdsman 10.9.1 ZNP adapter manager. Source and log findings are in issues #139 and #136.
