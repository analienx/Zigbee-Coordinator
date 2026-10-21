# P7U restored-network startup — 2026-10-21

The original 107-device network is **already restored in the single SLZB-06P7U stock coordinator NV**. Verified PAN 0x45A1, channel 11, extended PAN, active key, IEEE identity, Trust Center, NIB (116B, nwkState=8), BDB on-network=1, and security table with Herdsman's original backup frame counter +2500. No additional counter margin was applied.

Both upstream zigbee-herdsman `ZDO startupFromApp` and a separate `APP_CNF BDB startCommissioning(mode=0x00)` hung synchronously for 40 seconds on stock. After reset-only recovery, ZNP is alive with device state **0**, not coordinator state **9**. Zigbee2MQTT must stay stopped. Do NOT reflash, re-erase, re-restore, form a PAN, or repair NIB again.

TI `mt_zdo.c` calls `bdb_StartCommissioning(NWK_FORMATION)` for coordinator on `ZDO_STARTUP_FROM_APP`. TI `bdb.c` invokes `ZDOInitDevice()` on first BDB initialization and `zd_app.c` restores NWK state and NWK security tables. **Both commands share this stack initialization path; replacing ZDO with BDB0 is necessary for non-forming startup but NOT sufficient to resolve the observed hang.**

Next: firmware-source review and fix of the shared restore path (`ZDApp_RestoreNetworkState`, `NLME_RestoreFromNV`, `ZDApp_RestoreNwkSecMaterial`) with a retained-only entrypoint. Use GitHub CI for candidate builds. A hardware pass requires `DEV_ZB_COORD=9`, matching security identity and actual device traffic. No production HA fork or custom Herdsman component is planned; normal Zigbee2MQTT is allowed only after the live coordinator reaches state 9 and its configured marker is consistent. Missing Herdsman `ZNP_HAS_CONFIGURED_ZSTACK3` can otherwise select destructive automatic beginRestore.

Upstream: TI SimpleLink CC13xx/CC26xx Z-Stack (mt_zdo.c, bdb.c, zd_app.c); zigbee-herdsman 10.9.1 ZNP adapter manager. Source and log findings are in issues #139 and #136.
