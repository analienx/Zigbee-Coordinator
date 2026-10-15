# P10 → SLZB-06P7U: real pre-flash inspection (15 October 2026)

**Status: SOURCE-ONLY / NOT RESTORE READY / NOT FLASHABLE.** These are observed
findings, not assumptions that P7U has been flashed, made to join the household
mesh or has a qualified fallback. The active source remains the *P10*
coordinator network, even though its current USB radio is not plugged into HA.

## Verified target and current Home Assistant situation (read-only)

- HA USB sysfs identifies **SMLIGHT SLZB-06p7U** (`303a:4002`) at
  `/dev/ttyACM0`; it is our exact target model, NOT a plain SLZB-07 or the
  CC2674P10/MR4U radio. USB presence is not a TI wafer/ROM BSL readback.
- On 15 Oct, HA's Zigbee2MQTT container was **Exited (1)**, EMQX healthy,
  OTBR stopped, and no process owned `/dev/ttyACM0`. Zigbee2MQTT YAML still
  referenced the previously connected MR4U/P10 `if02`, not the new P7U.
  **No HA YAML, add-on options, USB mode or services were changed.**
- An explicitly bounded **SYS_PING only** read-only probe through exclusive
  Linux tty returned no SRSP within 3 seconds; no SYS_VERSION or SYS_GET_EXTADDR
  followed, no NV/BSL/erase/reset/flash command issued. RTS/DTR were requested
  deasserted after opening; cannot independently exclude initial CDC line
  effects. Therefore the **stock radio ZNP/version/IEEE remains UNVERIFIED**.
  Follow-up must determine whether SLZB-OS is presenting the correct radio
  bridge / Zigbee mode, and prove ROM bootloader recovery with same-device
  backup before doing any app-sector write.

## P10 backup authority, verified against actual HA filesystem

**Source archive (private only):**

`C:\Workspace\.analienx\sonoff-private\recovery\p10-candidate-2026101104\z2m-cold-before-coordinator-switch-20261013-0808CEST.zip`

- ZIP SHA256 `27072c521cb8bf3aec2fa2b0bbfaca592f8e97bb5b4cc17eca358b1c1411682e`;
  ZIP integrity **PASS**.
- Its canonical `data/coordinator_backup.json` SHA256
  `6907949caf3b3d3f8c667fc59fdf66aabdf77f34f200be554a62eeeac17c6338`,
  byte-identical to **HA current** `/homeassistant/zigbee2mqtt/coordinator_backup.json`.
  Archive saved on 13 Oct but its HA backup itself has mtime 12 Oct
  21:29:19 UTC. *Neither filename nor mtime proves an on-chip 15-Oct counter.*
- Backup **106 devices / 106 link keys**, Zigbee channel 11, NWK frame
  counter **350126153**. HA matches the archive's `configuration.yaml`
  SHA256 `b8282f224639d225d558cedfb09b8c1021f3b50abc905c8d00f4818d596026eb`
  and `database.db` SHA256
  `71324101658bdafa25a70eea93c809997c8a6db940fa13eabb20a28bb07eebf7`.
  The 106 active database devices comprise 59 routers and 47 end devices;
  the DB also contains historical/other entries.
- Three active DB IEEE records are **missing from the coordinator backup**:
  one router, two end devices. The public report deliberately omits their
  IEEE/friendly names. Three other coordinator-backup security entries are no
  longer in the DB. Device coverage is **NOT a clean 106/106 match**, even
  though both totals happen to equal 106.
- An older Aug 2026 backup retained a historical link key for the missing
  router, but no current proof that this key remains valid. The two missing
  end devices did not have a usable key record in the checked archives.
  **Never graft old keys into the new authority without independent proof.**

## Security counter high-water safety (offline, not applied)

- Current source NWK counter **350126153**. Historical P10 A1 postrestore
  snapshot (10 Oct, failed ZNP startup later) has **350305652**: *179499
  higher*. Treat it conservatively as a floor pending live/radio reconciliation,
  despite not proving the higher counter was ever transmitted over the air.
- With the historical authority plus the Oct12 archive, **99** current
  same-key devices require link TX counter floor adjustments before applying
  a standard Herdsman restore. Five historical key comparisons differ; the
  latest actual P10 source retains ownership of active keys, with no silent
  substitution. No historical RX counter exceeded the latest in same-key rows.
- Herdsman 10.9.1 restore adds **2500** to backup NWK and link-key TX
  counters. For an offline plan, baseline the input counter at the maximum
  historical same-network value, yielding a planned postrestore network
  floor **350308152**. This is a planning floor, NOT actual device state.
- New host-only `p7u_p10_migration_authority.py` verifies the pinned
  source SHA, exact live `data/` members (rejecting stale nested backups),
  ZIP CRC, strict backup schema, network/TCLK identity, database membership,
  historical key conflicts, counter maxima and overflow. It never touches
  HA or a radio, prints only hashes/aggregates, and returns
  `restoration_authorized=false` / `flash_authorized=false`.
  Optional counter-floor derivative, if explicitly staged into the existing
  private workspace, is called **NOT_RESTORE_READY** and never replaces the
  source ZIP. This is not an automatic restore operation.

## Remaining action gates, in order

1. Qualify SLZB-06P7U **stock ZNP vs USB bridge** (the first stock SYS_PING
   timed out). Use the board-specific vendor USB/LAN mode with a single owner;
   prefer isolated access on Zephyrus only after radio/bridge mode is understood.
2. Obtain **actual same-device readback** of stock application, CCFG, IEEE
   and **all relevant NV2/NV5 bytes**, verify repeated read CRC/hash plus
   off-device private preservation; prove ROM BSL access/reentry. The logical
   P10 network backup cannot substitute for physical P7U recovery material.
   The new opt-in `p7u_original_radio_escrow.py` implements full 704-KiB
   **read-only** ROM capture with per-8-KiB double ROM CRC32, device identity
   and CCFG consistency, private exclusive file + seal and a synthetically
   tested fail-closed path. **It has NOT been run on physical hardware.**
   Entering ROM BSL through authenticated board management may reset the
   spare radio and requires an additional explicit flag; without proven
   board-specific BSL and recovery it must not be run blindly. The
   pre-existing stock-app rollback mechanism is not a substitute for this
   independent original-state preservation.
3. Determine real blank state of the five NV5 sectors
   `0xA4000/0xA6000/0xA8000/0xAA000/0xAC000` while keeping the CCFG
   sector `0xAE000` strictly protected. The existing writer must continue
   to refuse nonblank initial NV5; no automatic erase or bank erase.
   New `p7u_nv5_preservation_plan.py` validates the **actual private 704-KiB
   same-device image and readback receipt** (whole-flash SHA, every sector
   hash, factory silicon/CCFG readback, all five sectors individually),
   then emits a no-secrets, per-sector preparation and original-NV2 rollback
   evidence document to a private location. Synthetic negative tests cover
   tampered image/receipt/sector/CCFG/identity and nonblank-to-blank
   misclassification. It contains **no code path for sector erase**.
   Actual nonblank NV5 remains a release blocker until target-specific,
   reviewed and approved preparation plus rollback are physically proven.
4. Resolve the **3 missing DB security records** (especially the router),
   verify latest actual P10/source on-air security counters if available, and
   prepare sealed high-water-adjusted private restoration material only
   after the active coordinator is quiescent. No same-IEEE simultaneous PAN.
5. With the above proven, independently qualify a source-matched R2
   application and same-ROM stock rollback pair, then a controlled spare
   pilot for native F0 diagnostics, RF, restart and multi-hop routing.
   **Never use the stock SMLIGHT flash CLI's bank-erase path.**

The new optional extension and the current PR #82/#83 must remain draft
until their own hardware acceptance is complete. Firmware software CI does
not assert that the single physical P7U can always be recovered.


## Later 15 October update — physical R2 first flash completed

The preceding sections are a dated *preflash* snapshot, not the final P7U state.
Later on 15 October the operator captured all 88 sectors of the stock 20240316
radio, preserved an independently verified copy off-device, and performed the
approved NV5 five-sector preparation (three sector erases; all five blank).
A fresh post-NV5 R2 plan then programmed all 23 application sectors, verified
each by ROM CRC, and preserved the full CCFG sector. Installed candidate HEX
SHA-256: 16837972afeb3a502e03505e2998c5d2b2b8a1ce61ce91450f5999e175e908de.

The management radio-restart command was acknowledged; bidirectional ZNP
boot and SYS_VERSION are still unverified. The postboot read-only probe was
blocked at platform pre-dispatch. Do not evade that refusal via other transports.
No network restoration, Zigbee2MQTT startup or production migration has occurred.

The latest offline missing_device_triage extension is private-only and identifies
per-device remediation for DB members missing a coordinator security record.
Historic key presence is not proof of validity and cannot authorize silent
key insertion. Missing entries may require controlled rejoin/re-pair after
verified radio boot, source-network quiescence, safe counter floors, and a
validated restore plan. This remains a DRAFT / NOT RESTORE READY PR.
