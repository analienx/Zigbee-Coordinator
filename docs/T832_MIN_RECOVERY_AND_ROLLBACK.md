# T832-MIN P10 — recovery kit and one-attempt rollback

**2026-10-10 | MR4U CC2674P10 | STATUS: OFFLINE PREPARED, NO FLASH PERFORMED**

This is the **practical** fallback for PR #49, not a new migration project.
Never place private bundles, network credentials, device identities, actual
factory IEEE or per-device keys/counters in GitHub.

## 1. Existing verified offline recovery kit

On the authorized Zephyrus:

`C:\Workspace\.analienx\sonoff-private\issues\p10-recovery-kit-20261010`

Private kit contents:
- `z2m-cold-20261006.zip`: independently verified quiescent/cold bundle,
  11,488,365 bytes; 361 Z2M files, complete add-on options, database,
  104 backup device entries including **103 real TC link keys** and counter
  fields; **21 Zigbee2MQTT groups**, 59 routers, 47 end devices.
  Use `recovery-kit.private.json` for the exact integrity hashes.
- `rollback-vendor-20240716.bin`: **actual vendor image used in the
  successful October 6 rollback**, 182,840 bytes, SHA-256
  `633f79058c39e2fc9335bb11f816ad6a045438515da11c36b30a46b7c8d1b7d9`.
  This is distinct from the experimental T832-R11 and T832-MIN HEX files.
- `z2m-hot-before-trial-20261010.zip`: **new read-only live HOT snapshot**;
  valid ZIP, 1,465 application files, add-on options, one external symlink
  dependency. **NOT atomic: never substitute for preflash cold capture.**
- The October 6 successful `verified.json` and accepted-health receipts,
  plus the historical tested restore source files (reference-only copies).
- `recovery-kit.private.json`: SHA/size manifest for the preceding files.

The October 10 hot archive's `coordinator_backup.json` is **byte-identical
to the October 6 cold backup**, while `database.db` and `configuration.yaml`
have changed. The coordinator-backup file alone must NOT be assumed to
represent the newest live on-chip transmit counters or post-October-6 joins.

**Historical proof:** October 6 vendor rollback reported management flash
success. Subsequent real ZNP verification observed firmware revision
`20240716`, coordinator state `9`, original network identity/key,
**103 restored link keys**, all 103 required address rows, and security TX
counter floors. The first passive mesh acceptance reported no live device
traffic; a later explicit device-query health check passed. Do not reinterpret
that as proof that every physical router was tested.

### Verify current offline kit (no radio or HA access)

From this repository's worktree in CMD:

```cmd
python deploy\p10_recovery_offline_gate.py --cold-bundle "C:\Workspace\.analienx\sonoff-private\issues\p10-recovery-kit-20261010\z2m-cold-20261006.zip" --vendor-firmware "C:\Workspace\.analienx\sonoff-private\issues\p10-recovery-kit-20261010\rollback-vendor-20240716.bin"
```

Expect `RECOVERY_ARCHIVE_VERIFIED_OFFLINE_NOT_LIVE`,
`cold_consistent=true`, `trust_center_key_records >= 103`,
`vendor_rollback.verified=true`. No files or network are changed.

## 2. One NEW snapshot at the actual trial boundary

**NOT executed yet.** This is the only freshness gate necessary before an
authorized physical flash. With the current network functioning:

1. Record Z2M device/group baseline and actual MR4U P10 transport, revision,
   coordinator state, identity and **on-chip** NWK/TC transmit-counter floors.
   The October 6 backed-up counters are not a substitute.
2. Stop the **Zigbee2MQTT add-on** under explicit authorization. Verify it is
   quiescent; keep every other coordinator carrying this network isolated.
   Do not change HA Core, MQTT, unrelated automations or MG26.
3. Create a uniquely named new full Z2M data bundle **after stop**:

```cmd
python deploy\p10_data_bundle.py capture --mode cold --out "C:\Workspace\.analienx\sonoff-private\issues\p10-recovery-kit-20261010\z2m-cold-before-trial-UNIQUE.zip"
```

Then verify the new bundle with the preceding offline gate, substituting its
actual path. Check keys >=103, network identity, refreshed application
database/config/add-on options and the external-symlink dependency. Use this
fresh cold file for every trial/rollback operation, never the old October 6
archive by default. If the capture or counter receipt is incomplete, **do not flash**.

## 3. Failure path A — firmware-only rollback (preferred)

The MR4U flash method must target the **CC2674P10 radio** (management index
`1`) and request **no NVRAM erase**; verify the existing flash procedure is
still applicable before the trial. The MG26 and ESP32 management firmware
must be untouched.

If the custom firmware fails:
1. Keep Zigbee2MQTT stopped. First distinguish lost radio response from
   lost network state. A soft/hardware P10 reset may suffice without any
   firmware or NVRAM rewrite.
2. If the custom code is unusable, reflash the validated vendor image **once**,
   preserving NVRAM, using the already versioned
   `deploy/p10_vendor_rollback_once.py` with a **new unique receipt folder**.
   This script pins the vendor image digest, verifies the target model/chip,
   requires a quiescent Z2M and verified cold bundle, uses `eraseNVM=0`,
   observes the firmware completion event and prohibits automatic retries:

```cmd
python deploy\p10_vendor_rollback_once.py --artifact "C:\Workspace\.analienx\sonoff-private\issues\p10-recovery-kit-20261010\rollback-vendor-20240716.bin" --cold-bundle "PATH_TO_FRESH_COLD.zip" --receipt-dir "C:\Workspace\.analienx\sonoff-private\issues\p10-recovery-kit-20261010\attempts\vendor-UNIQUE" --execute
```

**Do not run this example until flash is explicitly authorized.** A vendor
management completion event alone is not enough: verify raw ZNP
`SYS_PING`, `SYS_VERSION=20240716`, coordinator `state=9`, original
IEEE/PAN/extPAN/channel, on-chip security and counter floors.

If the original network is intact, **DO NOT RESTORE/RECOMMISSION**.
Simply return to the unchanged latest Zigbee2MQTT configuration/add-on
options and start the add-on; verify real unicast, groupcast and selected
router/end-device reporting. This is the lowest-risk path.

## 4. Failure path B — restore security only if NV/network is lost

The previously **executed** 2026-10-06 vendor restore is preserved in the
private kit. Its exact strategy is also carried forward into versioned
`deploy/p10_recover_original_network.py` and
`deploy/p10_recover_original_network.js`; no full restore has been executed
through the newly parameterized copy.

The script is deliberately **plan-only** unless given explicit
`--execute --approval RECOVER_ORIGINAL_ZIGBEE_NETWORK`. It performs one
Herdsman 10.9.1 restoration with unique local/HA attempt roots. Preconditions
enforced by the proven restore logic:
- Z2M completely quiescent, exactly one active P10 radio client.
- Vendor P10 has **unconfigured** state `0` and **no NIB**, with verified
  factory IEEE. If it is already in state `9`, **never** run this path.
- Backup SHA/104 devices/103 keys, network identity and active key match,
  all restored TX counters exceed independently recorded **current** floors;
  hard fail on overflow or mismatches.
- The Herdsman restore's single provisional `bdbStartCommissioning(mode=4)`
  is allowed **only on a blank/uncommissioned radio during this specific
  from-backup provisioning operation**. Never invoke network formation as
  a recovery action on an already-restored production network.
- Restore stops **before ZDO_STARTUP_FROM_APP** and verifies link keys,
  device table, read-back security data and frame-counter margins. No retries.
  Separately use the existing `skills/p10-zstack-restore-recovery/SKILL.md`
  mode-`0x00` restored-network resume gate if that prior failure recurs.

Read-only plan example (insert a new attempt ID, exact verified factory IEEE
and current transport; no network connection is made):

```cmd
python deploy\p10_recover_original_network.py --cold-bundle "PATH_TO_FRESH_COLD.zip" --attempt-id p10-restore-YYYYMMDDTHHMMSSZ-unique --endpoint tcp://VERIFIED_P10_HOST:7638 --factory-ieee VERIFIED_FACTORY_IEEE
```

Actual restore is a **separate, later approval**: the same command must have
`--min-network-counter LAST_READ_ONLY_NETWORK_TX_COUNTER`,
`--min-link-tx-counter HIGHEST_READ_ONLY_TC_LINK_TX_COUNTER`, an appropriate
non-overflowing `--counter-jump`, and explicit
`--execute --approval RECOVER_ORIGINAL_ZIGBEE_NETWORK`. Those floors must
come from the preflash read-only radio receipt; never guess them from the
historical backup. After restore, require coordinator `state=9`,
same network identity, 103 restored keys and address rows, frame-counter
floors and successful cold boot **before** resuming Zigbee2MQTT.

## 5. What is complete and what remains

**Now ready:** private copies and SHA verification of cold Zigbee2MQTT
backup, current hot snapshot, vendor rollback firmware, proven historical
recovery evidence, reusable offline validation and a deterministic guarded
restore plan. The previous October 6 full restore was successfully exercised.

**At actual user-approved cutover:** stop Z2M and take a **new cold bundle**,
capture fresh on-chip security-counter watermark and confirm the real flashing
package/transport for T832-MIN; only then attempt one candidate. Its GitHub
Actions `.hex` is an **offline build artifact**, not yet a validated MR4U
upload package. If failure, prefer vendor firmware-only rollback; restore NV
only when proven necessary. This practical procedure intentionally avoids
a large test suite, alternative firmware matrix, or re-pairing all devices.
