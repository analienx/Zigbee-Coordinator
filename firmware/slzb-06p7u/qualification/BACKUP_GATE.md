# P7U coordinator backup preflight — read-only inventory and counter-floor gate

**Status: candidate utility. No flash or migration authorization is provided.**

For the retained backup-only network, `--migration-inventory` assesses an old or
cross-stack backup without passing the fresh same-family gate. It compares the
independent DB roster, counts explicit per-device link-key/counter records,
reports whether a Z-Stack TC seed exists and flags counter exhaustion. Outputs
contain counts/hashes, never keys or addresses. Missing explicit rows can be
derived relationships on some stacks; their absence is a review requirement,
not automatic proof of either loss or completeness. Prove same-network restore
per device or use deliberate re-pairing. Preserve the original full Z2M data
bundle (groups/bindings/configuration as well as this DB); this inventory does
not establish the bundle's completeness or the last transmitted counter floor.

For original raw radio recovery and deliberate NV5 preparation, use the separate
[NV5 recovery procedure](NV5_RECOVERY.md). Logical coordinator backup inventory
and exact same-radio raw-state recovery are different operations.

The painful failure mode addressed here is proceeding with coordinator firmware/cutover from a missing, stale or incomplete backup and discovering later that the coordinator NV security state or device roster cannot be reconstructed.

## Canonical inputs

This tool validates the unified `zigpy/open-coordinator-backup` v1 format from pinned `Koenkk/zigbee-herdsman` commit `0968f979d558874b17396c96b66382d4236bbdcd`, file `src/models/backup-storage-unified.ts`, and an **independent Zigbee2MQTT `database.db` NDJSON** roster.

```sh
python3 firmware/slzb-06p7u/qualification/verify_z2m_backup.py \
  --backup /secure/path/coordinator_backup.json \
  --database /secure/path/database.db \
  --expected-ieee 00124b0011223344 \
  --previous-backup /secure/path/prior_coordinator_backup.json \
  --max-age-hours 24 \
  --out /secure/path/p7u-backup-evidence.json
```

`--expected-ieee` is the independently observed **source** coordinator IEEE address, not an invented or assumed replacement P7U address. Do not substitute a backup's own IEEE into this argument; that defeats independent identity verification.

The output contains **only file hashes, counts and deliberately false release status fields**. It never prints network keys, Trust Center seed, link keys, extended PAN ID, IEEE IDs or individual device records. Keep the full input backups confidential: these files contain working network cryptographic material.

## Fail-closed safety checks

- JSON/schema and `metadata.format/version` match, source present, timezone-aware fresh backup date (24 h default, max 7 days configurable).
- Independently supplied coordinator IEEE matches; PAN/extended PAN, channel/mask, security level, update ID and NWK key block are valid. Exact source converter uses **unpadded hex PAN IDs and NWK addresses**, both explicitly supported.
- Z-Stack Trust Center key seed and nonzero NWK key present. This is a conservative same-family restoration policy; an otherwise valid generic-format backup lacking the Z-Stack seed is **not** acceptable for automatic P7U coordinator cutover.
- NWK frame-counter and link-key counters are valid uint32; key sequence uint8.
- All unique Router/EndDevice IEEE entries in the independent database exactly match the backup's roster, so a partial backup cannot silently pass. Stale/offline historical devices in the database must be reconciled deliberately, not discarded by the tool.
- When a prior snapshot is supplied, new NWK sequence does not regress, frame counter does not regress for the **same** sequence, extended PAN and TC seed remain stable, and retained link-key records and their RX/TX counter floors do not regress. New network key with unchanged sequence fails.
- Handles malformed, duplicated, missing, stale and mismatched inputs with safe reason codes, without copying secret content to CI logs.

## Strict remaining blockers

A passed backup preflight **does not** establish coordinator NV image backup completeness, immutable network-frame monotonicity across power loss, actual trust-center restoration, device route/table preservation, or physical recovery using SLZB management console. It cannot validate that the firmware target reads the same keys or that the target owns the same coordinator IEEE.

Before any flash or migration, separately prove:
1. Current actual radio NVRAM backup, read-only snapshot/hash and topology inventory.
2. Recovery path to the same model and verified bootloader/CCFG/IEEE restoration.
3. NV2→NV5 migration preservation (the flash regions overlap).
4. Cold-reset and abrupt power-loss key/counter monotonicity on isolated hardware.
5. Working P7U application UART/RF/console recovery, and explicit user approval for target-specific deployment.

Even with a successful result, this script always writes `flash_authorized: false`. It never connects to radios, Home Assistant or Zigbee2MQTT. Hosted tests use fake-only secrets and generated inventory.
