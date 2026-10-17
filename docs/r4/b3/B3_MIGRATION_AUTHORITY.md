# B3-03 — strictly offline migration analysis

**Implementation:** `firmware/slzb-06p7u/r4/b3/tools/b3_migration_sim.py`. **Authority: none**. No access to the currently running Zigbee network, historic escrow, USB/serial, MQTT, OTA or HA. This is a synthetic rehearsal, not a real backup migration tool.

## Contract that is actually implemented

The CLI accepts an at-most-2,000,000-byte ZIP of exactly four files in the root: `manifest.json`, `coordinator_backup.json`, `z2m_database.json`, `z2m_config.json`. ZIP entries are never extracted. An external lowercase SHA-256 pin is required; all three payload JSON files must match hashes in the synthetic manifest. JSON duplicate keys, bad ZIP CRC, duplicate ZIP members, symlinks, noncanonical/nested names, oversized members, invalid mock fields or malformed timestamps fail closed. The hash pin establishes byte identity, **not** authenticity of the original backup issuer.

Input is a deliberately invented teaching schema (`r4-b3-synthetic-v1`); `SIM-`-prefixed identities and key references replace actual IEEE, PAN/extPAN and key material. Manifest properties `synthetic=true` and `target_layout=NV2|NV3|NV5` are required. Cross-source network consistency, latest device/security overlap, changed mock key identity, high-water TX counter comparisons across ordered snapshots, page profile mismatch and same-network double-online signals are compared. No raw keys are materialized, no output includes identities, and original byte streams are left untouched.

### Example, once a **synthetic** ZIP is prepared

`python firmware/slzb-06p7u/r4/b3/tools/b3_migration_sim.py synthetic.zip --sha256 <64-hex-externally-recorded-pin>`

The decision JSON reports redacted counts and nonsecret reason codes, and **ALWAYS** contains:

```json
{"restore_authorized":false,"flash_authorized":false,"network_mutation_authorized":false}
```

`OFFLINE_CONSISTENT_FOR_REVIEW` only means internally consistent within invented data; `source_authentication=NOT_ESTABLISHED` remains. `NOT_RESTORE_READY` means a consistency blocker. Neither permits any write or network use. Do not submit household backup files to this experimental simulator, GitHub Actions or this public repository.

## Not implemented — hard migration blockers

Actual Zigbee2MQTT backup archive canonical selection, versioned Zigbee coordinator-backup JSON schema, configuration serial binding, original radio metadata binding and authenticity, real key-byte equality through private enclave/redacted cryptographic proof, address-manager verification, binding/group/TC rows, per-device RX vs TX distinction from TI call graph, source-age provenance beyond synthetic timestamps and physical isolation are not implemented. Current stock 20260310/20260311 NV layout is **UNKNOWN**. The historical #84 mismatch counts (106/106, 3 + 3 stale) are private observations, not new verified input or authorization. A future **separate** operator-approved R4-07 must run outside public CI after real authenticated backup escrow and isolated hardware planning.

## Source-review hardening — 17 October 2026

The original synthetic v1 schema did not record a NWK TX floor and its broad malformed-input handler could return `None`. It now requires `nwk_tx_counter` in **every** snapshot (older synthetic v1 fixtures without it fail closed), conservatively refuses NWK counter rollback/overflow, empty tables, dropped older device keys, unexpected synthetic-manifest trust claims, ZIP prefix/comment ambiguity and disallows implicit `None` decisions for unexpected structural errors. These are synthetic-only judgments, not real backup parsing. The source hash pin still does not authenticate an issuer.
