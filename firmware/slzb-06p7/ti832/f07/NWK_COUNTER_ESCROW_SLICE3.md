# F07 slice 3 — coordinator NWK counter escrow (candidate, NOT FLASHABLE)

## Problem in pinned TI SDK 8.32

`zd_app.c` restore path `ZDApp_RestoreNetworkState()` calls `ZDApp_RestoreNwkKey(TRUE)` without checking whether that call actually recovered valid security state. Downstream `ZDApp_RestoreNwkSecMaterial()` scans `ZCD_NV_EX_NWK_SEC_MATERIAL_TABLE` using the legacy NV wrappers, accepts ambiguous read statuses and unconditionally updates RAM `nwkFrameCounter` and `FrameCounterUpdated` without checking or reading back the NV write. The legacy read wrapper can incorrectly treat `NVINTF_NOTFOUND` as success.

That is dangerous for a restored coordinator. A failed counter persistence step must not let the radio resume with a replay counter that may revert after restart.

## Implemented exact pinned source guard

`f07_nwk_counter_escrow.py` inserts an independent, natively observable `p7_f07_nwk_counter_escrow()` helper into pinned TI SDK `zd_app.c` and replaces the restored-coordinator callsite with:

```c
if (!p7_f07_nwk_counter_escrow() || !ZDApp_RestoreNwkKey(TRUE)) {
    return ZDO_INITDEV_NEW_NETWORK_STATE;
}
```

The previously merged F07 restore-failure guard catches this return **before** the SDK can initialize network defaults or clear keys, and transitions to `DEV_HOLD`. No implicit network reformation is allowed.

The helper requires all three raw NV backend callbacks. It reads the exact `ZCD_NV_NWKKEY` legacy item with raw `NVINTF_SUCCESS`, rejects missing or all-zero active keys, then scans the network security-material NV table using raw `getItemLen` and `readItem`. It requires **one and only one** valid material record for the restored Extended PAN ID (no silent generic fallback); duplicate networks, unreadable present rows, missing table entries and corrupt lengths are rejected. Empty unused slots may be skipped but cannot silently create security material.

Let `floor = max(persisted_material_counter, stored_NWK_key_counter, current_RAM_counter)`. The candidate calculates `advance = MAX_NWK_FRAMECOUNTER_CHANGES + NWK_FRAMECOUNTER_CHANGES_RESTORE_DELTA` with overflow rejection, refuses to cross uint32 max, and writes `floor + advance` into the chosen existing security-material record. It requires **raw NVINTF_SUCCESS for both update and readback** and exact record-byte equality. Only *after* that successful readback does it publish the advanced `nwkFrameCounter`, set `FrameCounterUpdated=TRUE` (suppressing the SDK's subsequent unchecked increment) and clear `nwkFrameCounterChanges`. Local key material is cleared on every return, and no secrets are logged.

## Tests and compiler gates

Hosted `test_f07_counter_escrow.py` compiles the actual injected C helper with fault-injected typed NVINTF callbacks. Positive and negative scenarios cover exact floor advancement, `NVINTF_NOTFOUND`, generic read/write errors, readback corruption after successful write, invalid key length, missing key or material row, all-zero key, missing write callback, missing backend object, duplicate matching security rows, overflow from persisted record or RAM, and a second same-boot counter reservation.

The native 3-profile workflow composes the verified G5/G6/G7/F07 overlays **plus this new helper** in:

- `p7u-f07-stock` (P7U vendor CCFG and stock NV2)
- `cap192-f07` (CAP192/NV5 and reference TI CCFG)
- `p7u-cap192-f07` (P7U vendor CCFG and CAP192/NV5)

The linked F07 verifier must prove an actual `ZDApp_RestoreNetworkState → p7_f07_nwk_counter_escrow` call edge, in addition to the two previously proven F07 edges, full G7 task/UART callback path, CCFG, NV zero-initialized bytes and strict ELF/HEX map.

## Strict limitations

- An immediate successful NVOCMP readback is **NOT** proof of durable retention across sudden power loss or interrupted compaction. These require isolated hardware fault injection and cold-start/counter-monotonicity testing.
- This deliberately **rejects an old network that has only a generic security-material record and no exact Extended PAN ID match**. That is a conservative safety choice, not a guaranteed drop-in fix for every existing coordinator. An explicit compatibility/recovery policy is needed before deployment.
- This tranche protects the NWK counter on *restored coordinator* startup only. It does not certify ongoing `ZDApp_SaveNwkKey()`, NWK-counter periodic checkpoints, APS/TCLK link-key counter persistence, TC device table completeness, or NV2→NV5 migration.
- A successful host or native build is not a hardware or migration qualification. Fitted P7U DIO UART/RF/management-console erase scope remain unproven.
- **NEVER flash this image or modify a production Zigbee network based on this branch.** No `main` merge; parent feature #61 remains draft.
