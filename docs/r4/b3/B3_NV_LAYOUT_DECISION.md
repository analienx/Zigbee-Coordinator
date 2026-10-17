# ADR B3-00 — NV2 versus NV3 versus NV5

**Status: PROPOSED / NOT ACCEPTED.** Author: R4-B3 source contributor; date: 2026-10-16; source baseline B0 `1baefbee8e4de2c9d28c5e1a7c339cf2025a2afe`.

## Decision

**Retain B0 NV2 unchanged for the source branch; select no production expansion yet.** NV3/NV5 are candidate geometry only. This is not a claim that NV2 can hold all 106 devices or that an existing NV can safely boot. Do not infer a decision from R2 NV5.

Source-derived one-reserve-page upper bound: NV2 8,176 bytes, NV3 16,352, NV5 32,704 before per-item 7-byte headers, obsolete versions, key rows, journals, CRC/compaction overhead and free-space reserve. A full table model needs real serialized records for NWK/NIB/BDB, TC/APS/TCLK, address/binding/group, and any durable routing; see unresolved mapping in capacity manifest.

## Criteria before final profile choice

1. B1 fail-closed NV preflight, unknown-format HOLD_NV and successful management path must be source-accepted.
2. B2 must choose supported TC/key table count and RAM/heap limits (106, 128, 160, 192 scenario); no silent persisted table migration.
3. Compile-time types and actual NVOCMP call-path/write fault harness for SDK 8.33 must prove item lengths, compaction reserve, torn-page behavior, cold reboot persistence and high-water key/counter policy.
4. 1k/10k/100k repeated item update model with realistic, separately sourced payload mix, bounded erase counts, worst-case copy demand and measured quantiles; no invented flash lifetime.
5. Two clean authenticated GitHub CCS native links per selected candidate with ELF/XML/HEX/BIN, CCFG vendor 88-byte SHA and board UART checks; explicit writer and rollback sectors.
6. Independent NV/security/build and migration authority review. No live stock format assumption.

## Alternatives

- **NV2:** smallest erase surface and unchanged B0 linker, but one 8,176-byte active page nominal bound may be inadequate for many link keys; cannot claim capacity.
- **NV3:** doubles nominal active capacity, removes 8 KiB of app address space, needs new native linker / NVS mapping; not an upgrade path from unknown NV2/NV5.
- **NV5:** four active pages, largest nominal capacity, 24 KiB app tradeoff and larger active/swap journal scans; stock format still unknown.
- **Offline escrow:** good for forensic evidence but cannot replace durable runtime frame-counter/key storage, and it never authorizes a flash.

**Fails closed:** unknown old layout, unknown current counter floor, divergent keys or insufficient room => NOT_RESTORE_READY / HOLD. No automatic formatting or sector erase.

Sign-off: **PENDING B1/B2/native/reviewer gates**; B3_SOURCE_READY=false, B3_INTEGRATED_READY=false, RESTORE_READY=false, FLASH_READY=false.

## 17 October APS/TCLK row-byte sensitivity
The pinned original TI `aps_mede.h` persisted row definitions are APS 24 bytes and TCLK 20 bytes. Per NVOCMP record the 7-byte compressed metadata brings these to 31 and 27 bytes respectively. A **conditional** fully populated APS+TCLK pair per device consumes 6,148 / 7,424 / 9,280 / 11,136 bytes at 106 / 128 / 160 / 192 devices, excluding all other live NV state and compaction. NV2 with 8,176 nominal active bytes is impossible for 160/192 both-full tables, but actual B2 TC/APS occupancy is not yet established. The correct profile remains **NO_PROFILE_LOCKED**; NV3/NV5 native links are experimental and do not authorize migration.


## Conditional capacity choice — FINAL SOURCE CANDIDATE, not deployment

For a capacity target allowing both APS and TC rows populated at 192 devices, **NV5 is the preferred experimental profile** (32,704 nominal live bytes vs 16,352 NV3 and 8,176 NV2). In the conditional 192-device example, both all-full tables consume 11,136 bytes, leaving 21,568 bytes nominal in NV5 vs only 5,216 in NV3 for NIB/address/binding, obsolete rows, other item classes and free reserve. That is a margin comparison, not proof of actual layout occupancy or durability. NV2 cannot fit the stated both-full 192-row scenario; B2 may select materially smaller tables, in which case NV3 is a legitimate alternative.

**Production layout remains UNLOCKED** until B1 unknown-format HOLD, B2 actual heap/table evidence, existing-stock NV version and separate operator-authorized migration. Preserve native NV2 B0 as the unchanged compatibility reference. Never reformat or erase installed unknown/NV2/NV3 media to implement a preference.
