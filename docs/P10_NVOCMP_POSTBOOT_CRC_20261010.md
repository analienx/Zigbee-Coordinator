# P10 NVOCMP postboot CRC and record-mapping forensics — 2026-10-10

**Status: OFFLINE SNAPSHOT INTEGRITY VALIDATED; ORIGINAL NETWORK NOT RECONSTRUCTED.**
This report is about an **A1 revision 8320063 postboot** snapshot, not the
earlier R11 8320052 startup-hang CPU capture. Preserve that distinction.
This is a read-only evidence report. It does **not** authorize a new BSL
session, firmware flash, erase, radio restart, ZDO startup, restore, Zigbee2MQTT
restart or CPU debug attachment.

## Evidence custody and sources

- Snapshot: original 30,720-byte private immutable raw physical flash copy,
  SHA256 `87862b4f5b659c29b2874c562efdc3d02de14a4cc338fa95122fbacf3744cbdc`.
  It resides only in the Zephyrus restricted recovery directory
  `p10-issue53-bsl2-20261010` as
  `nvs-8320063-after-first-boot.private.bin`. **Never commit/copy the bytes.**
- Original read audit SHA256
  `d449355a51641592eed303ae2acb87ce9be5fd11913d809b2e583113948f78d2`,
  recorded 7,680 x four-byte BSL reads, no flash writes and a successful
  idx1 return-to-ZNP. Independent read-only SYS ping was 3/3 and version
  `8320063`, while ZNP length reads returned legacy NIB `33=0` and
  legacy Address Manager `35=0`.
- The previous 10:32 metadata parser
  `C:\Workspace\scratch\p10_nv_item_meta_offline.py` found 867 items
  based on bounds, 466 active, but did not validate CRC or correct ID mapping.
  Existing runner logs and snapshot audit were inspected before this pass.
- **TI SDK exact source** from the locally retained SDK
  `6499c3f53fc5fb5806213be695450a7b43fbaf3d`:
  `source/ti/common/nv/nvocmp.c` and `crc.c` / `crc.h`;
  `source/ti/zstack/osal/osal_nv.c`,
  `source/ti/zstack/stack/sys/zcomdef.h`,
  `source/ti/zstack/stack/nwk/aps_mede.h` and
  `source/ti/zstack/stack/zdo/zd_sec_mgr.c`.
- **Deployed A1 binary provenance as built**, not simply SDK defaults:
  hosted artifact `t832-a1-verified-38028972584`,
  manifest `T832-R12-A1-DIAG-vendor-20240716`, revision `8320063`,
  source commit `e601143594192c42bd9ecaeba9be5b0d71d3caaa`, SDK
  commit above. Independent artifact
  `provenance/vendor-layout-proof.json` shows compiled A1
  `NVOCMP_initNv` assembly `cmp r1, #0xf; movhs r1, #0xf`
  for a maximum of **15 sectors**, NVS base `0xF8800`,
  **30,720 bytes**, sector size **2,048**. The matching R12 and A1
  `provenance/nv-contract.json` specify 15 physical pages.
  **The source's default `NVOCMP_NVPAGES=2` was not substituted
  for this compiled-artifact evidence.**
  The SYS revision verifies the running firmware version, not the full
  byte-for-byte SHA of on-radio code; binary identity is not claimed.

## Reproducible *offline only* validation

`firmware/t832/r12/nvocmp_crc_offline.py` uses Python stdlib and an
exact SHA256-pinned input. It never imports any network, serial, GPIO or
hardware library and **never writes the snapshot**. To inspect locally:

```cmd
cd /d C:\Workspace\worktrees\zigbee-t832-r12-forensics
python -m unittest discover -s firmware\t832\r12 -p test_nvocmp_crc_offline.py -v
python firmware\t832\r12\nvocmp_crc_offline.py --snapshot "C:\Workspace\.analienx\sonoff-private\recovery\p10-issue53-bsl2-20261010\nvs-8320063-after-first-boot.private.bin"
```

It parses the exact 7-byte packed NVOCMP item header (big-endian packed
form, `NVOCMP_HDRLE=0`), backwards from the last programmed byte on a
2048-byte page to offset 16, observing `valid` and `active` flag bits
**separately**. Header signature must be `0x96`; lengths must stay
within page. CRC matches TI `crc_update()`: width 8, polynomial
`0x97`, init `0`, reflected input/output false, xorout `0`.
Critically, `NVOCMP_verifyCRC()` processes the **item payload plus the
first four full packed header bytes and a fifth byte with the CRC bits
masked off**; it does **not** include status bits or the stored CRC
itself. This is independently tested with synthetic records, a data
mutation, an inactive record and flag handling. The wrong little-header
interpretation yields only 11 candidate records, **zero matching CRCs**
and 11 bad CRCs, supporting the big-packed format.

## Source-supported physical results

| Check | Actual postboot snapshot | Interpretation |
|---|---:|---|
| Raw dump bytes | 30,720 | Complete, SHA256-pinned |
| Physical pages | 15 of 15 valid page headers | All programmed, not blank |
| Page states | 11 full, 1 active, 2 inactive, 1 transfer-destination | NVOCMP v3 formatted |
| Record-bearing pages | 12 | Pages 12–14 have no records |
| Item boundaries parsed | **867/867** | No gaps or out-of-page records |
| Valid item CRCs | **867/867** | 0 CRC failures |
| Valid item flags | 867 | 0 invalid IDs |
| Active / inactive records | **466 / 401** | One active copy per logical ID |
| Header SysID | all 867 **SysID 1** | Consistent with Z-Stack |
| Active logical duplicates | 0 | No active ID collision |

**Actual TI legacy mapping:** `osal_nv.c` translates
`osal_nv_read(id)` to
`(systemID=NVINTF_SYSID_ZSTACK=1, itemID=ZCD_NV_EX_LEGACY=0, subID=id)`.
The original comparison's search for NIB `itemID=33` and AddrMgr
`itemID=35` was wrong; the intended on-flash legacy IDs are
**`(1,0,0x21)`** and **`(1,0,0x23)`**, respectively. After correction,
**neither exists in this complete CRC-valid postboot snapshot**, active
or inactive. Extended Address Manager `(1,1,subID)` also has **zero
records**. This is concordant with postboot ZNP NIB33/AddrMgr35 logical
lengths both being 0. It does **not** tell us when those items were lost.

**Trust-center records:** the physical extended table identifier is
`(1,4,subID)`. It has 800 CRC-valid 20-byte entries: **400 active and
400 inactive**. TI source `APSME_TCLinkKeyNVEntry_t` is two 32-bit
frame counters, `extAddr[8]`, then 4 attribute bytes. Inspection of
the **eight extAddr bytes for empty/nonempty only**, without recording,
hashing or printing addresses, identified **zero occupied addresses
among the 400 active AND zero among the 400 inactive entries**.
These are allocated/default slots, **not 400 paired devices**.
No IEEE identifier, key, payload content or index is published.

Other **structurally present**, not semantically validated: exactly
**3 active APS-key-data** entries `(1,6,subID)` (24-byte records) and
**5 active NWK-security-material** entries `(1,7,subID)`
(12-byte records). Their presence does not prove a commissioned
network, matching network keys, or successful `startupFromApp`.
There are 58 active legacy `(1,0,subID)` records of various lengths,
but none for NIB or AddrMgr.

### 103-device backup reconciliation

The archived **R12 8320062** restoration receipt
`p10-r12-singleflash-20261010/a1-native-restore-inspection-r2/restore-receipt.json`
provides a **last-good immediate pre-A1-flash checkpoint**: 103
trust-center keys, 103 address records, protected counter floor passed,
630 NV mutation commands, and network start **not attempted**.
This is in addition to the older independent R11 8320052 original
network verification. Both private backup sets remain sealed.

The immediately following A1 flash receipt
`p10-a1-singleflash-20261010/a1-postflash-evidence-verdict.json`
confirms programmed image rev **8320063**,
SHA256 `5d0c3f111b9ec821da6c848ec62cfd32f3e08fa0cb22e7d385f2ca39705e0031`,
with **`requested_eraseNVM=0`**. The first postflash ZNP inspection
found legacy NIB33 and AddrMgr35 length **zero**, without issuing ZDO
startup or restarting the network.

The later A1 8320063 physical BSL snapshot then confirms **0 occupied
TCLK slots and 0 physical address-manager entries**, even though 800
TCLK headers/CRCs are valid. This localizes the disappearance to the
**verified R12 state → A1 flash/boot/postflash state** interval. A
request to skip NVS erasure is **not proof of NVS preservation**.
No matching *post-programming, pre-application-boot* raw snapshot or
writer trace exists. The evidence does not establish whether the
uploader, firmware initialization or another transition caused the
loss; it also does not explain the older R11 startup hang.

## Evidence matrix and decision

| Classification | Evidence | Conclusion |
|---|---|---|
| **Verified** | BSL dump SHA, all pages formatted, CRC 867/867 | NVS region was not globally erased |
| **Verified** | Packed-header mapper + SDK OSAL legacy translation | Prior `itemID=33/35` search was incorrect |
| **Verified** | 0 `(1,0,0x21)`, 0 `(1,0,0x23)`, 0 `(1,1,*)` | NIB and address-manager items absent **in this snapshot** |
| **Verified** | 400 active + 400 inactive TCLK item records; all empty addresses | No populated TCLK associations in the snapshot |
| **Verified** | A1 artifact compiled NVOCMP clamp `#0xf` | Application build recognizes up to 15 pages, not SDK default 2 |
| **Verified pre-transition** | R12 8320062 immediate pre-A1 receipt: 103 keys, 103 address records, 630 NV mutations, counters pass | Original network records existed before A1 flash/boot |
| **Verified post-transition** | A1 8320063 flash completion, requested eraseNVM=0, logical NIB/AddrMgr zero, later BSL empty slots | Loss occurs somewhere across flash/boot transition; no attribution to a single writer |
| **Unresolved** | No preflash / preboot / postboot matched triplet | Cannot attribute loss to uploader erase, boot NVOCMP, restore process or another transition |
| **Unresolved** | No qualified CPU debugger witness of R11 hang | R11 startup failure mechanism remains unknown |
| **Validation failure** | Alternative little-packed header: 0 matching CRC | Do not use it to interpret this snapshot |
| **Not authorized** | A new BSL/reset/startup/flash action | All future hardware activity remains blocked |

**Specific source-backed initialization hypothesis (NOT proven):**
TI `stack/sys/zglobals.c:zgInit()` obtains `setDefault` from the
startup-option factory-default bit when `NV_RESTORE` is enabled, or
forces it `TRUE` when `NV_RESTORE` is not compiled. It calls
`ZDSecMgrInitNVKeyTables(setDefault)`, which calls
`APSME_TCLinkKeyInit(setDefault)`. That initializer iterates **all
400 trust-center table slots** in this project profile, creating
defaults as required and writing existing entries during
initialization. A blank-table reinitialization is therefore
*consistent* with 400 active and 400 inactive all-empty entries.
**We have NOT established the exact A1 compiled `NV_RESTORE` preprocessor
state, the factory-default startup-option value during that boot, or
a timestamped writer trace.** Thus this is a falsifiable target for
offline build-flag/source inspection, not an identified cause.

**Highest-value next experiment within current OFFLINE-only authorization:**
inspect the archived A1 uploader transaction details and firmware
first-boot NVOCMP initialization/compaction path **without touching
hardware**. The restored R12 receipt already verifies 103 keys and 103
address rows immediately before A1 flashing; the A1 postflash verdict
proves NIB/AddrMgr missing immediately after. Determine whether the
updater's eraseNVM=0 guarantee can be reconciled with physical sector
writes, and whether application boot's `APSME_TCLinkKeyInit`
could explain the 400 active + 400 inactive zero-address entries.
Those are still hypotheses: two 400-slot generations **do not prove**
that boot erased/reinitialized originally populated TCLK entries
without a timestamped preboot snapshot or explicit writer trace.

If chronology is still ambiguous, a future independently approved,
**different** hardware experiment would need sealed before-flash,
post-programming/pre-app-boot and postboot physical snapshots. Such an
experiment is **not approved by this report**. The R12 cJTAG debugger
hardware gate in `T832_R12_NON_RESET_FORENSICS.md` remains blocked.

**Snapshot unchanged. No BSL, erase, flash, ZNP startup, reset, Z2M
restart or secret extraction was performed in this CRC/ID investigation.**
