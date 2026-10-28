# B1 security changes and remaining gate

Status: **PARTIAL / source only; B1_SOURCE_READY is not established.** No
device, serial, RF, HA or network operation is part of these changes.

The exact TI SDK input is `3615ad5d3f4f271258d18a2f5ce1785064ff9a58`.
`apply_b1.py` validates Git blob preimages before modifying the SDK:

| Source | Original blob |
|---|---|
| `stack/zdo/zd_app.c` | `d67a7798a3e6a8681faddebf5e4b87b4b4c60421` |
| `stack/zdo/zd_sec_mgr.c` | `65d7857cc9c62b75419807a8c0d03a62ec1a5574` |
| `stack/sys/zglobals.c` | `0a1d7d2a61a88d1a6bb6e4bc5e359e71e1719024` |
| `zmac/f8w/zmac.c` | `38edebba04b31a416f64949ef991aa990dd99dba` |

Paths in the table are relative to `source/ti/zstack/`.

## Source-confirmed call paths

`stackInit()` invokes MAC initialization before `zgInit()`. `zgInit()` then
initializes global NV items and invokes `ZDSecMgrInitNVKeyTables()`, whose
NWK/APS/TCLK/seed helpers can create missing NV records. Later,
`ZDApp_RestoreNetworkState()` uses the library's `NLME_InitNV()` and
`NLME_RestoreFromNV()` and invokes NWK key restoration. The returned
restored/new state reaches `ZDSecMgrInit()` -> `ZDSecMgrEntryInit()`;
`ZDSecMgrRestoreFromNV()` runs only for
`ZDO_INITDEV_RESTORED_NETWORK_STATE`.

Consequently, adding a key check only in `ZDApp_RestoreNwkKey()` is too late
to preserve evidence of missing security records. The new
`b1_sec_validate_restored()` runs at the beginning of `zgInit()`, before its
first `osal_nv_item_init()`. It does not initialize the NIB or authorize RF.

For a structurally admitted nonblank image, the BDB network flag must be
readable and boolean. A stored true flag requires a nonzero NWK key,
agreement with the active key's sequence and key bytes, a nonzero stored
TCLK seed and trust-center record, a bounded APS header and all referenced
APS keys, and readable donor-preallocated TCLK storage. Counter reserve
overflow and invalid seed shifts reject before these helpers write any
security checkpoint. No key, seed, IEEE or row payload enters diagnostics.

An APS header with `numRecs == 0` is a legitimate optional empty APS table;
unreferenced APS data rows are not required. The donor creates TCLK empty
slots by zeroing the complete row and setting `ZG_DEFAULT_KEY`; therefore
an existing empty slot has seed shift zero. An absent slot on a restored
network is treated differently from a verified empty slot. Missing rows
are not replaced by the key/table/seed initializers in restored mode.

A false BDB flag permits the configured-new path. Truly blank media also
requires the separate existing factory authorization at NV admission.
These controls do not invoke restored APS handling: the actual
`ZDSecMgrEntryInit(NEW_NETWORK_STATE)` dispatch is compiled in the tests.
This is a limited classification; full NIB-versus-BDB coherence remains
open and this code must not be represented as a formation authorization.

## Demonstrated persistence defects corrected

- `ZDSecMgrRestoreFromNV()` previously used an unchecked APS key read,
  indexed RAM with an unchecked NV index, added without overflow checks,
  published RAM counters, then ignored the checkpoint write. It now checks
  reads/index/key/reserve and persists and reads back the complete row
  before publishing that row's RAM state.
- `APSME_TCLinkKeyInit()` previously incremented unchecked data and
  published RAM before an unchecked write. It now preserves empty slots,
  checks overflow, and publishes after exact readback. A restored-network
  startup-default request latches HOLD rather than resetting security.
- `ZDSecMgrSaveApsLinkKey()` and `ZDSecMgrSaveTCLinkKey()` previously cleared
  pending flags even when writes failed. They retain pending state on
  failure, reject RAM-counter rollback, verify persistence and stop boundedly
  on the first fault.
- `APSME_TCLinkKeyLoad()` now rejects HOLD, out-of-range search results,
  unknown key attributes and wrap before exposing a frame counter. New
  legitimate TCLK rows require verified persistence before RAM publication.
  `ZDSecMgrGenerateKeyFromSeed()` rejects a failed seed read before deriving
  a key.
- NWK restore accepts the final generic counter row only when its identity
  is the donor's all-FF generic identity. An arbitrary different network in
  the final slot is no longer accepted as generic.

Security failures call `b1_security_runtime_hold_latch()`. The management
authority records HOLD_SECURITY; the union hold is also visible to the
existing ZMac guards. There is no automatic clear on a later successful
read or callback.

## Test boundaries and acceptance limits

`make_security_harness.py` extracts the actual patched TI functions and the
new helpers into a C translation unit. NV item APIs, the state latch,
address lookup and OSAL event posting are simulated boundaries. The
scenario list is exported as `SCENARIOS` for the GitHub-hosted runner.
The positive restore, configured-new dispatch, optional-empty APS and
checkpoint controls accompany hostile missing-record, generation, bounds,
overflow, write/readback, rollback, runtime load and sticky-hold cases.
Four compiled mutants test publication before persistence, pending-flag
clearing on failure, readback bypass and wrap bypass. A local compiler smoke
run is development evidence only; only exact-head GitHub job results are
HOSTED_SYNTHETIC acceptance evidence.

These tests do **not** close full N02, N12, N25, N28 or N30. They do not
validate all NIB/IEEE/PAN/channel identities, all key generations, duplicate
or aliased APS/AMI relationships, install-code ownership, library-internal
APS/NWK counter paths, or every key-update caller. Earlier rows may already
have valid checkpoints and RAM publication when a later persistence fault
occurs; the sticky hold must block subsequent new admissions. This is not
a cross-row atomic transaction or rollback mechanism.

The donor's full-TCLK-table fallback to the global key is preserved. Its
library/global-counter semantics have not been proved unsafe or safe here;
the `load_full_legacy` control records only unchanged source behavior.
Changing capacity policy belongs outside this scoped persistence fix.

The eight ZMac guards reach actual MAC request APIs for new application
requests. MAC initialization precedes the security check, and MAC ROM,
direct lower calls, beacons/ACKs, queued frames and in-flight radio activity
are not shown to be stopped. **No claim of zero physical RF or complete
lower-MAC gating is made.** N22 remains partial and NIB/security/RF phase
acceptance stays blocked until those paths are independently resolved.

The source admission is not a stock NV format endorsement. Stock NV layout
and hardware behavior remain `STOCK_NV_LAYOUT_UNKNOWN` /
`R4_IMAGE_NOT_PHYSICALLY_TESTED`; no flash, merge or release is authorized.
