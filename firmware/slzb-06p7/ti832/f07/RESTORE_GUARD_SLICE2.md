# F07 slice 2 — fail-closed requested-restoration discriminator

**Status: NOT_FLASHABLE, test/native-compile candidate.** It is not an
NV5 migration implementation and does not authorize destructive operations.

## Pinned TI 8.32 source behavior

`ZDOInitDeviceEx()` first reads the startup option and, for a requested restore,
calls `ZDApp_RestoreNetworkState()`. If that returns
`ZDO_INITDEV_NEW_NETWORK_STATE`, stock firmware enters the **new-network**
path despite the original restored-network intent. The explicit new-network
path calls `NLME_InitNV()`, `NLME_SetDefaultNV()`, and
`ZDSecMgrClearNVKeyValues()`, then executes new-network initialization.

The difference between *a user-requested reset* and *failed preservation of
an existing coordinator network* is crucial. A failed restore must never
silently trigger network formation or erase valuable keys.

## Implemented narrow guard

- For a **requested restore**, before entering the restore function
  (`NLME_InitNV` can itself initialize/create records), require a configured
  NV read and length backend, a precisely sized `ZCD_NV_NIB` and a
  successful bounded read into an owned/free buffer.
- On preflight failure, set `DEV_HOLD` and return
  `ZDO_INITDEV_LEAVE_NOT_STARTED`. Do **not** start the radio or initialize
  defaults/clear keys on this path.
- If the actual `ZDApp_RestoreNetworkState()` returns a non-restored
  result, likewise return HOLD/LEAVE_NOT_STARTED **before the original
  new-network branch**.
- A separately **explicitly requested new network** via startup option
  retains the old SDK behavior for now; that reset path still requires an
  explicit operator provisioning policy and its own acceptance tests.
- Original F07 slice1 (backend pointer presence and read-back before
  `DEV_ZB_COORD`) stays unchanged except the clarified C null-pointer check.

This is a preflight and control-flow guarantee, **not proof of trustworthy
security tables, a valid NWK counter, NIB contents or power-loss durability**.

## Verification

The host workflow compiles the exact extracted **post-overlay C decision
branch**, rather than duplicating its condition logic in Python. It exercises
successful restore; failed restore with valid NIB; absent/malformed item;
unreadable NV; allocation failure; absent backend/callback; and explicitly
requested new network. Every implicit-failure path must avoid
`NLME_InitNV()`, `NLME_SetDefaultNV()` and key clearing.

The existing native G6+F07 stock profile composes slice1 and slice2 after
G5/G6, keeps the authentic TI compiler/source and strict ELF/HEX/CCFG/NV
image gates, and compares stock/CAP192/P7U baseline tracks. Hosted tests
and native compilation are prerequisites, not runtime acceptance.

## Remaining essential work

1. Distinguish healthy empty factory NV, corrupt/partial prior NV and
   migrated old-layout NV **without** using a single missing NIB record as
   irreversible permission to erase.
2. Verify NWK key, TCLK/device tables and monotonic frame counters as
   a coherent restored security state *before* any coordinator-ready claim.
3. Qualify true NV retention, compaction, power-cut recovery and validated
   security-state migration from NV2 at `0xAA000` to NV5 at `0xA4000`.
4. Establish exact board UART/RF and console flashing/erase semantics on an
   isolated P7U, followed by a separate physical acceptance.

Never set feature `F07` fully implemented or publish a flashable artifact
on the basis of this slice alone.
