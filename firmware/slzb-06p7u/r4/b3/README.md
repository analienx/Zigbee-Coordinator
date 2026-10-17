# R4-B3 source-only workstream — issue #97

Branch starts **exactly** from accepted R4-B0 commit `1baefbee8e4de2c9d28c5e1a7c339cf2025a2afe`; it contains no B1/B2 worktree changes.

- `tools/b3_source_overlay.py` refuses donor drift (exact Git blob SHA), applies narrow fail-closed fixes to TI SDK 8.33 `osal_nv.c` and an early NVS_open guard in `nvocmp.c`, *only in a disposable SDK checkout*. No full SDK fork. Does **not** close all actual-source NVOCMP read-status or compaction issues.
- `tools/b3_migration_sim.py` is an **offline synthetic-only authority-denial simulator**. Requires independent archive hash pin, exact four ZIP members, member digest bindings, CRC/size/path checks, strict mock identities and fixed non-authority flags. It never opens real backing radio, restores backups or emits secret values.
- `tests/b3_host/osal_driver_test.c` links the actual patched TI OSAL C file compiled on a GitHub-hosted runner with minimal mocked interfaces; validates missing backend and rejected statuses. **This is not actual NVOCMP compilation or power-cut acceptance**.
- `tests/test_r4_b3_migration.py` includes hostile synthetic archive/network/frame counter cases, not a substitute for M01–M36 actual C matrix.
- `docs/r4/b3` includes sourced geometry/ADR/unknowns.

**Still OPEN:** exhaustive NVOCMP reader/compaction faults despite initial status patch; `osal_nv_init` void return; B1 HOLD_SECURITY RF admission; B2 effective TC/APS persisted table limits; authenticated high-water reserve-before-send; 36 full tests; completed native NV3/NV5 reproducible proof; independent reviewers; installed vendor stock NV format and physical qualification.

All mutation authorities are false. No automatic releases/merges, no real hardware, HA, MQTT, Z2M or Zigbee operations. B3_SOURCE_READY=false; B3_INTEGRATED_READY=false; MIGRATION_AUTHORIZED=false; FLASH_READY=false.

## 17 October source progress
The exact-git-blob pinned TI `nvocmp.c` now rejects failed data before record-header publication, propagates failed bounded reads and latches fatal failure. The original `zd_sec_mgr.c` APS/TCLK writers preserve pending checkpoint flags on rejected OSAL writes. Actual TI NVOCMP C host tests for NV2/NV3/NV5 successfully repeated cold-process reopen, healthy compaction, failed write and failed read. TI `zd_sec_mgr.c` original function bodies compiled and ran with mocked backend status; mutation and TI row-size C tests are in GitHub CI.
Separate genuine TI CCS native NV3/NV5 experimental workflows are added, NOT validated for deployment and not allowed to flash/restore. B0 UART and protected CCFG checks remain. **No hardware or household secret data was accessed.**
