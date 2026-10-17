# B3-01 — actual-source failure triage

Source pin: TI LPF2 8.33 SDK `3615ad5d3f4f271258d18a2f5ce1785064ff9a58`.

**P0:** `NVOCMP_initNV` performs `NVS_getAttrs(NVS_open(...), ...)` *before* checking the handle for NULL; an NVS_open failure can dereference invalid handle. Repair should move NULL guard immediately after open; must not change init ordering relative to B1 preflight.

**P0:** `NVOCMP_read` drops `NVS_read` status entirely. Returning initialized stale buffer data after read error risks interpreting unreadable NV as erased or valid data. A mere signature/bounds check after an ignored read is not a sound solution. Converting to a returning status requires propagating errors to all callers, and may not be safe as one-line patch. **BLOCK until full call graph + compiled fault harness**.

**P1:** `osal_nv_write_ex` starts `rtrn=SUCCESS` and falls through if updateItem callback missing; `osal_nv_read_ex` reports SUCCESS for any status except FAILURE and `osal_nv_init` drops init status (void ABI). The B3 hosted harness should first reproduce the false-positive, then test a guarded overlay while B1 owns resulting HOLD behavior.

**P1:** TI NVOCMP permits destructive recovery under `NVOCMP_RECOVER_FROM_COMPACT_FAILURE` if explicitly enabled. Ensure the native B0 build does *not* define it, and refuse source-only claims of fail-closed when unreviewed boot logic can format nonblank NV.

Flash write/erase NVS return <0 already maps to NVINTF_FAILURE; avoid bulk rewrite without negative controls. The presence of CRC8 and restart recovery design does not prove protection from all torn reads/pages. Runtime HOLD_SECURITY/no RF remains B1 cross-phase gate, **not implemented here**.

No live NV, coordinator or household credentials accessed.

## 17 October corrected donor defects / remaining hazards
Patched TI `NVOCMP_writeItem()` refuses writing the *header validity marker* after data write failure and rejects failed one-shot write without offset advance; synthetic persistent NOR replay verified across NV2/3/5, not real physical brownout. Added explicit NVOCMP_read status propagation and page/offset/length validation, avoiding unsafe `memset` from corrupted item lengths. The B1 source branch independently owns unknown-format preflight and RF HOLD_NV / HOLD_SECURITY, not integrated here.
Original TI `zd_sec_mgr.c::ZDSecMgrSaveApsLinkKey` and `ZDSecMgrSaveTCLinkKey` discard write statuses and clear pendingFlag: B3 now clears only after successful OSAL update. Compiled actual function-body harness passed; actor state alone does NOT stop RF after a failed security checkpoint. `ZDApp_SaveNwkKey` still discards several NV write/read statuses and resets its batching counter regardless, leaving NWK security durability an OPEN high-risk gate.
The actual TI NVOCMP C host fault suite provides partial M08/M09/M12. All-op power-cut injection and B1 integration remain OPEN.
