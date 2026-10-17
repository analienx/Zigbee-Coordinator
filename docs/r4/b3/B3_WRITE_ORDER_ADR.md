# B3-01 — write-order and persistence-failure ADR

**Status: PROPOSED / PARTIALLY IMPLEMENTED; not a security proof.** Source pin `3615ad5d3f4f271258d18a2f5ce1785064ff9a58`.

Confirmed source faults:

1. TI `NVOCMP_initNV` called `NVS_getAttrs` before checking `NVS_open`; B3's narrow source overlay moves the NULL guard ahead of the call. A subsequent geometry guard rejects zero/wrong sector size and mismatch between reserved pages and compile-time `NVOCMP_NVPAGES` before any division/scan. It does **not** distinguish unknown pre-existing page-format bytes; B1 preflight is still the owner of HOLD_NV.
2. `osal_nv_write_ex` previously returned SUCCESS if `nvFps.updateItem` callback was absent; B3 defaults to `NV_OPER_FAILED`. `osal_nv_read_ex` previously accepted all statuses except `NVINTF_FAILURE` as SUCCESS; B3 accepts only `NVINTF_SUCCESS`. `createItem` and `deleteItem` likewise require known success and available corresponding get-length backend.
3. TI `NVOCMP_read` is a void function that discards `NVS_read` status. It remains **UNRESOLVED** because all reader paths must be instrumented and preserve no use of stale buffer after failure. A superficial single-location patch would give false confidence. `osal_nv_init` has a void ABI and loses init status: also OPEN.
4. Vendor `NVOCMP_RECOVER_FROM_COMPACT_FAILURE`, if enabled, can erase all pages after a failed collection; never enable it in B3. Read/compaction power-cut acceptance is open.

A successful `NVS_WRITE_POST_VERIFY` indicates the donor write API's result, **not** a cross-item atomic network-security checkpoint. For any write/readback error, a higher RAM counter/key may never enable secured TX until B1 latches HOLD_SECURITY; no fast retries, no startup fallback to factory formatting, and no missing-key fabrication. B1 must own RF admit/block; B3 cannot alter B1 state machine here. B2's key-table capacity decision must precede any persisted table format change.

The compiled actual TI OSAL source harness verifies a subset of the adapter contract; it does **not** implement crash-safe NVOCMP and therefore cannot qualify this ADR as ACCEPTED. No hardware proof, no flash permission.
