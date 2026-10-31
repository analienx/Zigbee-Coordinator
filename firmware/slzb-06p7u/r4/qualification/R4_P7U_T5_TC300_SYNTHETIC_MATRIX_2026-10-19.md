# R4 P7U / partial T5+T6: pinned TI TC300 synthetic source matrix

Status: **source-only evidence; NOT a flash, migration, formed-network, or full-B0–B4 release approval**. The canonical finding remains R4-R04 / R4-R05 in [issue #137](https://github.com/analienx/Zigbee-Coordinator/issues/137). The separate B4 work stays in draft #138.

## Pinned scope and implementation

- TI SDK 8.33.00.16, pinned `3615ad5d3f4f271258d18a2f5ce1785064ff9a58`, `source/ti/zstack/stack/zdo/zd_sec_mgr.c`.
- Pinned B1 overlay `firmware/slzb-06p7u/r4/b1/tools/patch_security.py`; CI additionally applies immutable B3 security fusion before extracting the **actual patched TI C functions**.
- Public full-profile requirements: `trust_center_devices=300`, `aps_table_entries=3`. The C test uses a 300-entry synthetic stub, not an assertion about the fitted radio's private NV contents, exact TI `sizeof`, or NVOCMP capacity.
- The existing extracted-function C harness now supports an independent `--tc300` variant. It preserves the existing 4-slot/53-scenario B1 tests. No ROM, radio, UART, keys, private NV, hosted service, or flash interaction.

## Matrix and observed behavior

| Source-only setup | Cases | Required observation |
| --- | --- | --- |
| **Formed** with preallocated TCLK items | 64, 100, 192, 255, 256, 299, 300 | Missing row at the first absent index must **HOLD without any NV write**. Fully allocated 300-row synthetic media may pass the read-only preflight. |
| **Unformed** with that many existing TCLK items | Same seven sizes | `APSME_TCLinkKeyInit(FALSE)` initializes only absent synthetic items, never changes seed, and finishes without HOLD if all NV creates succeed. This test does **not** estimate genuine NVOCMP occupancy, compaction or write latency. |
| High live TCLK index | 299 | The actual 16-bit loop traverses slot 299, persists increased TX counter with readback before RAM publication; unused slots remain unaffected. |
| Second TCLK checkpoint write fails | 0 then 299 | First independently verified row may advance; no second-row RAM publication, sticky HOLD. Cross-item atomicity is **not** established. |
| First TCLK checkpoint readback corrupt | 0 | Sticky HOLD; no unverified RAM publication. |
| Counter near `UINT32_MAX` | 299 | Reject the restore increment before any write. |
| Unformed create fails at index 256 after index 192 | 192–256 | Partial synthetic row creation can occur before failure, but operation latches HOLD; do not imply that an actual NV migration is safe or rollback-capable. |

19 compiled C scenarios are run against the source-extracted functions, with all seed bytes held constant and zero synthetic `APSME_EraseICEntry` calls. Three independent mutations must be rejected: truncating the TCLK loop to `uint8_t` (the test forces runtime wrap detection), accepting missing formed rows, and publishing RAM counter state after an NV write failure.

The [B1+B3 exact-source workflow](../../../../.github/workflows/test-r4-b1b3-fusion-source.yml) invokes `tests.test_r4_t5_tc300_security` **after** the pinned TI B1/B3 overlay. A local run with only the B1 security patch is corroboration, not a substitute for exact-head CI.

## Remaining evidence before acceptance

1. Pinned **genuine NVOCMP** allocation and torn-write/compaction cuts with 64/100/192/255/256/299/300 rows, realistic serialized size/overhead and near-three-page occupancy. This stub holds an array and cannot prove free flash capacity or latency.
2. True post-B1/B3/B2/B4 **native linked** `sizeof`/ABI/index checks, heap and RAM budgets, actual generated effective TC300, APS3, child97 and MTO/routing controls.
3. Genuine NWK/APS/TCLK transmit scheduling with repeated power cuts and durable counter high-water *before any frame is encrypted*: last transmitted counter under the same key must never be repeated. Current restore/readback and periodic checkpoint functions alone are **not** that end-to-end proof.
4. Immutable TC seed/key-epoch continuity under those crash/restart sequences, final startup semantic HOLD/no-RF behavior, later separately authorized physical qualification.

No legacy migration or opportunistic creation of missing **formed** TCLK rows is authorized. Preserve the formed-network fail-closed behavior and draft/unsealed status until all dependent gates are satisfied.
