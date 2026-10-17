# B2 — pinned TI application-level MTO/NV failure correction (source-only)

**Status: experimental fail-closed replacement, NOT installed or integrated.** Parent: [#95](https://github.com/analienx/Zigbee-Coordinator/issues/95), proprietary RTG limitation: [#101](https://github.com/analienx/Zigbee-Coordinator/issues/101).

## Source-backed finding

The pinned TI SDK `3615ad5d3f4f271258d18a2f5ce1785064ff9a58` `zd_app.c` callback `ZDApp_ForceConcentratorChange` discards **both** `osal_nv_read` status values. On an error the old globals can remain enabled, causing the application to re-arm its MTO timer. The original B2 actual-source C harness documents this precise behavior. TI's routing guide says the application owns concentrator recovery, and TI SWRA650B documents many-to-one operation in large networks; neither proves this particular home's routing health.

## Concrete candidate

`tools/b2_mto_fail_closed_overlay.py` verifies exact SDK commit and pristine TI callback bytes, emits a function replacement that:

- Loads both NV settings to local bytes and examines both return codes *before* publishing globals;
- Stops the MTO event, clears local in-memory MTO enable/discovery and returns on either read failure or invalid boolean enable;
- Leaves both persisted NV items untouched; on healthy valid state, preserves the original 100-ms scheduling and stop logic;
- Does **not** turn on MTO by default, rewrite the closed TI RTG library, or alter B1 admission/security.

The dedicated GitHub workflow extracts genuine TI C, compiles with ASan/UBSan, exercises baseline/healthy/first-read-failure/second-read-failure/invalid-value cases, and deliberately mutates the second-read error check. Each run generates SHA-bound source-only receipts. **A green workflow proves only the callback logic at stubbed NV/timer boundaries.**

## Remaining acceptance gates

No permission to enable MTO or change an existing Zigbee network. Before promotion: compose the callback with B1/B3, decide whether NV failure must set sticky B1 HOLD rather than just stop MTO, show actual native P7U builds from one composite SHA, inspect route-cache/MTO **effective runtime** configuration, distinguish 1,000 RTG callback invocations from actual network broadcasts, and qualify physical routing/heap and network rollback separately. TI's closed `libZStack_nwk_all.a` remains unavailable for white-box verification.

References: [TI official Z-Stack routing overview](https://software-dl.ti.com/simplelink/esd/simplelink_cc13xx_cc26xx_sdk/7.10.01.24/exports/docs/zigbee/html/zigbee/z-stack-overview.html), [TI SWRA650B](https://www.ti.com/lit/swra650). **NO FLASH / NO PRODUCTION.**
