# P7 F07 / coordinator-ready synchronous NIB gate — slice 1

**Status:** HOSTED SOURCE + NATIVE COMPILER QUALIFICATION PENDING;
**NOT FLASHABLE**, `F07` **NOT COMPLETE**. Never migrate an existing network
or alter the live P10/MR4U coordinator as part of this slice.

## Actual pinned SDK defect targeted

In TI SDK8.32 `source/ti/zstack/stack/zdo/zd_app.c`,
`ZDApp_NetworkStartEvt()` announces `DEV_ZB_COORD` immediately after
`ZDApp_NwkWriteNVRequest()`. That macro aliases to a **void**
`AddrMgrWriteNVRequest()`; it is not proof that the NIB or network security
state was durably saved. In `osal_nv.c`, `osal_nv_write_ex()` initializes
the return value to `SUCCESS` and may report it even without a configured
`nvFps.updateItem` backend. A write-return-only patch would be insufficient.

## Implemented behavior

A precise overlay adds `p7_f07_commit_nib_before_ready()` to `zd_app.c`.
For `NV_RESTORE` builds it checks that the existing `ZCD_NV_NIB` item
has the exact `nwkIB_t` length; allocates a caller-owned readback buffer;
executes an `osal_nv_write`, `osal_nv_read` and full-byte comparison;
and always frees the readback. Any failure leaves `devState` in
`DEV_COORD_STARTING` without announcing `DEV_ZB_COORD`.
The ordinary address-manager NV request still follows the completed NIB
gate. No retry loop, buffer leak or overwrite/erase branch is added.
Non-`NV_RESTORE` paths remain unchanged.

This is **not** an assertion of flash durability against a power cut:
readback may be served by NVOCMP runtime state. True persistence requires
isolated device cold-cycle/power-loss qualification.

## CI

- Hosted pinned-TI-source anchor and actual C function fault-injection:
  `tests/p7-f07-host/test_f07.py`.
- `slzb-06p7-g6-native.yml` adds `f07-stock` to existing stock/CAP192
  native CCS tracks. Native compilation still requires all original G6
  code/ELF/HEX checks, reference CCFG identity and no NV bytes in image.
- No source change to `NLME_InitNV`, `NLME_SetDefaultNV`, network
  commissioning or NV page geometry. Do not enable this gate for a live
  coordinator on the basis of source/CI tests alone.

## Still missing — separate F07 slices

1. **Restore/factory discriminator before destructive initialization:** the
   current `ZDOInitDeviceEx()` can fall into a new-network branch that calls
   `NLME_InitNV`, `NLME_SetDefaultNV` and `ZDSecMgrClearNVKeyValues`.
   Must distinguish explicit blank-network permission from incompatible,
   corrupt or partial old NV. Do not guess blank from one missing item.
2. **Network security/key tables and frame counters:** successful NIB
   readback does not prove durable trust-center/security material or monotonic
   replay counters. Require independent validation and isolated cold restarts.
3. **Queued non-NIB writes:** `AddrMgrWriteNVRequest()` and
   `NLME_UpdateNV()` return void; address/security-table persistence
   completion is not covered by this slice.
4. **Failure observability and recovery policy:** add non-secret bounded
   failure counters to the versioned G6 diagnostic endpoint, specify operator
   re-provisioning versus corrupt NV stops, and test forward progress after
   transient faults without repeated reformat/commissioning.

All F07 parity and release-qualification flags remain unchanged until
source, native and physical evidence warrant promotion.
