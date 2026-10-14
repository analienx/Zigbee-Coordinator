# F07 slice 4 — coordinator NWK periodic checkpoint (NOT FLASHABLE)

## Exact scope
Pinned TI 8.32 `ZDApp_SaveNwkKey()` ignores `osal_nv_write()` and `osal_nv_write_ex()` returns, reads security material without checking item status/length, silently falls back to a generic last slot, and unconditionally zeros `nwkFrameCounterChanges`. A source-only/NV-backed test is not evidence of power-cut durability.

`f07_nwk_checkpoint.py` retains the original TI body **only for non-coordinator roles**, replacing the coordinator branch with `p7_f07_nwk_checkpoint()`. It requires raw NVINTF callbacks, existing correctly-sized nonzero matching active NWK key, exactly one existing exact Extended PAN ID material record, non-regressed live counter with headroom against wrap, two ordered raw updates (material followed by key), and exact readbacks of both values. Counter changes are acknowledged **only after both readbacks**.

Any error sets an irreversible (until reboot) `p7_f07_nwk_checkpoint_fault` latch and the coordinator wrapper invokes `ZDApp_PauseNwk()` and `ZDApp_ChangeState(DEV_HOLD)`. It never silently inserts/clears the security material, creates a new network, substitutes a generic counter, resets a counter after failed persistence, or retries ambiguous writes. The previously accepted restored-startup escrow slice 3 is required before applying this overlay.

## Acceptance evidence required on PR latest head

- `tests/p7-f07-host/test_f07_nwk_checkpoint.py`: genuine injected C helper compiled with hostile NV callback responses (including failure after first write, readback corruption, rollback, duplicate/missing records, no callbacks, overflow).
- `tests/p7-f07-host/test_g7_f07_integration.py`: synthetic `ZDApp_SaveNwkKey → p7_f07_nwk_checkpoint` call-edge replacement negative controls.
- Real CCS12.8 TIARMClang3.2.2/SysConfig1.21.1 three-track full matrix: `p7u-f07-stock`, `cap192-f07`, `p7u-cap192-f07`. Verify exact linked call edge, CCFG, NV2/NV5 layout, no loaded NV and strict ELF↔HEX evidence. The existing base image remains unchanged.
- Evidence artifacts `NOT_FLASHABLE` and `flash_authorized=false` remain mandatory.

## Explicit release blockers

This new guard does **not** prove that pending TX is fully quiesced, that a successful NVOCMP readback survives sudden power loss, that periodic checkpoints bound all NWK frame-counter use, or that the trust-center APS/TCLK counters, pending network keys, key rotation and per-device link-key rows are protected. It can safely refuse to run when an unqualified legacy network lacks a unique exact material record or when live key counters are below an escrowed floor. These are intentional conservative rejects, **not validated runtime compatibility**.

No live HA/Z2M, MR4U/P10, P7U radio, flashing, erase, factory reset, commissioning or secrets are involved. Before any physical test, separately prove the P7U fitted board TI UART/RF and ESP bridge, vendor console flasher erase policy, original NV/CCFG/IEEE readback and rollback. NV2→NV5 preserved-state migration and cold power-cut recovery remain unimplemented.

## Source provenance
- `TexasInstruments/simplelink-lowpower-f2-sdk` pinned `6499c3f53fc5fb5806213be695450a7b43fbaf3d`, `source/ti/zstack/stack/zdo/zd_app.c`.
- Depends on previous F07 slices 1–3 and native G7/F07 three-profile integration.
