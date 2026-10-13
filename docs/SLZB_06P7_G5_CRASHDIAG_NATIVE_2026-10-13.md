# SLZB-06P7 G5 crash diagnostics — CR1/CR2/native-DIAG milestone (2026-10-13)

**Qualification: offline source + hosted-CI only. NOT_FLASHABLE. No hardware, flash, NV, CCFG, radio, HA/Z2M, P10/MR4U access. All 36 parity flags in `feature-parity.json` stay `false`; no `p7_implemented`/`p7_tested` is flipped by this milestone.**

## Evidence classes (kept distinct)

| Claim | Source evidence | Linked evidence | Runtime evidence |
| --- | --- | --- | --- |
| CR1 writer ownership | `p7_crashdiag.c`: single-owner atomic claim, task/ISR drop+count on contention, seqlock snapshot reader; PRIMASK/Hwi mapping specified in header comments only | DIAG ELF contains `p7_diag_record*` symbols (native workflow) | **None.** No Hwi-priority, PRIMASK, or board behaviour is claimed. |
| CR2 O(1) record + seal | Rolling per-event fold in `record_common`; full ring CRC only in `p7_diag_seal_retained()` + boot verify in `p7_diag_init_preserving()`; post-seal/unsealed/corrupt history falls back to clean init | Same DIAG link as above | **None.** No ISR cycle count on M4F is claimed. |
| Native DIAG callsites | `diag_overlay.py`: fail-closed, count==1 anchor insertions on the pinned SDK (`6499c3f5…`) + examples (`87ff5b63…`) ZNP project; NV decision callsite is read-only and never alters restore/wipe flow | BASE vs DIAG CCS builds in `slzb-06p7-g5-native-diag.yml`: per-build maps, `BASE-VS-DIAG.json` resource deltas (text/data/bss, FLASH/SRAM, stack), DIAG symbols present / BASE absent | **None.** Instrumented firmware has never run on a board. Tick is constant 0. CR7: the UART2 write callback records `P7D_UART_FIFO_LOADED` only (TI SDK 8.32 UART2 docs: callback = bytes in HW FIFO); physical TX-pin completion (`UART2_EVENT_TX_FINISHED`, not subscribed) and host reception stay UNKNOWN. CR8: `p7_diag_preempt_hook` exists only under `P7_DIAG_TEST_HOOKS=1` (host test); the native workflow asserts the hook symbol and any `__atomic_*` library symbol are absent from the DIAG ELF, and contention drops use lock-free atomic fetch-add. |
| Endpoint `0xF0` | Spec in `MT_SYS_ENDPOINT_SPEC.md`; `P7_DIAG_MT_ENDPOINT_ENABLED=0` | Pinned `mt_sys.c` grep + pinned herdsman (`0968f979…`) ZStack SYS-handler grep reported as CI evidence in the native workflow | **Disabled.** Evidence of absence is necessary, not sufficient; human review at one SHA plus a board gate are still required. |

## Callsites (DIAG only, BASE unchanged)

Boot/main entry (`p7_diag_init` in `main()`), `ZDOInitDeviceEx` enter/exit, NV restore decision read from the already-decided `networkStateNV` (restored/new/ambiguous), MT `startupFromApp` RX, MT dispatch, SRSP queued, NPI queue accept (sync/async) and reject (type/alloc), UART2 write accepted/rejected (both flow-control variants), UART2 write-callback FIFO-loaded (kind 23; wire TX-finished stays UNKNOWN per CR7), frame FCS error, frame alloc/parse error, and RX overflow (NPI + UART, ISR-context record).

## Retention note

Retained-ring preservation now requires an explicit task-context seal with no record since sealing. Firmware integration must call `p7_diag_seal_retained()` at a quiescent task point to arm cross-reset preservation; otherwise the next boot cleanly re-initialises. SRAM retention on the SLZB-06P7 board remains **UNPROVEN** (CR3 open): no `.noinit`/linker or reset-class evidence is claimed here.

## Still open

CR3 (retained RAM across reset), CR5 enablement decision (human review of both collision reports), CR6 (counter/queue-depth runtime semantics), stack/ISR WCET measurement on hardware, and every board/flash gate. Green hosted CI at the final SHA is the only completion evidence for this milestone; run IDs and BASE-vs-DIAG deltas are reported on PR #63.
