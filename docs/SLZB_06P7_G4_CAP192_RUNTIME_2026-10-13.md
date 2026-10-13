# SLZB-06P7 G4 CAP192 runtime ledger (2026-10-13)

**Qualification: source + linked evidence only, hosted CCS at exact SHA. NOT_FLASHABLE. No hardware/flash/NV/CCFG/radio/HA/Z2M/P10 access. All 36 `feature-parity.json` flags stay `false` (`p7_implemented`/`p7_tested`/`release_qualified` unchanged); this ledger never flips them.**

Build tracks in `slzb-06p7-g4-cap192-native.yml`: **BASE** (pristine pinned ZNP), **CAP192** (NV5 5-page geometry + CAP192 capacity SysConfig via `g4/cap192_overlay.py`, fail-closed), **CAP192+DIAG** (CAP192 + G5 `diag_overlay.py`). CI emits `BASE-VS-CAP192.json` / `BASE-VS-CAP192DIAG.json` map+heap deltas (`g4/cap192_compare.py`) and the effective-header audit (`cap192_capacity.py --generated`). Startup guard: the CAP192 overlay patches only `znp.syscfg`, asserts no wipe/format token and never modifies `zd_app.c`/`nvocmp.c` (`audit_no_wipe` + CI grep of the SDK diff); the DIAG NV callsite only reads the already-decoded `networkStateNV`.

| ID | Feature (acceptance gist) | Source | Linked | Runtime | Disposition |
|---|---|---|---|---|---|
| F03 | TC192/NWK96/Addr298/bindings4 | syscfg TC192+NWK96 inserted; 298 derived; bindings have no proven SysConfig anchor | generated-header audit TC/NWK; NV5 host 587-record mix | none | PARTIAL config-only; bindings BLOCKED (no anchor) |
| F04 | Route128/SRoute128/Nbr64/RREQ16/Hops16/Conf8 | syscfg routing128+RREQ16 inserted; others no proven anchor | header audit routing/RREQ | none | PARTIAL; source-route/neighbor/hops/conflicts BLOCKED |
| F05 | NWK24 buffers wait16/sched8/conf8 | no safe `nwk_globals.c` anchor proven on pinned SDK | none claimed | none | BLOCKED ? needs exact-source review, not invented constants |
| F06 | OSAL 32KiB heap | no heap patch (P7 linked heap span already >>32KiB) | `cap192_compare` heap-span proof per map | none (no high-water) | LINKED-PROOF only |
| F07 | Sync NIB NV commit before state9 | no patch; DIAG reads decision read-only | none claimed | none | BLOCKED ? blocking/commit semantics need SDK review + R10 guard proof |
| F08 | UART TX_DONE vs FIFO acceptance | no patch; G5 DIAG distinguishes FIFO-loaded vs TX-finished (UNKNOWN) | DIAG symbols in CAP192+DIAG | none | CONFIG-ONLY/documented; wire completion UNKNOWN |
| F09 | UART_ISR 128 / NPI_TL 1080 | values NOT copied without RAM proof | map SRAM delta reported | none | BLOCKED ? burst/RAM evidence required first |
| F10 | NPI alloc ownership fixes | no safe anchor proven | none claimed | none | BLOCKED ? 512-cycle leak test needs patched-body review |
| F11 | Retry only sync reject, max3/50ms | no safe anchor proven | none claimed | none | BLOCKED ? timer/ownership review required |
| F12 | SRSP-first dual FIFO 4:1 fairness | no safe anchor proven | none claimed | none | BLOCKED ? queue-order proof required |
| F15 | RX overflow recover/resync | no patch; DIAG records overflow (ISR) only | DIAG symbols in CAP192+DIAG | none | BLOCKED for recovery behaviour; observability source-only |

NV5 realistic faults (Task B, host simulation labelled non-hardware): `tests/p7-nv5-host` `cycle` op churns the G3-accounted 587-record mix (192x27B TC + 96x23B NWK + 298x19B addresses + 2300B misc) through 3 update+compact rounds in 4x8KiB storage + 1 compaction page, 5 cold-restart verifies, and a CRC-corruption negative (controlled driver failure, clean image re-verified) in `slzb-06p7-g3-nv5-host.yml`; torn-write/erase-prefix negatives remain the existing PARTIAL-WRITE/ERASE verdicts. No real keys, no hardware.
