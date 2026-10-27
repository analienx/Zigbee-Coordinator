# R4 v4.3 — bounded NPI UART TX error unwind (2026-10-27)

**Status:** Source-only candidate atop physically serving `4cfe317` and F2 minor2 source PR #170. **Not flashed; no new radio/ESP/USB action.** Host F2 v4.2-capable source is already deployed in production as `6975ef2` (#171).

## Source-identified conditional failure

Pinned TI SDK 8.33 `npi_tl.c::NPITL_writeTL` marks `npiTxActive=TRUE` before calling `transportWrite`; if `npi_tl_uart.c::NPITLUART_writeTransport` gets an immediate UART2 write rejection, it returns **0**, and no completion callback is guaranteed. Original `npi_tl.c::NPITL_checkNpiBusy` can remain permanently true, blocking the NPI response queue. This is a source-proven **conditional defect**, not proof that a write rejection happened in the 26–27 October field outage.

The accepted R4 B1 overlay **already** checks asynchronous `NPITLUART_writeCallBack` status and latches physical transport HOLD on failure, before returning without reporting TX success. A post-B1 handler inserted after that return would be unreachable. The R4 v4.3 patch explicitly hooks the existing B1 early-error exit to release NPI busy state **without weakening B1 HOLD**.

## One-owner fix

The exact-composite, anchored `tools/r4_uart_tx_liveness.py` modifies only:

- `npi_tl.c`: when **no physical TX was accepted** (`transportWrite==0`), clear the unstarted busy state, pending fragment pointer/length and TX length. Genuine accepted writes still retain normal completion ownership.
- `npi_tl.c`: add an explicit callback-error unwind `NPITL_abortFailedTx` to clear the transport busy state and notify the existing NPI task without reporting TX success; it does not clear B1 HOLD.
- `npi_tl_uart.c`: hook the *actual B1 early return* for callback status, byte-count mismatch or preexisting physical HOLD. B1 physical fault gating and normal success path remain unchanged; no new UART, RF or worker.

Never infer logical MT/OSAL queue errors are physical UART failures or invoke the B1 fail-closed physical fault path on ordinary logical rejection. No auto-reset, queue-growth workaround, RF alteration, counter/security/NV/CCFG writes.

## Runner-grade acceptance

`tools/r4_b0_b4_composite_stage.py` applies the fix **after** the exact B1+B3+B2+B4+AF handoff+F2 v4.2 source fusion. It then executes `tools/r4_uart_tx_liveness_harness.py`, compiling the actual modified TI C functions, asserting:

1. Immediate UART rejection with no callback cannot leave `npiTxActive` latched.
2. A subsequently accepted response still transmits and completes normally **before** B1 enters HOLD.
3. Asynchronous UART completion error releases busy state, preserves B1 physical HOLD and does not report successful TX.
4. Failed fragmented transmissions clear unsafe fragment state.
5. Three deliberately broken C mutants—stuck-busy, inverted B1 status and omitted B1 error unwind—must fail.

A full source receipt binds final npi_tl.c and npi_tl_uart.c hashes. CI must include exact-source and dual-native builds, B1 NV/security seal and negative tests. No mocked-green or local-only build counts as hardware qualification. Do not weaken original B1 security admission or composite pinning.

## Remaining work before physical flash

- Get exact-head GH runner PASS and independent Muse Code Wonder Max adversarial review; remediate issues with fresh runner qualification.
- Verify final ARM-compiled APP/AC000 executable, ROM handoff, linker/memory/stack margins, exact flash/release provenance and protected NV/CCFG/security counters.
- If gates pass, one controlled flash of the unique existing radio with one serial owner, followed by physical Zigbee response and v4.2 F2 minor2 acceptance.
- An operational pass is *not* proof that this conditional rejection caused the historical progressive SRSP hang; continue collecting host passive boundary evidence.
