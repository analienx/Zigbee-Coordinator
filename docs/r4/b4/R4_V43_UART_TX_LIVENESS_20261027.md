# R4 v4.3 — bounded NPI UART TX error unwind (2026-10-27)

**Status:** Source-only candidate atop physically serving `4cfe317` and F2 minor2 source PR #170. **Not flashed; no new radio/ESP/USB action.** Host F2 v4.2-capable source is already deployed in production as `6975ef2` (#171).

## Source-identified conditional failure

Pinned TI SDK 8.33 `npi_tl.c::NPITL_writeTL` marks `npiTxActive=TRUE` before calling `transportWrite`; if `npi_tl_uart.c::NPITLUART_writeTransport` gets an immediate UART2 write rejection, it returns **0**, and no completion callback is guaranteed. Original `npi_tl.c::NPITL_checkNpiBusy` can remain permanently true. In the actual R4 composite, B1 also latches physical transport HOLD on that immediate error. Clearing NPI busy therefore repairs bookkeeping; it **does not restore physical UART service** or permit another physical write after failure. This conditional source defect does not establish the cause of the 26–27 October field outage.

The accepted R4 B1 overlay **already** checks asynchronous `NPITLUART_writeCallBack` status and latches physical transport HOLD on failure, before returning without reporting TX success. A post-B1 handler inserted after that return would be unreachable. The R4 v4.3 patch explicitly hooks the existing B1 early-error exit to release NPI busy state **without weakening B1 HOLD**.

## One-owner fix

The exact-composite, anchored `tools/r4_uart_tx_liveness.py` modifies only:

- `npi_tl.c`: when **no physical TX was accepted** (`transportWrite==0`), clear the unstarted busy state, pending fragment pointer/length and TX length. Genuine accepted writes still retain normal completion ownership.
- `npi_tl.c`: add an explicit callback-error unwind `NPITL_abortFailedTx` to clear the transport busy state and notify the existing NPI task without reporting TX success; it does not clear B1 HOLD.
- `npi_tl_uart.c`: hook the *actual B1 early return* for callback status, byte-count mismatch or preexisting physical HOLD. B1 physical fault gating and normal success path remain unchanged; no new UART, RF or worker.

Never infer logical MT/OSAL queue errors are physical UART failures or invoke the B1 fail-closed physical fault path on ordinary logical rejection. No auto-reset, queue-growth workaround, RF alteration, counter/security/NV/CCFG writes.

## Runner-grade acceptance

`tools/r4_b0_b4_composite_stage.py` applies the fix **after** the exact B1+B3+B2+B4+AF handoff+F2 v4.2 source fusion. It then executes `tools/r4_uart_tx_liveness_harness.py`, compiling the actual modified TI C functions, asserting:

1. A normally accepted response completes through the real TL transmission callback.
2. A busy second submission cannot clear or replace the accepted write's state.
3. Immediate UART rejection clears NPI busy and preserves the real B1 HOLD; the next submission never reaches UART2.
4. Asynchronous status error and short completion clear busy, retain HOLD and never report successful TX.
5. An RX failure that latches HOLD while TX is outstanding suppresses that write's later success callback and safely releases busy.
6. Five deliberately broken C mutants—stuck-busy, inverted B1 status, omitted B1 error unwind, bypassed B1 HOLD, and failed-TX notification while the NPI CS is held—must fail at their specific expected return codes.

One integrated C fixture extracts eight real composed function bodies: TL write/abort/transmission callback, UART submission/completion callback, and B1 latch/failed/unavailable. Only UART2 hardware, interrupt masking and startup reservation/EOT telemetry are stubbed. Each of six production cases starts in a fresh process, using the supported UART flow-off profile and 270-byte fragment limit. B1 explicitly rejects flow-on builds. A separate 16-byte fragment-limit run is supplementary synthetic coverage, not a production fragmentation claim. Case and mutant receipts come from executed results. Failed-TX task notification must occur outside its CS; existing normal-success notification behavior is retained.

Muse's initial review of `93016f` raised a stale-callback ownership concern. B1 latches physical HOLD before the v4.3 error unwind and prevents new physical submissions afterward. Pinned TI SDK `3615ad5` completes and cancels only an active write, clearing `writeInUse` before invoking its callback; admission rejects a concurrent write. The source verifier now compares **both complete driver files byte-for-byte to their immutable Git blobs**, so an added callback alias or dirty driver cannot pass merely by preserving anchor strings. Driver hashes and the modified `npi_tl.c` hash are also bound into the existing B1 post-link sealer; the native ELF must contain `NPITL_abortFailedTx`. The C fixture proves submission gating, not simulated duplicate hardware callbacks. Hardware/DMA corruption and unrelated driver overrides remain outside this software argument.

The composition stage fingerprints preexisting tracked and untracked SDK changes outside its explicit seven-file write allowlist and rejects any change there. This preserves earlier B1/B3 and board configuration work rather than mistaking an expected dirty SDK for pristine source. Final native source snapshots still cover the whole final source delta. The source workflow now triggers for all local `r4_*.py` dependencies and B1 source changes. Source-only evidence remains distinct from native and physical qualification.

The saved final Muse review at `2aa7c1c` was **PARTIAL**, with the original P1s fixed and P3 proof/coverage/documentation gaps. This delivery pass addresses those concrete gaps without starting another review cycle. The PR description must describe six production cases, one supplementary fragment case and five mutants. The upstream provenance fetch uses blob filtering to avoid repeatedly transferring the whole SDK; all existing pin/content checks and negative controls remain in place.

## Remaining work before physical flash

- Get exact-head GH runner PASS and independent Muse Code Wonder Max adversarial review; remediate issues with fresh runner qualification.
- Verify final ARM-compiled APP/AC000 executable, ROM handoff, linker/memory/stack margins, exact flash/release provenance and protected NV/CCFG/security counters.
- If gates pass, one controlled flash of the unique existing radio with one serial owner, followed by physical Zigbee response and v4.2 F2 minor2 acceptance.
- An operational pass is *not* proof that this conditional rejection caused the historical progressive SRSP hang; continue collecting host passive boundary evidence.
