# P7U recovery finalization — 22 October 2026

The sole SLZB-06P7U is running R4 `323949a` with the retained network. The demonstrated manual recovery was radio reset + failed Z2M start, then ESP restart + successful Z2M start. This establishes an availability workaround, not the cause of the stock/R4 SRSP hang.

## Current iteration: shared watchdog #143 / draft PR #146

Version 0.2.0 implements the independent review corrections described in [README.md](README.md): transaction-scoped durable results, restart reconciliation, continuous stability, genuine timestamp-based RF evidence, semantic SRSP attribution, OTA inhibition, precise controls and two-destination warning delivery.

Required final gates:

- Exact-SHA GitHub recovery/Python suites.
- SHA-verified full guard deployment; reset execution stays disabled and boot manual.
- Approved live `last_seen: epoch` setting without restarting Z2M.
- Ten minutes of valid production observation, three devices with advancing RF timestamps, labelled synthetic warning in both HA destinations, and a guard-only restart preserving state.
- Keep automatic recovery unarmed until separately approved actuator/ownership admission. Do not disrupt the working radio to benchmark recovery.

## Next: R4 observability #144

Deploy maintained F0/F2 sampling through the actual single herdsman serial owner, with source-bound native validity and durable pre-hang samples. No second UART owner or ad hoc node_modules mutation. This follows shared guard qualification.

## Later: stock qualification #145

Independently verify stock image provenance, NV layout, current security state and counter-safe migration before proposing a stock flash. Seven-day and thirty-day reliability observations are separate from automatic recovery acceptance. No stock flash, network restore or power-cut tier belongs to this iteration.
