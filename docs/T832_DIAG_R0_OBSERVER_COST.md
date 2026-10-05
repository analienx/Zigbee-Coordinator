# T832-DIAG-R0 observer cost (bounded estimate, not a hardware measurement)

RAM (proven): `sizeof(T832DiagState) <= 4096` by `_Static_assert`
(harness prints the exact size; ≈ 2.9 KiB: 2560 B rings + 20 B first-fault +
8×6 B TX FIFO + 8×12 B AF table + counters/timestamps/flags). Linked map must
still show `>= 8192` bytes unallocated SRAM via the compiled-contract gate.
Rings are 64 critical + 64 routine 20-byte records; live system records
(HEALTH/AF_STATE/TASK_EVENTS/RESOURCE) are built at export time and never sit
in the rings. The first-fault snapshot is a verbatim copy with a flag bit, not
a second allocation.

UART volume (bounded): at most one diagnostic AREQ per 5000 ms. Each frame is
`[len]["T832D2:"+hex]` with at most 32 + 1 + 4×20 = 113 binary bytes = 233
text chars + 1 length byte = 234 B MT payload (≤ 240 B budget including the
DEBUG envelope accounting; static frame bound, asserted by the harness
frame-budget test on every emitted frame). Worst case is 12 frames/minute
(≤ 2808 payload bytes/minute) carrying up to 48 records/minute against a
periodic production of ≈ 20 records/minute plus command traffic; routine-ring
loss under bursts is counted (`routine_overwrite`) and the drain test runs
with periodics enabled. Typical volume is far less under backpressure, and
there is no backlog replay. Normal ZNP traffic always wins: export is gated
on sync-outstanding, transport-active, diag-pending and normal-pending.

CPU/hook cost (worst-case bounds, MT task or ISR context as noted):
- Tick read: one critical-section pair + one 32-bit tick read inside the
  section (no preemption race); 64-bit extension + scale. No false wraps.
- `record()`: one CS pair, one last-slot compare (coalesce), one 20-byte
  copy. Coalescing bounds repeat storms to one slot.
- Command RX/dispatch/complete: `record()` only.
- AF dispatch parse: bounded offset reads (7 or 16 byte minimum lengths),
  one 8-slot table scan on insert/confirm.
- Queue hook: one 8-slot shadow-FIFO push; a full FIFO refuses the push
  (the oldest tracked descriptor is never evicted) and counts
  `tx_overflow_n` plus a TX_MISMATCH record. Refusal ownership is
  correlated at the patched call site (R4-F01): unowned refusals retire
  nothing; the stage-3 owned refusal retires exactly the stashed
  generation, or nothing when the stash is the overflow sentinel.
- Dequeue hook: SOF check + head compare, O(1).
- TX finish: in-flight class resolution, O(1), one conditional record.
- NPI task wake / ZStack progress: single timestamp write, no record.
- NV hooks (task context, under NV mutex): word writes + tick read only.
- Export poll (1 s MT tick, early-outs on 5 s gate): builds at most 4
  records; hex conversion only on the export path, never in hooks.
- Heap sampling: `Memory_getStats` only in the 60 s RESOURCE tick (MT task
  context), one call per tick; unavailable reported as `0xFFFF/0xFFFF`.
  Each resourceDue export stages up to 2 of the 13 rotating selectors
  (`res_ext_idx % 13`), so a full rotation — heap slot included — recurs
  about every 7 exports (~7 min unimpeded), not every 60 s.
- No allocation, formatting, UART, flash, or waits exist in any hook or
  fault path; the validator greps every hot hook body for them.

Host cost: the collector is a 60 s file poll (default 16 MiB initial tail,
256 MiB per-run byte budget, 20000-row window cap, 30 s capture deadline).
State files are 0600/0700. Host-measured Python timings must not be presented
as target CPU claims. Hardware cycle/hook timing remains unvalidated until
bench measurement on the pinned toolchain and board.
