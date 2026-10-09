# T832-DIAG-R0 observer cost (bounded estimate, not a hardware measurement)

RAM (compile-gated): recorder + R5 snapshot + fatal latch + early capture
together remain <=4096 bytes by `_Static_assert`; this includes 2560 B rings,
TX/AF ownership, task handles, stage maxima and all fixed snapshots. Linked map must
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
periodic snapshots plus command traffic; routine-ring
loss under bursts is counted (`routine_overwrite`) and the drain test runs
with periodics enabled. Typical volume is far less under backpressure, and
there is no backlog replay. Normal ZNP traffic always wins: export is gated
on sync-outstanding, transport-active, diag-pending and normal-pending.

CPU/hook cost (worst-case bounds, MT task or ISR context as noted):
- Tick read: one critical-section pair + one 32-bit tick read inside the
  section (no preemption race); 64-bit extension + scale. No false wraps.
- `record()`: one CS pair, one last-slot compare (coalesce), one 20-byte
  copy. Coalescing bounds repeat storms to one slot.
- Command RX/dispatch/complete: bounded record plus generation/stage writes
  and tick read; no history allocation.
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
- NPI task wake: timestamp write. ZStack progress also runs bounded NWK table
  occupancy sampling at most once per 60 s (150 route + 40 discovery + 250
  source-route + 30 broadcast slots, plus six queue counts); no lock or alloc.
- NV hooks (task context, under NV mutex): word writes + tick read only.
- Export poll (1 s MT tick): samples 13 fixed current/max values before every
  gate in a bounded critical section. It builds at most 4 wire records;
  hex conversion stays on the export path. Each accepted frame carries one
  rotating R5 fragment (57 slots, at least 285 s per rotation). Blocking can
  delay export indefinitely; full RAM snapshots remain available by SWD.
- Task_stat scans two known fixed stacks at most once per 60 s in MT task
  context outside the interrupt lock. It is approximate and needs bench cost
  measurement. Global stack checks and Hwi stack scan remain disabled.
- Heap `Memory_getStats` traversal is disabled; RESOURCE:7 stays unavailable.
  Existing 13-selector RESOURCE rotation still exports two per 60 s tick.
- Fatal latch writes a fixed RAM structure before the existing spin. It calls
  no function and performs no clock/lock/NV/UART/formatting operation; raw
  cached timing is approximate, and retention is not claimed.
- No allocation, formatting, UART, flash, or waits exist in any hook or
  fault path; the validator greps every hot hook body for them.

Host cost: the collector is a 60 s file poll (default 16 MiB initial tail,
256 MiB per-run byte budget, 20000-row window cap, 30 s capture deadline).
State files are 0600/0700. Host-measured Python timings must not be presented
as target CPU claims. Hardware cycle/hook timing remains unvalidated until
bench measurement on the pinned toolchain and board.
## R11-DIAG addendum (operation-aware NV context, startup POD, extension frames)

Static RAM: NV POD grows by a net 24 B (First 16 B + Current 12 B replacing
4 B of first-failure scalars); at the deployed 15-page vendor geometry the POD is
116 B (124 B at 18 pages), within the 128 B cap. Startup POD is 20 B; extension
state is 44 B. Combined diagnostic RAM stays within 4096 B by compile assertion;
linker free SRAM floor stays 8192 B; FLASH_NV stays exactly 0x7800 at 0xF8800.

Hot path: NV captures add bounded register-width POD stores under the existing NV
serialization (no new locks, clock, allocation, flash, or NV reads). Startup sites add
plain volatile POD writes beside existing statements (no branch/return changes).
Export adds at most one 4-record (234 B payload) frame per eligible 5 s poll through
the same limiter and gates; hex formatting stays on the export path only. Cadence:
runtime every 30 s when eligible, firstNV/startup repeats at 60 s, legacy reserved
after every two extended frames. No retention is claimed (bit31 clear).
