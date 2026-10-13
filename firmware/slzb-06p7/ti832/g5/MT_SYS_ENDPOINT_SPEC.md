# G5 MT SYS vendor endpoint spec (DISABLED)

Status: **SPEC ONLY — `P7_DIAG_MT_ENDPOINT_ENABLED=0`, not wired, NOT_FLASHABLE.**

| Item | Value |
| --- | --- |
| Candidate CMD | `0xF0` (MT SYS subsystem, SREQ `0x21 0xF0` / SRSP `0x61 0xF0` shape) |
| Collision check | **UNKNOWN** — pinned TI `mt_sys.c` (SDK `6499c3f5…`) is not vendored in this repo; `feature-parity.json` F13 documents the *P10 CAP192* use of `0xF0`, which is P10 evidence, not proof of availability in the P7 vanilla table. The G5 workflow greps the pinned SDK checkout and records the result; until that grep plus a Herdsman (`0968f979…`) check pass at an exact SHA, the endpoint stays disabled. |
| Request | 0 bytes only; any payload → reject, no state change |
| Response | `p7_diag_snapshot()` bytes: 28 B header (reset-source at 16, reset-known at 17, reserved 18-19 zero, total at 20-23, ISR-contention drops at 24-27 kept separate from eviction `dropped`; decoder unconditionally cross-validates total==last seq and dropped==max(0,total-64) in non-wrap windows, tick regression only at BOOT_ENTER or uint32 wrap) + ≤8×12 B events + 2 B CRC16 = ≤126 B, schema v1; no snapshot before init; unstable snapshots return 0 rather than CRC-valid torn data |
| Semantics | Read-only snapshot; never resets counters, never writes NV/CCFG, SRSP priority preserved (single bounded snapshot, no loops). Snapshot returns 0 (fail-closed, no torn data) if the ring does not stabilise within 8 seqlock attempts, e.g. under an ISR event flood — availability under fault storms is explicitly not claimed. Reset-source byte is masked to 0 when reset-known=0. Retained-ring preservation requires magic + CRC + range sanity and a separately gated noinit check; SRAM retention on this board is UNPROVEN. |
| Privacy | Numeric kinds/args only; no keys, addresses, PAN/IEEE, payloads |

Enablement gate (all required): pinned-SDK grep shows `0xF0` unused in MT SYS dispatch, Herdsman has no conflicting SYS handler, CCS build + host decoder CI green at the same SHA, board gate separately approved.
