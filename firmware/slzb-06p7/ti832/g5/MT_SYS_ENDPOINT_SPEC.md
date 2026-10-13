# G5 MT SYS vendor endpoint spec (DISABLED)

Status: **SPEC ONLY — `P7_DIAG_MT_ENDPOINT_ENABLED=0`, not wired, NOT_FLASHABLE.**

| Item | Value |
| --- | --- |
| Candidate CMD | `0xF0` (MT SYS subsystem, SREQ `0x21 0xF0` / SRSP `0x61 0xF0` shape) |
| Collision check | Pinned TI `mt_sys.c` (SDK `6499c3f5…`) grep and pinned zigbee-herdsman (`0968f979d558874b17396c96b66382d4236bbdcd`) SYS-handler check both run as CI evidence steps in the G5 native workflow and report their findings at exact SHAs. Evidence of absence in those two trees is necessary, not sufficient: the endpoint stays **disabled** until a human reviews both reports at one SHA. P10's use of `0xF0` is not P7 evidence. |
| Request | 0 bytes only; any payload → reject, no state change |
| Response | `p7_diag_snapshot()` bytes: 28 B header (reset-source at 16, reset-known at 17, reserved 18-19 zero, total at 20-23, writer-contention drops at 24-27 kept separate from eviction `dropped`; decoder unconditionally cross-validates total==last seq and dropped==max(0,total-64) in non-wrap windows, tick regression only at BOOT_ENTER or uint32 wrap) + ≤8×12 B events + 2 B CRC16 = ≤126 B, schema v1 (kinds extended to 23 incl. UART_FIFO_LOADED, layout unchanged); no snapshot before init; unstable snapshots return 0 rather than CRC-valid torn data |
| Writer protocol (CR1) | Single writer ownership claimed by one atomic exchange (Cortex-M4 LDREX/STREX via C11 atomics; specified TI-RTOS7 mapping is a PRIMASK/Hwi test-and-set at claim/release only). Task and ISR writers drop + count contention instead of waiting or preempting an owner. Snapshot reader keeps the seqlock. Source/host-proven only; no Hwi-priority or board qualification is claimed. |
| Integrity (CR2) | Record path is O(1): a rolling fold over the 12-byte event plus state words, never a ring scan. The full retained CRC is computed only by `p7_diag_seal_retained()` (explicit, task context) and verified once at boot in `p7_diag_init_preserving()`. Any record after a seal invalidates it, so unsealed, post-seal-modified, or one-byte-corrupt retained history falls back to a clean init. |
| Semantics | Read-only snapshot; never resets counters, never writes NV/CCFG, SRSP priority preserved (single bounded snapshot, no loops). Snapshot returns 0 (fail-closed, no torn data) if the ring does not stabilise within 8 seqlock attempts, e.g. under an ISR event flood — availability under fault storms is explicitly not claimed. Reset-source byte is masked to 0 when reset-known=0. Retained-ring preservation requires a valid seal + magic + CRC + range sanity and a separately gated noinit check; SRAM retention on this board is UNPROVEN. |
| Privacy | Numeric kinds/args only; no keys, addresses, PAN/IEEE, payloads |

Enablement gate (all required): pinned-SDK grep shows `0xF0` unused in MT SYS dispatch, Herdsman has no conflicting SYS handler, CCS build + host decoder CI green at the same SHA, board gate separately approved.
