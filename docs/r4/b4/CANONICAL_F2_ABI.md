# Canonical R4 B4 SYS F2 ABI v4.1 — source-only decision

**Decision 2026-10-17:** B4 v4.1 **#105 + stacked #110** is the *single canonical source candidate* for later B5 integration. The independently CI-green alternative #104 is **SUPERSEDED** and binary **INCOMPATIBLE**, even though it also uses SYS F2, 160 bytes and R4D4. This is not a merge, release, physical verification, or flashing authorization.

## Command ownership

- SYS F0 / R4D3 / 132 bytes — B4 v3 baseline #100, unchanged.
- SYS F1 — B1 management/HOLD. HOLD remains authoritative; optional SYS F2 must be rejected while HOLD unless independently approved in a combined integration.
- SYS F2 / R4D4 / 160 bytes — **only this v4.1 format**. Request (0x21/F2) has exactly 8 host-cryptographic nonce bytes; response (0x61/F2) echoes exactly the same nonce.

## Response wire layout (SRSP data bytes only)

| Offset | Bytes | v4.1 meaning |
|---|---:|---|
| 0–3 | 4 | ASCII R4D4 |
| 4 | 1 | Major 4 |
| 5 | 1 | Zero flags |
| 6–7 | 2 | LE length 160 |
| 8–11 | 4 | Capability **bit0 only**, 0 or 1 for cached TRNG boot token |
| 12–15 | 4 | Counter validity exactly 0x3F or 0x2C |
| 16–23 | 8 | Boot token, zero iff unavailable |
| 24–27 | 4 | Zero, radio uptime unknown |
| 28–31 | 4 | Nonzero process-local uint32 sequence |
| 32–131 | 100 | 25 uint32 slots, only six source-qualified counters |
| 132–139 | 8 | Exact host nonce echo |
| 140–155 | 16 | **Zero**, full image digest not claimed |
| 156 | 1 | Reset cause or 0xFF unknown |
| 157 | 1 | ABI minor **1** |
| 158 | 1 | Bit0 reset-valid iff reset cause known |
| 159 | 1 | Zero reserved |

Six qualified slots: SRSP queue depth and high-water, async TX depth and high-water, source-qualified SRSP enqueue event count, and UART2 TX_FINISHED **notification** count. Unsupported counters have invalid bits and **zero** data, never fabricated zero observations. These do not establish RF delivery or USB host receipt.

**Reject/quarantine optional diagnostics only** on unknown capability/reserved bits, mismatched nonce, wrong length/magic/major/minor, invalid slots, contradictory token/reset flags, nonsensical depths, or stale same-token sequence. **Never fall back to #104**: #104 interprets capability bit1 as nonce echo, uses 140–155 for reset/fingerprint and places reset/minor elsewhere; even a correct 0xF2 opcode is insufficient to identify its semantics. Compiled pinned herdsman tests exercise that rejection.

## Boot-token invariant and acceptance

TRNG is attempted **at most once per actual chip boot** from the existing NPI task before host UART readiness, with a source-clock-converted 100 ms semaphore wait and cancel-before-close on error. A RAM-only first-attempt guard prevents NPI task re-entry from falsely assigning a new radio epoch without hardware reset; **a first-attempt TRNG failure is not retried**. No TRNG work in command handler, ISR, NV, RF, or key paths. A nonce is transaction correlation, not authentication; the boot token is probabilistic boot identity, not cryptographic attestation. Real hardware behavior and stack margins remain unverified.

**B5 gates:** one isolated combined B1/B2/B3/B4 review with F0/F1/F2 distinct and B1 HOLD intact; verified exact-head native TI ELF/HEX/BIN and original-owner pinned herdsman/Z2M; read-only installed host fingerprint; full coordinator NV/security/IEEE/PAN backup and independently proven rollback before any separately approved isolated physical testing; measure NPI task/ISR stack, heap, entropy/cold-warm reset, UART fairness/USB and OTA under load. **No merge, flash, release, host install, or active Zigbee changes from this decision.**

Authority: [#98](https://github.com/analienx/Zigbee-Coordinator/issues/98), [v3 #100](https://github.com/analienx/Zigbee-Coordinator/pull/100), [superseded #104](https://github.com/analienx/Zigbee-Coordinator/pull/104), [canonical #105](https://github.com/analienx/Zigbee-Coordinator/pull/105), [hardening #110](https://github.com/analienx/Zigbee-Coordinator/pull/110).
