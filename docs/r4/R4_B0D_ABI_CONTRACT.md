# R4 B0-D ABI contract (Deliverable B)

Status: CONTRACT ONLY. B0-minimal ships first with ZERO diagnostics.
B0-D is a read-only versioned MT diagnostic modeled on the proven
P10 F0 v2 / 102 B / 25-counter ABI. R4-00 Wonder gate stays OPEN
and gates any B0/B0-D implementation. No firmware written here.

## B0-minimal (first, zero diagnostics)

B0 is the stock-derived board-correct build with no custom MT command,
no counter block, no NV writes, no RF side effects. B0 must keep:

- Stock startup order, TI NPI ownership, UART2 completion semantics
  (per the R4-00 design memo's B0 profile; the memo was removed from `main`
  on 31 Oct 2026 and remains in history at commit `8ec1439` (PR #195)).
- SYS_PING / SYS_VERSION + herdsman ABI reachable.
- Single ZNP owner; MT/herdsman compatibility preserved.

## B0-D (read-only diagnostic extension, after B0 + gate)

### Wire format (copied from proven P10 ABI, scout prior result 1)

- MT SYS command ID `0xF0`, version 2, payload 25 x u32 little-endian.
- Reply body: `{u8 version (=2), u8 flags, 25 x u32 LE counters}`,
  total `2 + 25*4 = 102` bytes; SRSP built via
  `MT_BuildAndSendZToolResponse` (TI SDK `source/ti/zstack/mt/mt.c:316`
  at `3615ad5d`).
- Decoder constants: `VERSION=2`, `SIZE=102`; 102-bytes-only
  (P10 `firmware/t832/min/npi_diag_decode.py` L22-23/L27/L31-32/L36-38
  at `b273044`).

### Counter list (exact P10 names; TI source hooks are the B0-D proof obligation)

C names (`firmware/t832/min/npi_diag_patch.py` L15-23 at `b273044`) /
decoder names (`firmware/t832/min/npi_diag_decode.py` L12-20):

1. `srspDepth` / `srsp_depth` — NPI TX-queue SRSP depth hook.
2. `srspHighWater` / `srsp_high_water` — SRSP HWM hook.
3. `asyncDepth` / `async_depth` — async queue depth hook.
4. `asyncHighWater` / `async_high_water` — async HWM hook.
5. `srspEnqueued` / `srsp_enqueued`.
6. `srspTxAccepted` / `srsp_uart_accepted`.
7. `asyncTxAccepted` / `async_uart_accepted`.
8. `txImmediateRejects` / `tx_immediate_rejects`.
9. `txRejectedDrops` / `tx_rejected_drops`.
10. `stackFrameFailed` / `stack_frame_failures`.
11. `stackQueueFailed` / `stack_queue_failures`.
12. `srspAllocFailed` / `srsp_allocation_failures`.
13. `srspEnqueueFailed` / `srsp_enqueue_failures`.
14. `rxFrameFailed` / `rx_frame_failures`.
15. `srspQueueFallback` / `srsp_queue_fallbacks`.
16. `afDirectAccepted` / `af_direct_accepted`.
17. `afDirectBufferFull` / `af_direct_buffer_full`.
18. `afDirectMemFailed` / `af_direct_memory_failure`.
19. `afDirectOther` / `af_direct_other`.
20. `afSourceAccepted` / `af_source_accepted`.
21. `afSourceBufferFull` / `af_source_buffer_full`.
22. `afConfirmCcaFailed` / `af_confirm_cca_failure`.
23. `afConfirmOtherFailed` / `af_confirm_other_failure`.
24. `rxOverflowEvents` / `rx_overflow_events`.
25. `rxOverflowDiscardedBytes` / `rx_overflow_discarded_bytes`.

Every hook above is UNPROVEN at R4-B0 contract time: each counter's
exact TI source hook (e.g. `NPITask_ProcessTXQ`, `NPITask_sendToHost`,
`NPITask_processStackMsg`, `NPITL_checkNpiBusy`) must be pinned to a
repo@sha path:line before implementation. No numeric UNKNOWN sentinel exists in P10 V2; all 25 u32 fields,
including 0xFFFFFFFF, are legitimate measurements. A counter without
source-proven hooks disqualifies the claimed V2 evidence and must not
be zero-filled or replaced with 0xFFFFFFFF. Partially implemented
counter sets require a distinctly versioned ABI validity bitmap.

### Header fields

- magic: MT SYS `0xF0` SRSP framing (no separate magic word; version
  field disambiguates).
- version: u8 = 2 (reject any other version; strict decoder).
- caps/flags: u8 bitmask, donor-strict (P10 `npi_diag_decode.py`:
  bit 0 `srsp_priority_queue_enabled`, bit 1 `uart_retry_pending`,
  bit 2 `uart_transport_busy`; any other bit set is rejected, never
  preserved). B0-D adopts donor strictness exactly; this corrects the
  earlier draft claim that v2 defines no bits.
- Radio boot epoch is absent in V2: a host restart timestamp does not
  identify radio-only resets. V2 decoders reject longer frames.
- Sample sequence is absent in V2; a host sample number does not prove
  the radio has not rebooted. Compute no deltas without verified
  radio-epoch continuity.

### Safety invariants (B0-D)

- Read-only: no NV writes, no CCFG/flash writes, no RF TX, no
  key/counter mutation. IRQ safety via the same critical-section
  discipline as the donor (`OsalPort_enterCS`/`leaveCS` call sites
  in `npi_task.c`/`npi_tl.c` at `3615ad5d`); snapshot counters under
  CS, build/send outside CS.
- All u32 counters can wrap modulo 2^32, but arithmetic deltas are
  valid only after radio continuity is independently verified.
  A reboot with zeroed RAM counters can masquerade as numeric wrap.
- No RF side effects: handler never calls AF/NWK/TX paths; it only
  snapshots and replies.

### F0 collision audit outcome

- SOURCE PROVEN: TI `mt_sys.c:246-398` at `3615ad5d` dispatches on
  `pBuf[MT_RPC_POS_CMD1]`; `0xF0` has no case label and falls to
  `default` -> `MT_RPC_ERR_COMMAND_ID` (`mt_rpc.h:131`).
- SOURCE PROVEN: herdsman `definition.ts` SYS block (lines 20-422)
  holds 40 entries, max SYS ID 130; zero hits for ID 240, so SYS
  240 (`0xF0`) does not exist in herdsman 10.9.1.
- Outcome: `0xF0` is FREE on both sides at the pinned SHAs; B0-D may
  claim MT SYS `0xF0` for the versioned diagnostic.
- Fallback extension point if unsafe: if any donor/future audit finds
  `0xF0` assigned, B0-D moves to the next lowest unassigned SYS ID
  proven free by the same two-sided audit (TI `mt_sys.c` case list +
  herdsman `definition.ts` ID scan), keeping version 2 / 102 B /
  25-counter layout unchanged. Version field, not command ID, carries
  compatibility.

### Proposed V3 ABI — source-only specification

Legacy P10 V2 remains exactly 102 bytes and cannot encode UNKNOWN.
R4 V3 is a separate 132-byte design, with LE fields:

Offset 0: ASCII R4D3 magic, 4 bytes; offset 4: version=3, u8;
offset 5: flags, u8 (legacy bits 0-2 only); offset 6: size=132, u16;
offset 8: capabilities, u32 (bit 0 = valid radio boot identity);
offset 12: validity bitmap, u32 (counter bits 0-24 only);
offset 16: radio_boot_id, u64; offset 24: uptime_ms, u32;
offset 28: sample_seq, u32; offsets 32-131: 25 u32 counters.
A cleared validity bit means unavailable, not a reserved numeric value.

The boot-id capability MUST remain disabled unless the native firmware
can prove a per-boot source of sufficiently unique identity. If not,
send ID zero and disallow radio continuity conclusions. Matching host
epochs are never enough. Counter deltas additionally require matching
radio ID, valid fields and coherent uptime/sequence.

The pure offline reference model (R4-01a `r4_diag_reference.py`, verified
only against synthetic fixtures) was removed from `main` on 31 Oct 2026; it
remains in history at commit `8ec1439` (PR #195).
V3 MT command ID allocation, TI source hooks, actual compiled ELF,
entropy and field qualification remain separate future acceptance
gates. This stage does NOT implement firmware/host diagnostics.


### Decoder trust boundary

The source-only reference function trustworthy_radio_epoch() defaults
to false even if both wire messages claim boot-identity capability.
The higher-level host caller must explicitly provide source_qualified
ONLY after independent native proof of the per-boot identity source.
An attacker- or buggy-radio-supplied capability bit is not external
attestation. No such native qualification has been performed.
