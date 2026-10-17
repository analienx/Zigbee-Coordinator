# R4 B5 — source-only B1/B4 coexistence probe

**DRAFT / NOT SOURCE READY / NO FLASH.**

Pinned B4 canonical base: \`3231abb1f13210eb88afe13ff7b7f9f29709cd6b\`. B1 #94 source is read by immutable SHA, never merged. B1's own production management patch preflights genuine pristine TI 8.33 and exact herdsman before authentic B4 F0/F2 source overlays are applied. Its MT/NPI/UART transformations then run against the actual B4-modified code, with fail-closed checks for F0/F1/F2 command ownership, B1 HOLD, UART events, NPI counters and TRNG one-attempt guard.

**Scope limitation:** Only B1 management MT/NPI/UART source patch *compatibility*, not full B1 NV/security, B2/B3, native CCS link, startup/runtime stacks, host installation or physical safety. This probe cannot authorize merge, native rollout or flash. Do not modify real devices or network. A subsequent isolated full native integration/independent review and complete backup/rollback are mandatory.

## Full B1 source extension

After exact B1 management preflight and authentic B4 overlays, the runner now invokes B1's **actual complete `apply_b1.overlay()`** for NV admission, security, ZMac, ZDO, startup and transport; only the management preparer is replaced with the exact already-preflighted B1 transforms recomputed on post-B4 source. Every other B1 input SHA check and source mutation remains active. This is *full source composition*, **NOT a native/linked image**. In particular B1's embedded public source prefix identifies B1 only, not the composite binary; a combined image digest must be redesigned before any B5 acceptance or release. B1/NV security has no physical approval and real coordinator flash is forbidden.
