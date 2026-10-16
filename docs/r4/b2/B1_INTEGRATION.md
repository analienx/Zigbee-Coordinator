# B2 → B1 integration contract — deferred until both source gates seal

**NOT EXECUTED / NOT QUALIFIED.** B2 development PR #96 is rooted in B0
`1baefbee8e4de2c9d28c5e1a7c339cf2025a2afe`. B1 sibling
[PR #93](https://github.com/analienx/Zigbee-Coordinator/pull/93) is
draft; do not merge/force cherry-pick B2 into it or edit live hardware.

## Source/ownership separation

| Domain | Authority | B2 disposition |
|---|---|---|
| P7U UART0/NPI only owner, vendor CCFG/NV flash geometry | B0 | Exact B0 image audit; no modifications |
| NV readiness, HOLD_SECURITY/HOLD_NV, final MAC RF admission | B1 | Unchanged; not yet integrated |
| TC link-key persistence, child and NWK security table capacity | B3 | Unchanged; P1 keeps 21 linked AssociatedDevList entries |
| Routing source/neighbor/normal-route tables | B2 | Compiler-option P1 only; linked effect must be proven |
| NPI/MT diagnostic ABI and ownership | Existing diagnostics #87 | No new protocol or second UART path |
| Physical network migration/pilot | R4-07 authorized stage | Prohibited here |

## Proposed integration execution

1. Seal B0+B1+B2 each independently with exact source SHA.
2. Create *new disposable GitHub-hosted integration branch* from the
   reviewed B0 ancestor and apply **B1 first**, then only B2-owned
   compiler options/source files. If one SysConfig file is shared,
   apply its changes with schema-aware assertions, not blind patch.
3. Run source-level diff showing no B2 writes to CCFG, startup order,
   UART ownership, NV/security journal, TCLK/TC tables and B1 hold gate.
4. Real pinned TI CCS native build, ELF/XML/HEX/BIN and P7U UART,
   protected NV2/CCFG and exact vendor CCFG hashes.
5. Simulate HOLD_NV and HOLD_SECURITY *after AF enqueue but before the
   final MAC admission*: assert **zero newly admitted RF sends**.
   Separately simulate healthy NETWORK_READY (no accidental denial).
6. Run all relevant B1 N01–N30 and B2 Annex A T01–T32 compiled-source
   adversarial cases. Missing TI private RTG implementation is a hard
   blocker, not a simulated PASS.
7. Independent reviews of integration diff, at least one negative
   mutated-source control that removes hold gate and must fail.
8. Report B1_B2_INTEGRATED_READY only when evidence complete. No
   production flashing, pairing, OTA, HA/Z2M or release without
   explicit separate approval and B3/physical workstream gates.

## Current hard blockers

- B1 PR #93 not sealed or merged; B2 cannot silently assume READY
  or modify hold/NV semantics.
- TI SDK 8.33 NWK routing implementation is in closed
  `libZStack_nwk_all.a`; issue #95 requires actual compiled route
  code for adversarial T05–T28, which is unavailable here.
- Runtime heap high-water, RF mesh stability and genuine workload
  fairness/latency require separate authorized instrumentation/pilot.

**Never infer a change to PAN/IEEE/network keys from compiling B2.**
