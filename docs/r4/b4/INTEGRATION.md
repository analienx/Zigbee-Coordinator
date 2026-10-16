# R4 B4 isolated integration ADR — B0/B1/B2/B3

B4 exists on exact B0 baseline; no sibling worktree is modified, and B1/B2/B3 are not merged or rebased here. **Combined integration: PENDING**.

**B1:** if `HOLD_NV` or `HOLD_SECURITY`, a bounded SYS F0 diagnostic is read-only *only if* NPI is responsive. B4 must not form/join RF, read or write NV keys, suppress security hold, or fake state. No B1 API contract may be assumed until B1 source is sealed.

**B2:** optional routing/queue metrics are all unavailable until B2 actual producer code, memory semantics and validity mask are source proved in one combined ELF. B4 never modifies queue priorities or scheduling; B5 owns optional scheduler changes.

**B3:** only nonsecret error domain/stage may be imported under explicit schema version, never network/security data or private protected state. Do not infer that persistent NV state means radio boot epoch continuity.

**B0 invariants:** preserve same example/SDK SHA and CCS/Clang/SysConfig versions, P7U UART0 DIO12/DIO13 115200 no flow, 88-byte CCFG, and protected NV. Require two native rebuilt ELFs/HEX/BIN and link-map/memory deltas vs B0, not SHA on source-only code.

**Integration order:** independently confirm B1 N01–N30, B2 T01–T32, B3 M01–M36 source gates and commit hashes; create a *different* integration branch; combine exact pinned commits; run their regressions plus B4 D01–D36 and source mutants; independent four-lens review; then consider source-ready. Nothing authorizes live coordinator or HA tests without R4-07 approval.
