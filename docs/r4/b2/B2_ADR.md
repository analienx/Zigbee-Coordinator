# B2-ADR-001 — Fail-closed linked-capacity evidence

Date: 2026-10-16. Decision: start at sealed B0 rather than unreviewed B1.
Mandatory scope and T01–T32 oracle: issue #95 and its Annex A comment.

## Decisions
1. Do not change a TI routing or MAC pool macro until its active projectspec,
   generated configuration, linked symbol, entry sizeof and ownership are known.
2. Do not equate 106 devices with 106 direct children or 106 neighbors.
3. Leave Trust Center, APS/TCLK persistence and network security to B3.
4. Treat `tools/b2_capacity_gate.py` as an auxiliary arithmetic verifier only:
   its caller must attest real exact-commit GitHub-hosted ELF/map provenance,
   and a separate verifier must extract symbols from the native objects.
   String identifiers alone are not cryptographic evidence.
5. Hold B2_SOURCE_READY until all native test, budget, independent review and
   CI gates in issue #95 pass. Runtime heap high-water: UNKNOWN.
6. B1 gating is not implemented by B2; after integration, newly admitted MAC
   transmissions during HOLD_NV/HOLD_SECURITY must be zero.

## Explicit unresolved blockers
- Native B0 ELF XML/map and exact per-table symbol/size data not yet collected.
- Source call chain and failure ownership for NWKSTAT_SOURCE_ROUTE_FAILURE pending.
- P0/P1/P2/P3 real profiles, memory ledger and native tests T01–T32 pending.
- Synthetic unit tests are not TI native-source compiled tests.
- No real high-density RF qualification; PHYSICAL_UNVERIFIED.

This ADR is an implementation checkpoint, not a claim of completed B2.
