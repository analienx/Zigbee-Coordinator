# R4-00 design memo (ADR): stock-derived minimal composition

Status: PROPOSED (R4-00, source-only). Issue #85. No hardware claim.
Scope: provenance, parity contract, CI shape. No native code yet.

## Decision

R4 is a new stock-derived line, not a patch over R2/R3:

- Donor: clean pinned TI lowpower-f2-sdk `6499c3f`
  + zstack-examples `87ff5b6` (SDK 8.32), herdsman 10.9.1
  (`0968f97`), CCS 12.8.0.00012 / TI-ARM-CLANG 3.2.2.LTS /
  SysConfig 1.21.1.3772.
- Koenkk Z-Stack-firmware patch + CHANGELOG is a distinct
  comparison donor only, NOT identical to working 20260310.
- Working 20260310 image (sha256 `f18011d2…626afbe`)
  provenance stays UNKNOWN (source unproven). Historical
  20240710 (`1e257bc0…060d6b`) is catalog history only.
- See `SOURCE_PROVENANCE.json` (pins + explicit unknowns)
  and `PARITY_MATRIX.json` (22 entries, no overclaim).

## Per-feature profiles B0-B4 (explicit, no G7-mandatory)

- B0 minimal board-correct build: stock startup order, TI
  NPI ownership, UART2 completion semantics, DIO12/DIO13
  115200 flow-off preserved, C/IRQ 4096 evaluated with
  map proof, donor NV layout preserved, SYS_PING/VERSION
  + herdsman ABI reachable. No custom G7 scheduler/latch.
- B1 observable fail-closed NV/security: staged states
  incl. HOLD_NV/HOLD_SECURITY/HOLD_TRANSPORT, immutable
  keys/counters on failed restore, host-readable fault.
- B2 measured mesh capacity: linked TC/routes/neighbors/
  buffers/retries with RAM budget; no blind community copy.
- B3 deliberate NV strategy: NV3-vs-NV5 by row counts +
  wear evidence; migration simulator with stated gaps.
- B4 bounded diagnostics: single versioned read-only SYS
  endpoint reusing one owner; default off, no key leakage.
- B5 transport experiment is optional and never blocks B0-B4.

## Invariants (from #85)

No NV5-implicit-migration. No auto erase of NV/CCFG/chip.
No full-flash writer creep into NV/CCFG. Single ZNP owner.
MT/herdsman compatibility preserved. Claim taxonomy is
SOURCE_CONFIRMED / SYNTHETIC_TEST / NATIVE_CI /
PHYSICAL_UNVERIFIED / HARDWARE_PROVEN; at R4-00 (source-only)
only SOURCE_CONFIRMED and PHYSICAL_UNVERIFIED validate --
SYNTHETIC_TEST/NATIVE_CI evidence does not exist yet and no
HARDWARE_PROVEN is permitted. All physical gates OPEN.

## Consequences

B0-B4 each need exact-HEAD hosted CI + adversarial review
before advancing. Physical SYS_PING/cold-restart/soak need
separate authorization. R3 stays frozen as learning only.
