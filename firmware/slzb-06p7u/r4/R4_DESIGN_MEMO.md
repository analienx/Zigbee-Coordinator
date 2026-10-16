# R4-00 design memo (ADR): stock-derived minimal composition

Status: PROPOSED (R4-00, source-only). Issue #85. No hardware claim.
Scope: provenance, parity contract, CI shape. No native code yet.

## Decision

R4 is a new stock-derived line, not a patch over R2/R3:

- Donor: coherent pinned pair at release `lpf2-8.33.00.16`:
  TI lowpower-f2-sdk `3615ad5d` + zstack-examples `87ff5b6`
  (examples commit message names 8.33.00.16 and its
  `cc13xx_cc26xx_sdk` gitlink equals the SDK pin),
  herdsman 10.9.1 (`0968f97`), CCS 12.8.0.00012 /
  TI-ARM-CLANG 3.2.2.LTS / SysConfig 1.21.1.3772
  (re-checked against the upstream 8.33.00.16 release notes
  at the pinned SDK commit: CCS-12.8.0 / TI ARM Clang
  3.2.2.LTS / SysConfig 1.21.1).
- Koenkk Z-Stack-firmware patch + CHANGELOG is a distinct
  comparison donor only (never a build input), NOT identical
  to working 20260310.
- Working 20260310 image (sha256 `f18011d2…626afbe`)
  provenance stays UNKNOWN (source unproven). Historical
  20240710 (`1e257bc0…060d6b`) is catalog history only;
  its `source_unproven: false` is explicit and intended
  (marks a vendor-origin catalog artifact, not source proof).
- See `SOURCE_PROVENANCE.json` (pins + release strings +
  explicit unknowns) and `PARITY_MATRIX.json` (27 entries,
  no overclaim).

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
MT/herdsman compatibility preserved. SOURCE_CONFIRMED marks
donor-confirmed design intent and pinned source digests only,
never fitted-board behavior. Claim taxonomy is
SOURCE_CONFIRMED / SYNTHETIC_TEST / NATIVE_CI /
PHYSICAL_UNVERIFIED / HARDWARE_PROVEN; at R4-00 (source-only)
only SOURCE_CONFIRMED and PHYSICAL_UNVERIFIED validate --
SYNTHETIC_TEST/NATIVE_CI evidence does not exist yet and no
HARDWARE_PROVEN is permitted. All physical gates OPEN.

## Consequences

B0-B4 each need exact-HEAD hosted CI + adversarial review
before advancing. Physical SYS_PING/cold-restart/soak need
separate authorization. R3 stays frozen as learning only.

## Parity-matrix domain growth rule (B1 and later)

REQUIRED_DOMAINS_R4_00 in tools/r4_provenance_validate.py is a
frozen R4-00 snapshot; exact domain-set equality is the R4-00
gate. Adding a legitimate domain later (e.g. at B1) requires a
coordinated change, never a silent validator edit: add a
versioned REQUIRED_DOMAINS_B1 set, gate the equality check on
the manifest phase, add the new-domain entries with evidence,
add/refresh valid + extra-domain fixtures and tests, and record
the change here. A validator edit without the matching
manifest, fixtures, tests and memo entry must fail review.
