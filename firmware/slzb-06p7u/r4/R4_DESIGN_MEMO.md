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
  to working 20260310. Pinned to exact commit `5e4db67e`
  (tag `Z-Stack_3.x.0_coordinator_20250321`); patch blob
  `e015d9a9…e1fdb` + CHANGELOG blob `25f8bb3f…650`
  recorded from the contents API at that commit (see
  `SOURCE_PROVENANCE.json` pin_evidence for the method).
- Working 20260310 image (sha256 `f18011d2…626afbe`)
  provenance stays UNKNOWN; `binary_source_equivalence`
  is UNKNOWN for BOTH images (no binary-to-source proof
  for either). `vendor_catalog: LISTED` records the
  vendor-channel URL/filename/bytes tuple only, never
  source proof. Historical 20240710 (`1e257bc0…060d6b`)
  is catalog history only (`CATALOG_HISTORICAL`).
- Toolchain installer/download digests were never sourced:
  recorded explicitly UNKNOWN, never fabricated.
- See `SOURCE_PROVENANCE.json` (pins + release strings +
  explicit unknowns) and `PARITY_MATRIX.json` (27 entries,
  no overclaim).

## Per-feature profiles B0-B4 (explicit, no G7-mandatory)

- B0 minimal board-correct build: stock startup order, TI
  NPI ownership, UART2 completion semantics, DIO12/DIO13
  115200 flow-off preserved, C/IRQ 4096 evaluated with
  map proof, donor NV layout preserved (donor layout only,
  never stock-20260310 NV compat -- see B0 stock-NV gate
  below), SYS_PING/VERSION
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
an observed source fact with an exact upstream anchor
(repo + commit/blob + path), never future intent or
fitted-board behavior; at R4-00 only `c-irq-stack` qualifies
(Koenkk comparison-donor patch anchor). Claim taxonomy is
SOURCE_CONFIRMED / PHYSICAL_UNVERIFIED only -- no
SYNTHETIC_TEST / NATIVE_CI / HARDWARE_PROVEN statuses exist
at R4-00 and the validator rejects them. Claim/evidence/
verification must be nonempty trimmed strings within
documented length bounds, and evidence must carry a
traceable anchor (upstream path/blob/commit, issue ref, or
URL). Validator checks are manifest-consistency, not external
source-integrity proof; proof lives only in the hosted
`r4-00-upstream-attestation` job. All physical gates OPEN.

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

## Deterministic two-SHA seal protocol (R4-D02)

The review packet never self-certifies its own SHA. CODE_SHA is
the reviewed code commit; the packet records CODE_SHA, which must
equal its parent commit (the packet is regenerated in a seal
commit on top of the code commit). The packet's own seal SHA is
recorded only in the external issue-#85 checkpoint triple
CODE_SHA / SEAL_SHA / CI-runs, never pre-written inside the
packet. `pending push`, `uncommitted`, and stale-CI language
are forbidden in the packet: every CI receipt cites the exact
HEAD it ran on.

## B0 stock-NV architecture gate (R4-D09)

An independent review (PR #86 comment 6209730355) observed that
`nvocmp.c/h`, `NVSCC26XX.c`, `npi_tl_uart.c`, `npi_tl.c`,
`npi_task.c`, `npi_frame_mt.c`, and `UART2CC26X2.c` are
byte-identical across SDK 8.32 (`6499c3f5`) and 8.33
(`3615ad5d`). This narrows -- but does NOT close -- the
8.32-to-8.33 delta: it says nothing about board-generated
SysConfig, linker, CCFG, startup integration, NV geometry, or
safe restore, and it is cited here as a review observation,
NOT as our CI proof. `donor NV layout preserved` (B0 profile
above) means the TI donor layout only; donor-layout
preservation is NOT stock-20260310 NV compatibility, which is
unproven. Production-stock-NV boot with B0 is EXPLICITLY
PROHIBITED until an independent read-only compatibility proof
plus a separately authorized disposable-device trial both
exist. Physical gates stay OPEN; PHYSICAL_UNVERIFIED
throughout; zero HARDWARE_PROVEN.
