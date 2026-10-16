# WONDER_REVIEW_PACKET — R4-00 (issue #85)

Scope: R4-00 provenance/parity source foundation only. Not firmware. No radio/HA operations performed.

## Exact candidate

- PR: https://github.com/analienx/Zigbee-Coordinator/pull/86 (DRAFT)
- Branch: `feat/p7u-r4-stock-derived-redesign`
- HEAD: `a87ff29664ab6366b46ff27501c79a79aba8fb67`
- Base: `a48fa9deda36a9fc44624fcd142d5fa1533a449a`
- 16 files added, 521 insertions, 0 deletions.

## Source manifest (all under HEAD)

- `firmware/slzb-06p7u/r4/SOURCE_PROVENANCE.json` — donor pins + unknowns
- `firmware/slzb-06p7u/r4/PARITY_MATRIX.json` — 22 entries, one per required domain
- `firmware/slzb-06p7u/r4/R4_DESIGN_MEMO.md` — ADR (explicit per-feature B0–B4 composition; no G7-mandatory; no NV5-implicit-migration)
- `firmware/slzb-06p7u/r4/tools/r4_provenance_validate.py` — stdlib validator
- `firmware/slzb-06p7u/r4/tools/r4_parity_audit.py` — audit-report generator
- `firmware/slzb-06p7u/r4/fixtures/{valid,invalid}/` — 2 valid + 6 invalid fixtures
- `tests/test_r4_00_provenance.py`, `tests/test_r4_00_parity.py` — stdlib unittest contracts
- `.github/workflows/test-r4-00-provenance.yml` — hosted-only CI (ubuntu-latest, Python 3.12, checkout at exact SHA)

## Source reference evidence (author's stated basis, verify independently)

- TI lowpower-f2-sdk `6499c3f53fc5fb5806213be695450a7b43fbaf3d`, zstack-examples `87ff5b638b632050228a7504f35cf3b95581c278`, herdsman 10.9.1 `0968f979d558874b17396c96b66382d4236bbdcd`, CCS 12.8.0.00012 / TI-ARM-CLANG 3.2.2.LTS / SysConfig 1.21.1.3772 — Pins copied from prior R2 parity record; upstream authenticity NOT independently re-verified in this phase.
- Vendor 20260310 container sha256 `f18011d2…626afbe`, provenance UNKNOWN, source_unproven true. Vendor 20240710 sha256 `1e257bc0…060d6b`, catalog-historical. No binary↔source equivalence claimed.
- Koenkk Z-Stack-firmware patch/CHANGELOG treated as DISTINCT donor, `identical_to_20260310: false`.
- Matrix statuses restricted to SOURCE_CONFIRMED / PHYSICAL_UNVERIFIED. Zero HARDWARE_PROVEN. All physical gates OPEN.

## Hosted CI receipts (exact HEAD)

- Push run at `a87ff29`: R4-00 provenance and parity → success (12s). Run: https://github.com/analienx/Zigbee-Coordinator/actions/runs/38854230120
- PR runs: r4-00-contracts pass, unittest (existing P10 suite) pass. Checks: `gh pr checks 86`.
- No local build/test claims; no self-hosted runners.

## Spark review history (author's record, re-verify)

1. Coder-reviewer workflow (1 writer + 3 lenses + challenger): aggregate FAIL. P0s fixed in HEAD: fail-closed status set, duplicate-domain rejection, duplicate-rev rejection, six evidence re-cites, three new negative fixtures.
2. Focused re-review of fix diff: PASS (static trace; no P0–P1; three P3 robustness notes below). Dynamic proof rests on hosted CI, not on the re-review.

## Best attacks for Wonder (unresolved, in priority order)

1. Upstream pin authenticity: confirm each SHA exists upstream and matches the claimed content; confirm Koenkk patch era (TI 8.30) vs SDK 8.32 delta is characterized, not assumed.
2. Validator crash-vs-clean-fail: JSON `null` values (e.g. `sha256: null`) raise uncaught TypeError (traceback, exit nonzero) instead of error lines; dict-shaped `vendor_images` similar. Fail-closed but ugly.
3. Extra-domain permissiveness: a 23rd novel-domain entry validates; one-entry-per-domain is enforced only against duplicates.
4. `HARDWARE_PROVEN` rejection shares a code branch with other bad statuses; no dedicated fixture (covered indirectly via `matrix_bad_status.json`).
5. Evidence strings cite issue #85 prose, not fitted-unit measurements; B0 must replace each PHYSICAL_UNVERIFIED with map/ELF/authorized-trial evidence or keep it open.
6. No B0–B4 code exists yet; profile-composition architecture is a memo promise, not a demonstrated mechanism.

## Acceptance mapping (for Wonder to adjudicate)

- A0: no radio/HA ops in diff (source/docs/CI only); CI hosted-only. Verify via diff + workflow YAML.
- A1: UNKNOWN preserved by validator + `provenance_known`/`provenance_dup_rev` fixtures. Verify via CI logs.
- A2: 22-domain matrix, hypotheses tagged PHYSICAL_UNVERIFIED. Verify each entry against #85 text.
- A3: memo only; no B0 code. Adjudicate as plan, not proof.
- A4: validator + audit + fixtures + hosted workflow green at exact HEAD. Verify via CI receipts above.
- A5: Spark lane reports (this packet §History) are author-supplied; Wonder must independently re-derive.
- A6: this packet + draft PR; no merge performed.

No author conclusory claims: nothing above asserts R4-00 ACCEPTED, hardware-ready, or production-ready. PHYSICAL_UNVERIFIED throughout.
