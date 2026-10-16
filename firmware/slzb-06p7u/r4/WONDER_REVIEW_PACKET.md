# WONDER_REVIEW_PACKET — R4-00 (issue #85)

Scope: R4-00 provenance/parity source foundation only. Not firmware. No radio/HA operations performed.

## Exact candidate

- PR: https://github.com/analienx/Zigbee-Coordinator/pull/86 (DRAFT)
- Branch: `feat/p7u-r4-stock-derived-redesign`
- HEAD: `8f44662a234cb7813eeaecfd1c8786d8cf6964f2` (Wonder-findings fix commit; prior R4-00 commits `a87ff29` manifests/tools/fixtures and `0ceb101` packet v1; packet regenerated in the seal commit on top)
- Base: `a48fa9deda36a9fc44624fcd142d5fa1533a449a`
- Working tree: uncommitted R4-00 Wonder-fix revision on top of HEAD
  (donor re-pin to 8.33, 27-domain matrix, strict validators,
  single-fault fixtures, pinned CI). File list in §Source manifest.

## Source manifest (all under working tree)

- `firmware/slzb-06p7u/r4/SOURCE_PROVENANCE.json` — coherent 8.33 donor pair + unknowns
- `firmware/slzb-06p7u/r4/PARITY_MATRIX.json` — 27 entries, one per required domain
- `firmware/slzb-06p7u/r4/R4_DESIGN_MEMO.md` — ADR (explicit per-feature B0–B4 composition; no G7-mandatory; no NV5-implicit-migration)
- `firmware/slzb-06p7u/r4/tools/r4_provenance_validate.py` — stdlib strict validator (single source of truth for pins/domains)
- `firmware/slzb-06p7u/r4/tools/r4_parity_audit.py` — audit-report generator (exits nonzero on invalid input)
- `firmware/slzb-06p7u/r4/fixtures/{valid,invalid}/` — 2 valid + 20 invalid fixtures (all single-fault isolated)
- `tests/test_r4_00_provenance.py`, `tests/test_r4_00_parity.py` — stdlib unittest contracts (import pins/domains from validator)
- `.github/workflows/test-r4-00-provenance.yml` — hosted-only CI (ubuntu-latest, Python 3.12, SHA-pinned actions, exact-SHA checkout, validator + audit CLI gates)

## Source reference evidence (independently re-verified via read-only gh api)

- simplelink-zstack-examples `87ff5b638b632050228a7504f35cf3b95581c278`:
  commit message "SimpleLink LPF2 8.33.00.16 zstack examples update";
  tree entry `cc13xx_cc26xx_sdk` (gitlink, mode 160000) is
  `3615ad5d3f4f271258d18a2f5ce1785064ff9a58`.
- simplelink-lowpower-f2-sdk `3615ad5d3f4f271258d18a2f5ce1785064ff9a58`:
  commit message "SimpleLink lpf2-8.33.00.16 update"; tag
  `lpf2-8.33.00.16` exists in the same repo. Coherent 8.33 pair
  (option (a)); the old 8.32 SDK pin `6499c3f5` ("SimpleLink
  lpf2-8.32.00.07 update") is dropped. Examples tag
  `lpf2-8.33.00.16-zstack` exists upstream.
- Toolchain compat re-checked against the 8.33.00.16 release notes
  blob at the pinned SDK commit: "TI Code Composer Studio:
  CCS-12.8.0", "TI ARM Clang Compiler tools: 3.2.2.LTS",
  "SysConfig Standalone tool ...: 1.21.1". Pins 12.8.0.00012 /
  3.2.2.LTS / 1.21.1.3772 stand unchanged. herdsman 10.9.1
  `0968f979d558874b17396c96b66382d4236bbdcd` unchanged.
- Vendor 20260310 container sha256 `f18011d2…626afbe`, provenance UNKNOWN, source_unproven true. Vendor 20240710 sha256 `1e257bc0…060d6b`, CATALOG_HISTORICAL with explicit source_unproven false (catalog artifact, not source proof). No binary↔source equivalence claimed.
- Koenkk Z-Stack-firmware patch/CHANGELOG is a distinct comparison donor (never a build input), `identical_to_20260310: false`.
- Matrix statuses restricted to SOURCE_CONFIRMED (donor-confirmed design intent / pinned digests only) / PHYSICAL_UNVERIFIED. Zero HARDWARE_PROVEN. All physical gates OPEN.

## Hosted CI receipts (exact HEAD)

- Push run at `a87ff29`: R4-00 provenance and parity → success (12s). Run: https://github.com/analienx/Zigbee-Coordinator/actions/runs/38854230120
- PR runs: r4-00-contracts pass, unittest (existing P10 suite) pass. Checks: `gh pr checks 86`.
- No local build/test claims; no self-hosted runners.
- New in this revision (hosted proof pending push): PR checkout uses
  `github.event.pull_request.head.sha`, push uses `github.sha`;
  actions pinned by SHA (`actions/checkout@11d5960a`,
  `actions/setup-python@a26af69b`); validator CLI and audit CLI run
  against the real manifests and fail the job on nonzero.

## Wonder-fix changelog (this revision vs HEAD 0ceb101)

- P0 donor coherence: SDK re-pinned 6499c3f5 (8.32.00.07) →
  3615ad5d (lpf2-8.33.00.16); both donors carry `release`
  strings; validator enforces cross-version consistency
  (coherent 8.33 pair) + `provenance_sdk_mismatch.json` negative
  fixture. `sdk_version` is now `8.33` everywhere.
- P1 five domains added: image-vectors, linker-script,
  memory-geometry, mac-layer, application-version (27 total);
  validator requires exact domain-set equality plus a mandatory
  non-empty `verification` field; `matrix_extra_domain.json`
  negative fixture.
- P1 CI checkout: pull_request → head.sha, push → github.sha.
- P1 strictness: duplicate JSON keys rejected via object_pairs_hook
  in validator, audit tool, and test loaders
  (`provenance_dup_key.json`, `matrix_dup_key.json`); top-level /
  entry / vendor key allowlists; phase/issue/sdk_version, donor
  repo strings, vendor URL prefix, and source_unproven semantics
  enforced; unknowns must be non-empty strings with 20260310
  substance (`provenance_unknowns_x.json` proves `["x"]` fails).
- P2 clean failures: null sha256, dict vendor_images, list
  toolchain, unhashable/non-string id/domain, and non-dict
  entries all yield error lines with exit 1 (no tracebacks);
  isolated single-fault fixtures for each plus a dedicated
  HARDWARE_PROVEN fixture; bad_sha/known split into single-fault
  fixtures with per-guard assertions; tests import
  EXPECTED_PINS/REQUIRED_DOMAINS from the validator.
- P2 overreach: R4-P01/P05/P15 rephrased as donor-confirmed
  design intent; Koenkk uniformly "distinct comparison donor
  (never a build input)".
- P3 actions pinned by SHA; 20240710 source_unproven:false
  resolved explicitly and documented (validator comment + memo).
- Audit CLI now exits nonzero on invalid matrix/provenance; CI
  runs both tool CLIs against the real manifests.
- Parent repairs after second Spark workflow (aggregate FAIL):
  `provenance_known.json` reduced to a single fault
  (provenance-only flip, len==1 assertion); domain set frozen as
  REQUIRED_DOMAINS_R4_00 with a documented B1 growth procedure
  (validator comment + memo rule); R4-P02 rephrased as
  donor-comparison intent; catalog_sdk clarified as vendor
  metadata via `catalog_labels_note`; Koenkk role retagged
  DISTINCT_COMPARISON_DONOR; three new isolated fixtures
  (matrix_dup_id, provenance_bad_url, provenance_40710_flip);
  fixed a test-file syntax error the coder introduced.
  Scoped out (no isolated fixtures, enforced in code only):
  phase/issue/sdk_version value mismatches, donor repo-string
  mismatches, top-level key allowlists, empty claim/evidence
  fields, 26-domain missing-only coverage.

## Best attacks for Wonder (remaining, in priority order)

1. Upstream pin authenticity beyond gh-api reads: confirm each SHA's content out-of-band; confirm Koenkk patch era (TI 8.30) vs SDK 8.33 delta is characterized, not assumed.
2. Evidence strings cite issue #85 prose, not fitted-unit measurements; B0 must replace each PHYSICAL_UNVERIFIED with map/ELF/authorized-trial evidence or keep it open.
3. No B0–B4 code exists yet; profile-composition architecture is a memo promise, not a demonstrated mechanism.
4. Hand-verification risk: no local build/test/lint/python was executed
   in this revision by author constraint; correctness rests on
   hosted CI at push plus Wonder's independent re-derivation.

## Acceptance mapping (for Wonder to adjudicate)

- A0: no radio/HA ops in diff (source/docs/CI only); CI hosted-only. Verify via diff + workflow YAML.
- A1: UNKNOWN preserved by validator + `provenance_known`/`provenance_dup_rev` fixtures. Verify via CI logs.
- A2: 27-domain matrix, hypotheses tagged PHYSICAL_UNVERIFIED. Verify each entry against #85 text.
- A3: memo only; no B0 code. Adjudicate as plan, not proof.
- A4: validator + audit + fixtures + hosted workflow green at exact HEAD. Verify via CI receipts above.
- A5: Spark lane reports (§History below) are author-supplied; Wonder must independently re-derive.
- A6: this packet + draft PR; no merge performed.

## Spark review history (author's record, re-verify)

1. First coder-reviewer workflow (1 writer + 3 lenses + challenger): aggregate FAIL. P0s fixed: fail-closed status set, duplicate-domain rejection, duplicate-rev rejection, six evidence re-cites, three negative fixtures.
2. Focused re-review of fix diff: PASS (static trace; no P0–P1; three P3 robustness notes). Dynamic proof rests on hosted CI, not on the re-review.
3. Wonder HIGH independent review (comment 6208880928): verdict FAIL with 10 findings (P0 donor incoherence; P1 missing domains/CI exactness/permissiveness/dup-keys; P2 unknowns/crashes/mirroring/overreach; P3 pins/taxonomy). All fixed in commit 8f44662 per the changelog above.
4. Second Spark workflow on the Wonder fixes: aggregate FAIL on narrow items (dual-fault known fixture; exact-domain brittleness for B1; unexercised guard paths; minor phrasing). Repaired by parent as listed above; dynamic proof rests on hosted CI at the seal HEAD, not on either workflow.

No author conclusory claims: nothing above asserts R4-00 ACCEPTED, hardware-ready, or production-ready. PHYSICAL_UNVERIFIED throughout.
