# WONDER_REVIEW_PACKET — R4-00 (issue #85)

Scope: R4-00 provenance/parity source foundation only. Not firmware. No radio/HA operations performed. PHYSICAL_UNVERIFIED throughout; zero HARDWARE_PROVEN.

## 1. Exact candidate

- PR: https://github.com/analienx/Zigbee-Coordinator/pull/86 (DRAFT)
- Branch: `feat/p7u-r4-stock-derived-redesign`
- CODE_SHA (reviewed code commit; this packet's parent-to-be): `f3c37d68fa09ad5caff909e14fe5afdd7c6a74f7`
- Prior seal baseline (history only, not current HEAD): `139a682`
- Commit chain since prior seal: `3e80529` (D01-D09 fixes), `10ed559` (P0/P1 repair round), `d4725b6` (YAML coercion fix), `f3c37d6` (re-review micro-repairs)
- Seal-commit note (R4-D02 protocol): this packet records CODE_SHA `f3c37d6`, which must equal its parent commit after the seal commit lands on top. The packet's own SEAL_SHA is never pre-written here. SEAL_SHA plus the triple CODE_SHA / SEAL_SHA / CI-runs will be recorded ONLY in the external issue-#85 checkpoint comment.
- Findings under review: PR #86 comment `6209730355` (R4-D01..D09) + issue #85 comment `6209735519`.
- No merge performed. No B0 code in scope.

## 2. Hosted CI receipts at CODE_SHA

All three runs at exactly `f3c37d68fa09ad5caff909e14fe5afdd7c6a74f7`, all success:

- Push run `38871795189` (r4-00-contracts + r4-00-upstream-attestation): https://github.com/analienx/Zigbee-Coordinator/actions/runs/38871795189
- PR run `38871800228` (r4-00-contracts + r4-00-upstream-attestation): https://github.com/analienx/Zigbee-Coordinator/actions/runs/38871800228
- Unittest run `38871800145`: https://github.com/analienx/Zigbee-Coordinator/actions/runs/38871800145

## 3. Upstream evidence observed in hosted CI at CODE_SHA

Positive attest lines (from `r4_upstream_attest.py` via the `r4-00-upstream-attestation` job):

- 4 exact-SHA fetches green: zstack-examples `87ff5b638b632050228a7504f35cf3b95581c278`, lowpower-f2-sdk `3615ad5d3f4f271258d18a2f5ce1785064ff9a58`, zigbee-herdsman `0968f979d558874b17396c96b66382d4236bbdcd`, koenkk-firmware `5e4db67e550d41ea6dc6cd86ceeb04d82ffe1bfb`.
- Examples gitlink: `cc13xx_cc26xx_sdk` mode `160000` equals SDK pin `3615ad5d3f4f271258d18a2f5ce1785064ff9a58`.
- SDK commit message names release `lpf2-8.33.00.16`.
- Koenkk `ls-tree` match: `coordinator/Z-Stack_3.x.0/firmware.patch` mode `100644 blob` equals `e015d9a9020e08d049515664693b22a9ce0e1fdb`; `CHANGELOG.md` mode `100644 blob` equals `25f8bb3fb3bafe22b860d9a00134a2d722272650`.
- Vendor downloads: manifest `url` bytes sha256 match for rev `20260310` (`f18011d2652651e36d5e1e7e1cb1f7cbcb99e9493eacbbf8e404a036c626afbe`) and rev `20240710` (`1e257bc066e7a8db9c12e0b826791cc81d8744b9453355af0f4efce194060d6b`).
- Identity tripwire green: 11 manifest-vs-`EXPECT_*` comparisons pass before any network use.

7 message-asserting negative controls (same job, all green at CODE_SHA):

- (a) zero SHAs fail fetch: asserts `external proof unavailable (fetch of zstack-examples`.
- (b) vendor sha256 mutation fails content: asserts `upstream mismatch (vendor 20260310`.
- (c) koenkk CHANGELOG blob mutation fails blob: asserts `upstream mismatch (koenkk CHANGELOG.md`.
- (d) TI release `lpf2-8.33.00.99` fails message: asserts `upstream mismatch (SDK commit message`.
- (e) koenkk repoint to real HEAD `58dda33d834ef09132427cb41721d7d68e11a7a6` fails blob: asserts `upstream mismatch (koenkk firmware.patch`.
- (f) vendor URL repoint fails closed: asserts `manifest-consistency failed` with `vendor 20260310`.
- (g) coherent herdsman repoint fails identity: asserts `pin identity mismatch`.

## 4. Per-D01..D09 disposition

- D01 koenkk exact comparison pin: manifest carries commit `5e4db67e550d41ea6dc6cd86ceeb04d82ffe1bfb` + blobs + `pin_evidence`; validator enforces commit/blob/path + `identical_to_20260310 is False`; attest re-verifies blobs via `ls-tree`; guard tests: `test_koenkk_exact_comparison_pin`, blob-flip fixtures, controls (c)/(e).
- D02 two-SHA seal discipline: memo protocol section; workflow exact-SHA checkout (`pull_request.head.sha` / `github.sha`); this regen is the seal step.
- D03 toolchain digests: three `*_download_sha256: UNKNOWN` fields, validator requires UNKNOWN; test `test_toolchain_download_digests_explicit_unknown` + fabricated-digest fixture.
- D04 donor coherence: validator coherent-8.33 pair gate; `test_donor_pair_coherent` + `provenance_sdk_mismatch.json`.
- D05 traceable evidence: `_check_text` bounds + `_has_traceable_anchor` + strict SOURCE_CONFIRMED digest rule; `test_statuses_bounded_no_overclaim`; weak evidences strengthened with issue refs.
- D06 vendor tuple: 11-field exact-tuple binding per rev; schema `vendor_catalog` + `binary_source_equivalence` (both UNKNOWN); `test_vendor_tuple_binding`, split test, single-fault flips; control (b)/(f).
- D07 parity domains/statuses: frozen `REQUIRED_DOMAINS_R4_00` (27 entries) exact equality; only R4-P02 `c-irq-stack` is SOURCE_CONFIRMED; rest PHYSICAL_UNVERIFIED; retag tests.
- D08 audit boundaries: audit CLI fails closed on missing provenance, refuses output==manifest, atomic `os.replace` writes, clean error lines; `AuditBoundaryTests`; CLI gates in workflow.
- D09 stock-NV gate: memo B0 gate section (8-file 8.32/8.33 identity cited as review observation from PR #86 comment 6209730355, not CI proof; donor-layout preservation is not stock-20260310 NV compatibility; production-stock-NV boot prohibited until read-only proof plus separately authorized disposable-device trial); gates OPEN.

## 5. Honest limits

- Env literals are in-PR tripwires, not external roots. External roots are the upstream checks: fetches, gitlink, message, blob `ls-tree`, vendor content downloads.
- Vendor-URL limit: no catalog root for URL identity. Gates are exact-tuple consistency plus URL-actually-fetched-and-content-matches. URL authenticity beyond that is never claimed.
- Control (e) assumption labeled in-source: `58dda33d` blobs differ from pinned blobs; failure would be loud (`unexpectedly passed` exit 1), never silent.
- No local execution evidence in this seal: two disclosed read-only `python -c` slips by implementers, modified nothing; all dynamic proof is the hosted CI above.
- Exact-count tests are fixture-fragile by construction (documented in test comments): counts hold for the shipped fixtures, not for arbitrary mutations.
- Audit cross gate unreachable via main (both docs must be strict-valid first); kept as defense in depth with a unit test.

## 6. Schema notes

- `source_unproven` boolean REMOVED; replaced by `vendor_catalog` + `binary_source_equivalence`, both UNKNOWN.
- Only R4-P02 SOURCE_CONFIRMED; all else PHYSICAL_UNVERIFIED.
- Toolchain installer digests explicit UNKNOWN, never fabricated.
- Koenkk pin `5e4db67e` + blobs `e015d9a9…e1fdb` / `25f8bb3f…650`; tag `Z-Stack_3.x.0_coordinator_20250321`; role DISTINCT_COMPARISON_DONOR, never a build input.

## 7. Spark review history (author record; Wonder re-derives)

- lens1 FAIL (2 P1 anchor/blob + P2s, repaired).
- lens2 FAIL (2 P0 vacuous-control/URL + P1s, repaired via identity tripwire + 7 controls).
- lens3 PARTIAL (packet-staleness P2, resolved by THIS regen).
- challenger FAIL (identity P0, repaired via `_check_pin_identity` + control (g)).
- re-review A PARTIAL (P1 control (c)/(e) collision + (f) attribution + (e) label; P2 SDK type + path taxonomy; repaired: distinctive (c)/(e)/(f) lines, in-source (e) label, SDK `commit` type check, strict digest rule).
- re-review B PARTIAL (P2 canary 6/10 + cross-gate test overclaim + count fragility; P3 docstring/comment nits; repaired with micro-delta).
- Micro-delta PASS with FINDINGS: NONE (parent-reported; full text not saved).

## 8. Acceptance mapping + re-review request

- A0: diff is source/docs/CI only; verify via diff + workflow YAML.
- A1: UNKNOWN preserved; verify via validator + flip fixtures + CI logs.
- A2: 27-domain matrix, hypotheses PHYSICAL_UNVERIFIED; verify each entry against issue #85 text.
- A3: memo only, no B0 code; adjudicate as plan, not proof.
- A4: validator + audit + fixtures + hosted workflow green at CODE_SHA `f3c37d68fa09ad5caff909e14fe5afdd7c6a74f7`; verify via the three run URLs above.
- A5: Spark reports above are author-supplied; Wonder must independently re-derive.
- A6: this packet + draft PR; no merge performed.
- Request: Wonder is asked to re-review the new seal SHA once this packet's seal commit lands (CODE_SHA `f3c37d68fa09ad5caff909e14fe5afdd7c6a74f7` as parent). The CODE_SHA / SEAL_SHA / CI-runs triple is recorded in the issue-#85 checkpoint comment posted with the seal.

No conclusory claims: nothing above asserts R4-00 ACCEPTED, hardware-ready, or production-ready.
