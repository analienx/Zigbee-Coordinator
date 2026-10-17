# R4-00 — independent Wonder re-review packet (post-FAIL repairs)

**Status: CHANGES_APPLIED, CI_GREEN, INDEPENDENT_TRUST_ROOT_OPEN.** This is a source-only provenance and validation stage, not an R4 firmware build or physical coordinator qualification. PR #86 stays DRAFT.

## Review identity and seal discipline

- PR: https://github.com/analienx/Zigbee-Coordinator/pull/86
- Branch: `feat/p7u-r4-stock-derived-redesign`
- **CODE_SHA:** `11abebcba477fef980ae290c89f77f46a8419f35`
- The next commit is **packet-only**, with the CODE_SHA as its parent. Its own SEAL_SHA must be recorded externally in issue #85 after push, rather than self-referentially in this file.
- Prior Wonder FAIL reviewed CODE_SHA `f3c37d68fa09ad5caff909e14fe5afdd7c6a74f7`, seal `157aee3219855df81d60e077008867e2c1d0607b`.
- Wonder native review session: `01a143d2-cb53-7001-8279-8cadaf6430bb`, final aggregate FAIL (lens FAIL/PARTIAL/PARTIAL, challenger FAIL). Previous Wonder read-only review did **not** publish its findings to GitHub. Findings are summarized in issue #85 comment `6211725549`.
- R4-01 design work is independently owned by Spark in issue #87; it is **not** part of this code SHA.

## GitHub-hosted CI (exact CODE_SHA)

- R4-00 provenance/parity: [run 38875820154](https://github.com/analienx/Zigbee-Coordinator/actions/runs/38875820154): SUCCESS, including contract tests, strict validator, upstream attester, all eight stage-specific controls (a–h).
- Python tests: [run 38875820029](https://github.com/analienx/Zigbee-Coordinator/actions/runs/38875820029): SUCCESS.
- The R4-00 upstream attestation positive job: exact fetches of TI SDK, TI examples, herdsman and Koenkk; SHA-pinned SDK gitlink, Koenkk patch+changelog blobs, two SMLIGHT vendor image byte digests; newly validates Git fetched **commit** type, examples release message, pinned herdsman package.json version, and vendor approved exact final HTTPS URL/status/bytes.
- The new offline synthetic test suite `tests/test_r4_00_attest.py` exercises missing/empty environment expectations, repo/path/toolchain repoints, wrong Git object type, redirect/status/size, numeric type confusion and unrelated source anchors. It runs only under hosted CI, not locally.

## Post-Wonder-FAIL source repairs

| Finding | Change in CODE_SHA | Disposition |
|---|---|---|
| P1 origin and path repoint | Ten additional `EXPECT_*` literals check exact four donor repository names, two Koenkk relative source paths, `sdk_version` and 3 toolchain versions **before network**. The real upstream fetch still validates exact content. | Code guard repaired; governed trust root not independently enforced |
| P2 fetched source meaning | Assert actual Git object `FETCH_HEAD` equals expected SHA and type `commit`; check TI examples commit release string, actual herdsman `package.json` version. | Verified at exact SHA via hosted CI |
| P2 vendor provenance | Validate final HTTPS hostname, reject redirect/final URL drift, demand status 200, optional Content-Length and actual body bytes match approved manifest tuple, then SHA-256. Content provenance is still not source-to-binary equivalence. | Verified at exact SHA via hosted CI |
| P2 SOURCE_CONFIRMED | Match one continuous `Koenkk/Z-Stack-firmware@<pinned-commit> coordinator/Z-Stack_3.x.0/firmware.patch` anchor, not an unrelated hash and slash-bearing path. Only R4-P02 uses SOURCE_CONFIRMED; all target firmware behavior PHYSICAL_UNVERIFIED. | Synthetic negatives green |
| P2 missing EXPECT_* | New hosted control (h) removes EXPECT_KOENKK_REPO and requires precise `pin identity mismatch` message, not arbitrary failure. Also synthetically checks all env names. | Hosted green |
| P3 malformed typed tuples | Numeric vendor fields require genuine integers, not floats/bools; wrong Git object type now detected. | Hosted green |
| P3 internal exception category | Some broad fallback wrappers remain; no proof all programming defects are classified uniquely. | Open P3; fail-closed remains |

## Independent trust-root limitation — **NOT CLOSED**

The repo currently has **no enforced branch protection or required human reviewer/ruleset**. All `EXPECT_*` values and the attester implementation live in the same PR. A contributor who changes the workflow + validator + manifest together can bypass in-PR checks. Verified upstream contents are reliable positive observations but do **not** elevate this mutable check to an independently enforced policy.

**Required administration decision before accepting D01 as externally enforced:** configure usable required review / protected baseline validation for merges to `main` (or a mandatory trusted reusable workflow outside contributor-editable PR content). Avoid configuring a one-approval policy that renders the sole repository owner unable to merge without an eligible independent approver. Until actual enforcement is observed, this packet requests Wonder to report **PARTIAL/FAIL for trust-root assurance**, not PASS.

## Existing R4-D01..D09 scope and physical gates

- D02 packet-only SHA discipline maintained. D03 fixture-only phase rejected by production CLI. D04 unhashable JSON shapes return clean errors. D05 typed evidence. D06 catalog vs source equivalence UNKNOWN. D07 27-domain exact matrix, only P02 donor SOURCE_CONFIRMED. D08 audit fails closed if provenance missing and safe atomic output. D09 actual **stock 20260310 NV / board SysConfig/CCFG/RF compatibility remains UNKNOWN**, and no production-stock-NV boot or radio flashing is authorized by this packet.
- TX/RX pin mapping previously established strongly enough for source phase; no reopened RF pin research.
- No local build/test, no radio, HA, Zigbee2MQTT or security-NV operation as part of the post-Wonder repair.
- No merge, release publication or R4-01b firmware authorization.

## Re-review request

Wonder High should independently diff CODE_SHA vs previous seal, inspect the new test suite, check actual hosted raw logs, test coherent repo-fork repoint against the **protected-policy** requirement, and distinguish **source-code fixes now passing** from the **still-open admin trust-root gate**. Nothing should be marked firmware-ready or network-safe.
