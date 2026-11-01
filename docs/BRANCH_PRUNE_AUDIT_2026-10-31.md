# Branch and tree cleanup audit — 31 Oct / 1 Nov 2026

## Decision

`main` carries **only the latest P7U firmware version, V53**. The version-by-version history (V43 → V52 deliveries, ~1000 commits) and the files used only by earlier versions are not brought onto `main`, and the earlier-version branches are deleted.

This touches repository content only. It authorizes no firmware flash, NV/CCFG change, reset, BSL entry or Zigbee/HA restart, and it does not qualify V53.

## What lands on `main`

| Commit | Content |
|---|---|
| `p7u: add R4 V53 firmware, delivery and recovery tooling (latest version only)` | The tree of firmware `8ec1439` (PR #195) combined with delivery `ed42122` (PR #196), minus the files listed below, plus two stale-test fixes |
| docs commit | [V53 review](../coordinators/slzb-06p7u/REVIEW_V53_2026-10-31.md), status, runbook, READMEs and this audit |

**What stayed** is everything the V53 build, delivery and host release still execute: the dependency closure from `test-r4-stock20260311-native.yml`, `package-p7u-paired-operator.yml`, `release-p7u-host.yml` and `tools/p7u_ha_flash_driver.py`, plus the CI gates and tests of that code. That includes:
- The **V43–V52 stages**. These are not earlier versions: each is a layer that `tools/r4_b0_b4_composite_stage.py` composes into V53.
- The **custom host and web-flash code** (`host/r4-b4/`, `release/p7u_web_container.py`). The host release workflow and its tests still load them. Removing them means retiring the custom host first, which is tied to review finding F1.

The repository suite on the result: **924 passed, 31 skipped, 0 failed**. No workflow triggers on a push to `main`.

**Rebuild note.** The native build embeds the first four bytes of the source commit in the B1E evidence digest. A rebuild from `main` is therefore not byte-identical to the installed image; build at `8ec1439` to reproduce it.

## Files removed (used only by earlier versions or phases)

| Group | Files |
|---|---|
| R4-00 provenance phase | `firmware/slzb-06p7u/r4/tools/` (`r4_parity_audit.py`, `r4_provenance_validate.py`, `r4_upstream_attest.py`), `firmware/slzb-06p7u/r4/fixtures/` (52 files), `PARITY_MATRIX.json`, `SOURCE_PROVENANCE.json`, `R4_DESIGN_MEMO.md`, `WONDER_REVIEW_PACKET.md`, tests `test_r4_00_*`, workflow `test-r4-00-provenance.yml` |
| R4-01a diagnostics phase | `r4_diag_reference.py`, `r4_passive_recorder.py`, tests `test_r4_01a_*`, the recorder class in `test_independent_review_p2.py`, workflow `test-r4-01a-diag.yml`, `docs/r4/R4_B0_DIAGNOSTICS_FIRST.md`, `docs/r4/R4_HOST_RECORDER_CONTRACT.md` |
| Workflows triggered only by deleted branches | `p7u-b4-passive-timeout.yml`, `p7u-nv4-admission-oracle.yml`, `p7u-stock20260311-rom-adapter.yml`, `p7u-usb-fast-cutover.yml` (their tests stay and run under `pytest`) |
| Superseded notes | `docs/r4/R4_P7U_NV5_AND_STARTUP_FORENSICS_2026-10-18.md`, `docs/r4/b4/F2_V43_PAIRED_DELIVERY_20261027.md`, `docs/r4/b4/F2_NEXT_FIX_20261029.md` |

Before removal, a scan confirmed that no remaining code, test or workflow references any of these.

## Remote steps — results (1 Nov 2026)

| Step | Result |
|---|---|
| Push the work branch | **Done** (`claude/p7u-firmware-review-lxb903`) |
| Fast-forward `main` | **Done**: `d32a6582` → `9f72bcfc`, a plain fast-forward |
| Close PRs #195 and #196 | **Done**: content is on `main` as the latest version |
| Create provenance tags | **Done** (1 Nov, from a local clone): all six annotated tags below pushed and verified on `origin`; each peels to the commit in its row. |
| Delete the earlier-version P7U branches | **Not done**: refused by the cloud session's git policy (HTTP 403), and again by the local session's permission policy on 1 Nov. All 27 tips were re-verified unchanged on 1 Nov and each is an ancestor of the PR ref named in its row. The owner must run the deletion (command below). |

Provenance tags (annotated). Each commit is also preserved by the PR ref named in its row:

| Tag | Commit | Why |
|---|---|---|
| `p7u-v53-firmware-source` | `8ec1439786e3e98151d2796e6797675bb9ef5965` | Source of the installed image (PR #195 ref) |
| `p7u-v53-delivery` | `ed42122d8149af7643f0afa8137874f4b2d4a2fc` | Delivery that installed it (PR #196 ref) |
| `archive/p7u-v53-paired-host-2c2d96d` | `2c2d96d6334b424f6364a982ad976a674b260e04` | `HOST_SOURCE` pinned by the flash driver (PR #189/#197 refs) |
| `archive/r4-donor-b2-mto-d13a48f` | `d13a48f5226d42e247a17d9198d84c94a4415030` | B2 donor fetched by SHA in the native workflow (PR #121 ref) |
| `archive/r4-donor-b2-failure-530a526` | `530a52631fbde274a2ae356c490bad71b47168a6` | B2 failure-guard donor (PR #114 ref) |
| `archive/r4-donor-b4-3231abb` | `3231abb1f13210eb88afe13ff7b7f9f29709cd6b` | B4 v3/v4 donor (PR #110/#120/#138 refs) |

```sh
git fetch origin 'refs/pull/*/head:refs/remotes/pr/*'
git tag -a p7u-v53-firmware-source 8ec1439786e3e98151d2796e6797675bb9ef5965 -m "P7U R4 V53 installed firmware source"
git tag -a p7u-v53-delivery ed42122d8149af7643f0afa8137874f4b2d4a2fc -m "P7U V53 delivery"
git tag -a archive/p7u-v53-paired-host-2c2d96d 2c2d96d6334b424f6364a982ad976a674b260e04 -m "V53 paired host source"
git tag -a archive/r4-donor-b2-mto-d13a48f d13a48f5226d42e247a17d9198d84c94a4415030 -m "B2 MTO donor"
git tag -a archive/r4-donor-b2-failure-530a526 530a52631fbde274a2ae356c490bad71b47168a6 -m "B2 failure-guard donor"
git tag -a archive/r4-donor-b4-3231abb 3231abb1f13210eb88afe13ff7b7f9f29709cd6b -m "B4 v3/v4 donor"
git push origin --tags
```

## P7U branches to delete

Every tip below is also kept by at least one closed-PR ref, checked on 1 Nov, so deleting the branches loses no commit. All 27 tips were re-checked against this table before the attempted deletion; none had moved. A branch can be recreated with `git push origin <sha>:refs/heads/<name>`.

To delete them from a normal clone, first confirm `main` is at or after `9f72bcfc` and that each tip still matches the table, then:

```sh
git push origin --delete \
  fix/p7u-r4-v49-ready-npi-20261030 fix/p7u-v49-protected-delivery-20261030 \
  fix/p7u-v48-protected-delivery-20261030 fix/p7u-v47-protected-delivery-20261030 \
  fix/p7u-r4-v48-zdapp-fairness-20261030 fix/p7u-r4-v48-fair-stack-dispatch-20261030 \
  fix/p7u-r4-v47-startup-ingress-20261030 fix/p7u-v6-startup-host-pair-20261030 \
  fix/p7u-startup-evidence-20261030 fix/p7u-v7-b1-sampler-host-20261031 \
  fix/p7u-v6-versioned-rom-recovery fix/p7u-v6-qualified-delivery-20261029 \
  fix/p7u-f2-owned-overdue-stage-20261029 fix/p7u-f2-early-capture-overdue-stage-20261029 \
  fix/p7u-v5-srsp-runtime-priority-20261029 feat/p7u-r4-f2-v5-flight-recorder-20261028 \
  fix/p7u-v45-paired-delivery-20261029 fix/p7u-r4-v45-srsp-reserve-20261028 \
  fix/p7u-r4-v44-srsp-service-20261028 fix/p7u-r4-real-tx-liveness-20261028 \
  fix/p7u-r4-f2-seqlock-20261028 fix/p7u-r4-npi-rx-overflow-liveness-20261028 \
  investigate/p7u-npi-real-txq-drain-20261028 investigation/p7u-r4-hang-causal-review-20261028 \
  feature/p7u-f2-halfhour-evidence-20261028 fix/p7u-r4-v43-uart-tx-liveness-20261027 \
  codex/p7u-shared-recovery-policy-20261022
```

| Branch | Tip | Kept by PR ref |
|---|---|---|
| `fix/p7u-r4-v49-ready-npi-20261030` | `8ec1439786e3` | #195 |
| `fix/p7u-v49-protected-delivery-20261030` | `ed42122d8149` | #196 |
| `fix/p7u-v48-protected-delivery-20261030` | `d7727e317b2b` | #193 |
| `fix/p7u-v47-protected-delivery-20261030` | `b29f60256185` | #193 |
| `fix/p7u-r4-v48-zdapp-fairness-20261030` | `250441cd17c5` | #192 |
| `fix/p7u-r4-v48-fair-stack-dispatch-20261030` | `e709c0b3bac4` | #194 |
| `fix/p7u-r4-v47-startup-ingress-20261030` | `391d7a5b24d4` | #191 |
| `fix/p7u-v6-startup-host-pair-20261030` | `54240bb2cd57` | #190 |
| `fix/p7u-startup-evidence-20261030` | `2c2d96d6334b` | #189 |
| `fix/p7u-v7-b1-sampler-host-20261031` | `928f728feffa` | #197 |
| `fix/p7u-v6-versioned-rom-recovery` | `e821066f4db7` | #188 |
| `fix/p7u-v6-qualified-delivery-20261029` | `39d11edce73b` | #187 |
| `fix/p7u-f2-owned-overdue-stage-20261029` | `66ed700c2818` | #186 |
| `fix/p7u-f2-early-capture-overdue-stage-20261029` | `596e8dc2024e` | #185 |
| `fix/p7u-v5-srsp-runtime-priority-20261029` | `e3a0f3b7726a` | #184 |
| `feat/p7u-r4-f2-v5-flight-recorder-20261028` | `85ce37c24802` | #183 |
| `fix/p7u-v45-paired-delivery-20261029` | `3a19e39f4b71` | #182 |
| `fix/p7u-r4-v45-srsp-reserve-20261028` | `98b882c49cde` | #181 |
| `fix/p7u-r4-v44-srsp-service-20261028` | `e6ebb8003dfa` | #179 |
| `fix/p7u-r4-real-tx-liveness-20261028` | `0aee94efac9c` | #178 |
| `fix/p7u-r4-f2-seqlock-20261028` | `2742f48939e2` | #177 |
| `fix/p7u-r4-npi-rx-overflow-liveness-20261028` | `b5b60142203b` | #176 |
| `investigate/p7u-npi-real-txq-drain-20261028` | `50265e7e9d56` | #175 |
| `investigation/p7u-r4-hang-causal-review-20261028` | `99cbe5d1c320` | #174 |
| `feature/p7u-f2-halfhour-evidence-20261028` | `c5a9afdfff7f` | #173 |
| `fix/p7u-r4-v43-uart-tx-liveness-20261027` | `b97179a0112b` | #172 |
| `codex/p7u-shared-recovery-policy-20261022` | `1bcec0a86157` | #146 |

## Kept: other coordinators

These are not P7U firmware versions and stay untouched:
- `bundle-finalization`
- `supervisor/preflash-readiness-fixes`
- `codex/p10-usb-recovery-skill`
- `codex/t832-min-cap192-routing-20261010` and `fix/t832-af-status-rx-overflow-20261011` (open PR #60)
- `exp/mr4u-p10-ti832-kctrl-r0`

Two remaining workflows still list a deleted branch under `push:`; both also run on `pull_request`, so they were left alone:
- `test-r4-b0-native.yml`
- `test-p10-r2-reset.yml`
