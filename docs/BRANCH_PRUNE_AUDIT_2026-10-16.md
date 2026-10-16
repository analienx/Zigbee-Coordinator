# Coordinator branch cleanup audit — 2026-10-16

## Decision

**Primary engineering target: SMLIGHT SLZB-06P7U / CC2652P7, R4.** Existing finalized P10 evidence/branches stay preserved as an independent fallback/reference. This cleanup **does not** authorize firmware flashing, NV/CCFG changes, Zigbee/HA restarts or active-network interaction.

## Verified pre-cleanup recovery snapshot

- Device-local Git bundle: `D:\Workspace\artifacts\zigbee-coordinator-allrefs-before-prune-20261016.bundle`.
- SHA-256: `cd4307c9d3252dfc4d803fccf1e9fb52dfdaea91d2e9a8767463bd93c5225db9`.
- Size: **3,143,977 bytes**.
- `git bundle verify` passed: complete history, 162 refs printed at creation time.
- The bundle is **local-only**, not a cloud/offsite backup; retain an independent copy before deleting the original checkout or recovery drive.
- Recovery example from a fresh directory: `git clone <bundle-path> recovered-coordinator` or `git fetch <bundle-path> 'refs/remotes/origin/*:refs/heads/recovered/*'` with appropriate quoting for the local shell. Inspect a bundle's refs using `git bundle list-heads <bundle-path>` before recovery.

## Remote branch cleanup results

- Before: **76** remote branches on GitHub.
- After: **53** remote branches on GitHub.
- **23** remote branches removed, all outside the currently open PR head/base dependency set, checked-out branch set, and local upstream branch dependencies at the time of pruning.
- One local non-checked-out branch, `codex/p7u-issue80-review-20261014`, also removed; original tip remains in the verified bundle. Its associated detached review worktree was not removed.
- No force worktree deletion, no `git worktree prune`, no reset, and no production radio changes.

Removed remote branch names (original commits recoverable from the snapshot):

- `assistant/p013-concentrator-ab-20260916`
- `assistant/p013-route-health-20260912`
- `assistant/p015-bidirectional-rf-shaping-20260917`
- `p009-debug-capture-20260909`
- `p009-mg24-broadcast-headroom`
- `p009-staging`
- `assistant/p10-error-state-20260924`
- `assistant/p10-usb-cutover-main-20260924`
- `feat/mr4u-p10-r2-reset-helper`
- `feat/p10-rebuild-reconciler`
- `codex/p7-f07-osal-header-fix-20261014`
- `codex/p7-g7-hardening-unexpected-outcomes-20261014`
- `codex/p7-g7-native-evidence-repair-20261014`
- `feat/p7-f07-restore-failclosed-20261014`
- `feat/p7u-cap192-f07-production-target-audit-20261014`
- `feat/p7u-f07-counter-escrow-20261014`
- `feat/p7u-f07-nwk-checkpoint-20261014`
- `feat/p7u-preflash-backup-gate-20261014`
- `feat/p7u-r1-ccfg-native-20261014`
- `feat/p7u-rom-bsl-anti-brick-gate-20261014`
- `plan/cc2674p10-ti-znp-control`
- `plan/mr4u-p10-ti-znp-control`
- `codex/p7u-issue80-review-20261014`

## Explicit retention / remaining work

- Preserve `main` and the **P7U R4 chain**, including R4-00 [PR #86](https://github.com/analienx/Zigbee-Coordinator/pull/86), R4-01a [PRs #88/#89](https://github.com/analienx/Zigbee-Coordinator/pull/89), native B0 [issue #90](https://github.com/analienx/Zigbee-Coordinator/issues/90), and NV-safe B1 [PR #93](https://github.com/analienx/Zigbee-Coordinator/pull/93). Retain their base branches as well as heads.
- Preserve the finalized **P10 lineage**, including `bundle-finalization`, `fix/t832-af-status-rx-overflow-20261011` ([P10 consolidated PR #60](https://github.com/analienx/Zigbee-Coordinator/pull/60)), its necessary base `codex/t832-min-cap192-routing-20261010`, and `exp/mr4u-p10-ti832-kctrl-r0` while the P10 dependency chain remains open. These names are retention anchors, not an assertion of live firmware status.
- Other open P10/P7U R2 draft PR branches remain until those PRs are **explicitly reconciled/closed**; deleting their bases would break review context.
- Local worktrees checked out on distinct P7U and P10 branches were left in place, including R4 worktrees, unreviewed changes and detached review worktrees. Before reducing local branches further: audit `git worktree list --porcelain`, worktree dirtiness, unpushed commits and active external agents; archive, then close/retarget PRs, remove only truly abandoned clean worktrees and delete detached/local branches individually.
- `supervisor/preflash-readiness-fixes` was **not** removed: the local execution router flagged ambiguous project ownership. Reconcile this branch in a separately scoped cleanup rather than bypassing the ownership gate.
- Preserve all release tags and historical SHA references. Avoid rewriting old R2/R3 and P10 evidence: mark it *historical* rather than claiming it was R4.

## Practical future rule

For every proposed branch deletion, require: (1) exact repo and branch SHA; (2) no open PR head/base dependency; (3) not a finalized P10 or R4 retention ref; (4) no attached worktree or tracked upstream, unless that dependency is deliberately retired; and (5) independently verifiable recovery evidence. Never interpret branch naming alone as a proof that the commit is safe to discard.

---

## Wave 2 — remaining 53 branches reviewed and pruned (16 October 2026)

### Verified result

- Starting point after wave 1: **53** GitHub remote branches.
- One new, actively developed R4 branch `feat/r4-b1-codex-snapshot-20261016` was added concurrently (new [PR #94](https://github.com/analienx/Zigbee-Coordinator/pull/94)); protected immediately.
- Wave 2 removed **41** obsolete remote branch names, yielding **13** remaining on GitHub (verified from the GitHub branch API).
- Cumulative from original 76: **64 remote branches deleted**, one new R4 branch created, **13 retained**.
- Closed **27 superseded PRs**: #25, #26, #30, #33, #34, #38, #39, #40, #41, #43, #44, #45, #46, #47, #49, #51, #52, #54, #55, #56, #57, #58, #59, #61, #82, #83, #84.
- Six open PRs verified: [#60](https://github.com/analienx/Zigbee-Coordinator/pull/60) (P10 consolidated, draft), [#86](https://github.com/analienx/Zigbee-Coordinator/pull/86), [#88](https://github.com/analienx/Zigbee-Coordinator/pull/88), [#89](https://github.com/analienx/Zigbee-Coordinator/pull/89), [#93](https://github.com/analienx/Zigbee-Coordinator/pull/93), [#94](https://github.com/analienx/Zigbee-Coordinator/pull/94) (the latter five R4).
- Historical PR closure and branch deletion **do not imply merge**. P7U R2 test code is archived evidence, **not automatically in R4**. R4 must independently qualify any reused fix.

### Independent recovery evidence before wave-2 deletions

- Created and verified local bundle: `D:\Workspace\artifacts\zigbee-coordinator-pre-prune-wave2-20261016.bundle`.
- Copied and SHA-256-verified independently to the local **OneDrive folder**: `C:\Users\jakub\OneDrive\EngineeringArtifacts\Zigbee-Coordinator\zigbee-coordinator-pre-prune-wave2-20261016.bundle`.
- Both copies: **2,902,126 bytes**, SHA-256 `91ad8e3e5638a296b66e09e78fb4db56fe36e5f6dff16c3d548ec2c6fe03bca0`.
- `git bundle verify` succeeded. OneDrive **cloud-sync completion has not been verified**. This bundle snapshots Git refs/commits, **not uncommitted/ignored files**.

### Wave-2 remote branches removed (41)

- `assistant/mg24-emergency-fallback-20260930`
- `assistant/p009b-build-recovery-20260930`
- `assistant/p10-migration-prep-20260923`
- `assistant/r60-baseline-20260921`
- `assistant/r60-stack-feasibility-20260921`
- `p009-hardening`
- `codex/t832-min-v4-m0m2`
- `fix/t832-npi-allocation-ownership-20261011`
- `fix/t832-npi-srsp-fairness-20261011`
- `fix/t832-npi-telemetry-stackmsg-20261011`
- `fix/t832-npi-tx-recovery-20261011`
- `feat/slzb-06p7-ti832-p10-parity`
- `codex/p7u-r2-source-routes-20261015`
- `codex/p7u-r2-essential-diagnostics-20261015`
- `codex/p7u-p10-security-migration-gate-20261015`
- `codex/t832-diag-r0`
- `codex/t832-r5-deployment-gates`
- `fix/t832-r6-nv-capacity`
- `codex/t832-r6-nv-contract`
- `codex/t832-r7-vendor-nvs`
- `codex/t832-r8-powercut-recovery`
- `codex/t832-r9-minimal-debug`
- `codex/t832-r10-preserve-startup-nv`
- `codex/t832-r11-diag`
- `codex/t832-r12-aux-analysis`
- `codex/t832-a1-diagnostic`
- `codex/p10-bsl-readonly-forensics`
- `codex/p7-f07-durable-startup-20261014`
- `codex/p7-g6-timing-reliability-20261013`
- `codex/p7-g7-transport-fairness-20261013`
- `feat/p7-f07-nib-gate-20261014`
- `feat/p7u-board-profile`
- `feat/p7u-g7-f07-integration-native-20261014`
- `feat/p7u-strict-rom-sector-writer-20261014`
- `feat/p7u-v0.1.0-rc1-release-hardening-20261014`
- `feat/p7u-vendor-ccfg-evidence`
- `wonder/p7-cap192-crashdiag-20261013`
- `wonder/p7-g0g3-review-20261012`
- `codex/t832-r8-review-20261006`
- `codex/t832-r10-counter-seal`
- `codex/t832-r12-forensics`

### Branches retained (13)

- `main` — documentation and shared code
- `feat/p7u-r4-stock-derived-redesign` — R4-00/#86
- `feat/p7u-r4-diagnostic-first-issue87` — R4-01a/#88
- `review/p7u-r4-issue87-independent-fixes` — independent R4 review/#89
- `feat/p7u-r4-b0-native-issue90` — R4 B0 and PR #93 base
- `feat/r4-b1-direct-nv-safety-20261016` — R4 B1/#93, not flashable
- `feat/r4-b1-codex-snapshot-20261016` — concurrent R4/#94
- `bundle-finalization` — explicitly retained P10 baseline
- `codex/t832-min-cap192-routing-20261010` — P10 PR #60 base
- `fix/t832-af-status-rx-overflow-20261011` — P10 PR #60 head, still draft
- `exp/mr4u-p10-ti832-kctrl-r0` — local working root with uncommitted changes; retained
- `codex/p10-usb-recovery-skill` — previously completed P10 USB recovery tool
- `supervisor/preflash-readiness-fixes` — cross-project ownership unclear; retain pending separate scoped review

The **retained P10 consolidated PR #60 is still DRAFT**, not promoted as a physically approved release. `bundle-finalization` is retained separately; no claim is made that either was physically deployed. Retention means historical code/reference preservation.

### Local worktree and branch cleanup

- Audited **39** Git worktree registrations before local cleanup; 7 held work-in-progress tracked/untracked changes on the first status pass, and 2 were stale registrations.
- Used `git status --porcelain=v1 --untracked-files=all` plus `git clean -ndx` to prevent deletion of ignored firmware/build/evidence outputs.
- Removed **9** independently verified clean-and-no-extra worktrees, then deleted their **9 corresponding local branches**, only after checking their exact tips existed in both verified Git bundle copies:
  - `zigbee-p7-f07-20261014`
  - `zigbee-p7-f07-integration-20261014`
  - `zigbee-p7-g6-20261013`
  - `zigbee-p7-g7-20261013`
  - `zigbee-p7-wonder-review-20261012`
  - `zigbee-p7u-board-20261013`
  - `zigbee-p7u-ccfg-20261014`
  - `zigbee-p7u-g7-f07-combine-20261014`
  - `zigbee-t832-r8-review`
- Pruned only two proven missing worktree registrations (`zigbee-t832-r7`, `zigbee-t832-r8`), after dry-run verification. Their former source content is in Git history, not their absent on-disk directories.
- Preserved the original P10 checkout, all active R4 worktrees, and every worktree with dirty or ignored/untracked data (including substantial `.tmp/` files). **These remain a separate local housekeeping task** if their non-Git contents are to be archived and removed safely.
- No force-clean, hard reset, radio flash, Home Assistant/Z2M restart, live serial ownership change or NVM write was performed.

### Follow-up safety

The GitHub branch count is now operationally small; further deletion should not target R4 or the retained P10 PR #60 head/base. The only non-R4/non-P10 branch retained for ambiguity, `supervisor/preflash-readiness-fixes`, should be reconciled with the supervisor-control-plane workstream before deletion. Do not declare final firmware acceptance from this repository housekeeping exercise.
