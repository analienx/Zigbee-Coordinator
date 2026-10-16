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
