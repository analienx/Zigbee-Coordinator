# T832-DIAG-R0 R2 checkpoint

- Goal: goal-01a1060a-668f-73c3-ab72-69f314fcb68c (R2: fix S01–S16)
- HEAD: `aca72e8` (clean; matches reviewed SHA)
- Branch: `codex/t832-diag-r0`; PR #38 draft, base `exp/mr4u-p10-ti832-kctrl-r0`
- Brief: `2fc44fab-...` SHA256 verified `776d613c…4972`, read fully
- Issue 73: open, 27 comments, unchanged since 2026-10-03T10:01:37Z
- Prior review inputs: `C:\Workspace\scratch\t832-review-20261003\`
  (pinned SDK sources), `C:\Workspace\scratch\t832-review-20261004\artifacts`
- Base CI: run 37147303827 fully green at `aca72e8`

## A01–A16 states

All pending. Ledger: docs/T832_DIAG_R0_ACCEPTANCE_R2.md.

## Outstanding effects / jobs

M1 push (S01–S04): .inc ownership/generation/atomicity rework, patcher TX/RX
refusal hooks + RX reclassification, validator + manifest capability rename,
6 new harness regressions, fast host-regressions CI job. Awaiting hosted run.

## Open questions (from brief)

- Q1 transport-mode reset semantics: retained hypotheses, no experiments.
- Q2 safe task/stack/fault observations from public TI interfaces: design
  during M2; no fault-handler rewrite.
- Q3 passive ZDO/traffic freshness for stabilization: research during M4;
  no periodic radio workload.

## Next action

Watch M1 hosted run (host-regressions fast lane first, then full firmware /
control / interop). Then M2 (S05–S07).
Authority limits: hosted-only execution; no local builds/tests; no live/merge.
