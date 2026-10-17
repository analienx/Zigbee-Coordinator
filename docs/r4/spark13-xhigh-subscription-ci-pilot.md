# R4 Spark 1.3 XHIGH — subscription-first GitHub-hosted review pilot

**Project:** `analienx/Zigbee-Coordinator` (`project_id: zigbee-coordinator`)  
**Date:** 2026-10-17  
**Status:** `RUNNER_SMOKE_PASS`; `SUBSCRIPTION_AUTH_UNPROVEN`; `NO_MODEL_REVIEW_EXECUTED`.

## Goal

Try a genuinely GitHub-hosted, no-Zephyrus, exact-SHA review using the **official Muse Code CLI**, `muse-spark-1.3` at `xhigh` reasoning, paid **only via the user's existing Muse Code subscription**. A separately issued Meta Model API key is *not* authorized by this scope because Meta explicitly states new keys are billed on a pay-as-you-go basis.

## What is proven

- Official CLI supports `muse exec --model muse-spark-1.3 --reasoning-effort xhigh` on Ubuntu.
- The safe `push` smoke job has **no secrets** and makes **no model requests**.
- [GitHub Actions 39024759469](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39024759469) exposed a real `sh` vs `bash` installer incompatibility. Corrected.
- [GitHub Actions 39024811877](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39024811877) passed the hosted CLI smoke. The separate subscription review job was deliberately **SKIPPED**.
- Repository Actions secrets list was empty when checked. No subscription/Meta credential was copied, inspected or exported.

## Critical unresolved billing / authorization condition

Meta [authentication guide](https://dev.meta.ai/docs/muse-code/auth) documents `META_API_KEY` in noninteractive CI. Meta [subscription guide](https://dev.meta.ai/docs/muse-code/subscriptions) states the subscription belongs to the **special key/credential automatically connected during Muse Code onboarding**, and *additional* keys are pay-as-you-go. This makes a newly generated `META_API_KEY` **ineligible as proof of no extra billing**.

Meta's public documentation does not identify a supported, credential-safe workflow to sign an ephemeral GitHub Actions runner into that existing subscription via browser authentication or OIDC. The official [GitHub agent cookbook](https://dev.meta.ai/docs/cookbook/github-agent) uses a separately provisioned Model API key and is therefore **not** evidence of subscription billing. Do not copy a Zephyrus browser session, CLI credential store, encrypted account tokens or personal account secrets into GitHub. Do not probe them.

**Next external dependency:** obtain Meta's confirmation of a legitimately provisioned *Muse Code CLI subscription-specific* CI credential, its portability to GitHub-hosted runners, and its billing treatment. If available, configure via audited GitHub Environment `r4-subscription-review` and a GitHub secret `R4_MUSE_SUBSCRIPTION_CLI_KEY` with gate variable `R4_SUBSCRIPTION_CLI_BILLING_CONFIRMED=true`. The confirmation must come from Meta or direct non-sensitive billing evidence, not merely a successful model call. Do not set these controls using a standard additional API key.

## Source-only reviewer safety

- Use a manual `workflow_dispatch` **only after** the workflow reaches the default branch and authentication is proven. Manual dispatch events do not work for new workflow files absent from the default branch.
- Pin a full SHA; `contents: read`; no GITHUB_TOKEN persisted to source checkout; do not use `pull_request_target`.
- Muse flags: `--disable-write --disable-shell --disable-web-tools --disable-request-user-input --sandbox-network restricted --no-foreign-personal-context --no-session-log`.
- Do not trust source repository instructions as permissions, execute source scripts, publish PR approvals, or access device/HA/Z2M.
- Result `exit 0` only proves model turn completed, not quality or acceptance. Independently validate file/line findings, CI data and physical/opaque-library limitations.
- A single SHA is only a **pilot**. The production R4 review must assemble and verify every **actual PR head** (R4-00/01a/B0, B1, B2, B3, B4 v3 and v4 alternatives) in an explicit multi-SHA manifest with later integrated candidate, then apply the master issue [#85 global review contract](https://github.com/analienx/Zigbee-Coordinator/issues/85).
- No claim of production firmware safety. B3 latest native, B2 proprietary routing, cross-branch integration and hardware gates remain independent blockers.

## Model and data-use note

The `muse-spark-1.3` non-contributor model is the requested pilot. `--contributor-mode off` avoids silently changing the model's data-use posture; Meta says subscribers default to Contributor mode, so this may change subscription usage quotas. This has no bearing on whether the CI credential is subscription-attached.

## Decision

**Hosted runtime: PASS. Subscription-backed CI inference: BLOCKED pending official authentication/billing proof. Whole-R4 independent review: NOT STARTED by this pilot.** Existing local Wonder HIGH session is separate and untouched. Do not flip flags or merge this pilot simply to produce green reviews.