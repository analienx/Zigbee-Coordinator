# T832-DIAG-R0 R3 checkpoint

- Goal: R3 B01–B14 on retained candidate PR38 (draft, base
  exp/mr4u-p10-ti832-kctrl-r0). Starting SHA 8dd181b, worktree clean.
- Brief: `7ccf3a9d-…` SHA256 verified
  `11ca141e6a1a32f8c4c3bfc605fced860014d49a56fda6c281b974abb789ec2d`,
  read fully.
- R2 preserved: run 37192825360 green at fb7b641; seal run 37193570824
  green at 8dd181b. No R0/R1/R2 relaunch.
- Issue 73: open, latest comment 2026-10-03T10:01:37Z (unchanged).
- Authority: hosted-only builds/tests; local inspection/edit allowed; no
  local repo tests, no flash/live/merge/deploy.

## B13 investigation (done before edits — VERDICT: BROKEN, fix required)

Boundary: automation data template
(`deploy/t832_capture_barrier.yaml:52`) renders
`{{ trigger.payload_json | default({}) | tojson }}`; shell template
(`deploy/t832_shell_commands.yaml:20`) embeds
`'{{ trigger_payload_json }}'`; `--trigger "{{ trigger }}"` passes the
whole trigger object.

Inspected HA core dev sources (read-only, 2026-10-04):
- `tojson` is Jinja2 builtin `htmlsafe_json_dumps` (no HA override;
  `helpers/template/__init__.py` has no tojson/to_json/filter override):
  escapes `<`, `>`, `&`, `'` to `\u003c/3e/26/27`
  (`pallets/jinja src/jinja2/utils.py`, `htmlsafe_json_dumps`).
- Automation service `data:` passes through `render_complex` with default
  `parse_result=True` (`helpers/service.py`
  `async_prepare_call_from_config` → `render_complex(config[conf],
  variables)`); `_parse_result` is `literal_eval`-based
  (`helpers/template/__init__.py`).
- Consequence: tojson output for a JSON object re-parses to a **dict**
  (unless it contains `true`/`false`/`null`, where literal_eval fails and
  it stays a string — payload-dependent). `service.data` therefore
  carries a dict for ordinary object payloads.
- shell_command renders the command template with `parse_result=False`
  and executes via `shlex.split` + `create_subprocess_exec` (shell=False)
  (`components/shell_command/__init__.py` `_make_handler`).
- Consequence: `{{ trigger_payload_json }}` on a dict renders Python
  `str(dict)` (single-quote repr) inside shell single quotes → shlex
  mangles the argv (many broken args or ValueError) → the CLI never
  receives the payload; mqtt-triggered captures fail. Same for
  `--trigger "{{ trigger }}"` (whole-trigger dict; tool additionally
  expects an ID in `CANDIDATE_TRIGGER_IDS`, so it would raise
  unknown-trigger even if argv survived).
- Impact is availability/integrity, not RCE (shell=False; shlex only
  splits). Production HA version pin not found in home-assistant-stack
  (checked repo root, ARCHITECTURE.md, PROJECT_STATUS.md); cited lines
  are HA core dev 2026-10-04 — confirm exact pin at deploy time.
- Production cross-checks (read-only): production automation
  `zigbee2mqtt_mesh_communication_outage_alert` fires radio_timeout only
  on permit_join response with `status == 'error'`, `'SRSP -'` and
  `'after 6000ms'`; its ZDO verify publishes
  `'{"time":0,"transaction":"ha-mr4u-watchdog"}'` (time:0, not value:).
  Candidate barrier still uses device/remove topic (B07) and
  `{"value": false, ...}` (B08) — confirmed against production source.

Fix design (M3, minimal, our boundary only):
- Automation: `trigger: "{{ trigger.id }}"` (tool expects an ID).
- Shell: `--trigger-payload '{{ trigger_payload_json | tojson if
  trigger_payload_json is mapping else trigger_payload_json }}'`
  (dict→valid JSONohonestly quoted; JSON-text strings pass through —
  tojson output never contains a literal `'`).
- Tool `coerce_trigger_payload` already accepts str-or-dict (add
  double-decode tolerance only if the shell may double-encode — it will
  not after this fix; keep as-is unless oracle demands it).
- `t832_zdo_proof` transaction is safe by ordering (condition requires
  exact `ha-t832-barrier` before the call); no change.
- Hosted oracle: test reads the ACTUAL YAML template strings, renders
  them through a Jinja2 sandbox + literal_eval + shlex staged exactly per
  the cited HA source lines (pinned in-test with file/version/line refs),
  adversarial corpus (apostrophes, quotes, newlines, $/backtick/`;`,
  Unicode, booleans/null, non-JSON, missing payload); asserts the CLI
  receives precisely one inert `--trigger-payload` argv that round-trips,
  and no side effect occurs.

## B-row ledger (seal)

Code HEAD sealed for code: 4feb5e0 (M4 review fix), validated green
5/5 by run 37236433781. Prior green code HEAD: 1cc621f, run
37234099199 5/5 success. This seal commit is docs-only; its own 5-job
run is the exact-SHA seal evidence (ID recorded in the PR body +
completion report, not embedded here).
Each row: implemented / hosted-tested / independently reviewed.
"Reviewed" = M4 read-only reviewer verdict on 1cc621f, integrated in
4feb5e0 where actionable (review report archived with the session).

- B01 (M1 a695ed4 + fix 90a4ecb): IMPLEMENTED, TESTED, REVIEWED (no
  findings). Source: firmware/t832/t832_diag_impl.inc refusal paths;
  caller: actual patched SDK entry functions in hosted C harness.
  Oracles: host_harness/t832_diag_host_test.c B01 fixtures (identical
  headers/lengths, owned-ambiguity, overflow, SRSP stamp) + negative
  control (B01/B02 probes FAIL on pinned 8dd181b). Evidence: M1 green
  run 37220539562 (after red 37220147450 popPeek/seed/depth fixes).
- B02 (M1): IMPLEMENTED, TESTED, REVIEWED (no findings). Source:
  exporter staging/retirement (seq, first_ms, repeat) with explicit
  bounded loss + re-stage. Oracles: 3× B02 harness fixtures
  (coalesce/saturated/reuse); no test-side recorder clearing.
  Evidence: run 37220539562 + negative control on 8dd181b.
- B03 (M1): IMPLEMENTED, TESTED, REVIEWED (no findings). Source:
  single-section SRSP push+stamp+pending, NORMAL push+pending, AF
  confirm (gen re-validated), AF evict+reuse. Oracles: 2× B03 harness
  fixtures (SRSP atomic, AF replacement + churn). Evidence: run
  37220539562.
- B04 (M2 19ee8cb + fixes defe744/2b51da8): IMPLEMENTED, TESTED,
  REVIEWED (no findings). Source: firmware/t832/t832_incident.py
  capture/collect/peek/drain paths. Oracles (test_diag.py, hosted CLI
  subprocesses): test_capture_deadline_and_budgets,
  test_collect_budget_marks_partial, test_budget_rewind_recovers_unread_
  without_duplication, test_oversized_line_skipped_with_note,
  test_exact_cap_line_consumes_exactly,
  test_oversized_line_in_window_is_drained_boundedly,
  test_newline_free_flood_tail_skip_is_bounded,
  test_locked_timeout_bounds_contention, test_lock_timeout_fails_loudly,
  test_repeated_collects_stay_bounded_and_audited. Evidence: M2 green
  run 37223946706 at 2b51da8 (after red 37223699159).
- B05 (M2): IMPLEMENTED, TESTED, REVIEWED (no findings). Oracles
  (test_diag.py): test_corrupt_latch_fails_closed,
  test_unknown_latch_schema_fails_closed,
  test_malformed_and_unknown_schema_rejected,
  test_capture_refuses_invalid_latch_before_work,
  test_force_clear_audits_and_unbricks,
  test_repeated_trigger_while_latched_refused. Evidence: run
  37223946706.
- B06 (M2): IMPLEMENTED, TESTED, REVIEWED (no findings). Oracles
  (test_diag.py): test_empty_hash_inventory_blocks_authorize,
  test_uninventoried_manifest_blocks_authorize,
  test_tampered_bundle_blocks_authorize,
  test_missing_bundle_blocks_authorize, test_thinned_inventory_refuses,
  test_padded_inventory_refuses, test_count_mismatch_refuses,
  test_bad_digest_format_refuses, test_swizzled_digest_refuses,
  test_foreign_bundle_refuses, test_supplement_truncation_refuses.
  Evidence: run 37223946706.
- B07 (M3a 7b59e67 + rebase f73f476): IMPLEMENTED, TESTED, REVIEWED
  (no findings). Source: deploy/t832_capture_barrier.yaml permit_join
  trigger + t832_incident.py evaluate_radio_timeout/evaluate_trigger/
  load_trigger_defs. Oracles: test_diag.py test_production_corpus,
  test_tool_uses_production_permit_join_topic,
  test_load_trigger_defs_pins_source_sha,
  test_genuine_outage_after_observed_captures_and_authorizes_once,
  test_nonqualifying_capture_leaves_observed_latch; test_automation.py
  S7–S10 entry qualification + genuine-timeout E2E. Evidence: M3a
  green run 37226105835 at f73f476 (after 37225912039 retired-SRSP
  fail); production contract pinned read-only at home-assistant-stack
  6c934ba.
- B08 (M3c 3e3a8f5 + fix rounds through 01d4cbd): IMPLEMENTED,
  TESTED, REVIEWED (no findings). Source: real barrier YAML/shell/CLI
  driven by bounded interpreter (test_automation.py S1 + halt-phase
  legs: test_stop_unconfirmed_halts_in_stop_phase,
  test_rts_failure_halts_in_rts_phase,
  test_start_unconfirmed_halts_in_start_phase,
  test_bridge_offline_halts_in_bridge_phase,
  test_stale_zdo_halts_in_zdo_phase) + shell-boundary oracles
  (test_barrier.py R3M3ShellBoundary incl.
  test_mapping_payloads_round_trip_as_single_argv,
  test_old_template_mangles_objects negative control). TEMP probe
  commits exist in history; final tree contains no probes. Evidence:
  M3c green run 37231136965 5/5 at 01d4cbd.
- B09 (M3 a87eed7 + c9b1201 + 1cc621f): IMPLEMENTED, TESTED,
  REVIEWED sound (reviewer re-verified the a87eed7→c9b1201
  flag-restore that CI red run 37232551251 had caught first).
  Contract: gap 360s, mono gate, wall/mono skew
  gate (120s), boot-continuity gate, 120s out-of-window grace, proof
  preserved structured with flags restored. Oracles: test_stability.py
  test_stability_windows (slow threaded real-600s legs, firmware +
  control jobs) + fast honesty legs; test_automation.py
  test_boot_comparator_rejects_foreign_boot,
  test_wall_skew_comparator_rejects_jumps,
  test_outage_tick_records_counterevidence_without_closing,
  test_idle_tick_without_incident_is_noop (structurally pinned in
  4feb5e0). Evidence: green run 37234099199 5/5 at 1cc621f (after red
  37232551251 KeyError, red 37232697237 empty-message leg).
- B10 (M2): IMPLEMENTED, TESTED, REVIEWED (no findings). Oracles
  (test_diag.py): test_wrap_replay_duplicate_ambiguous_reboot,
  test_delayed_boot_keeps_session, test_uptime_wrap_keeps_boot,
  test_replay_keeps_session, test_ambiguous_pair_holds_frontier,
  test_expected_seq_clock_back_is_ambiguous,
  test_sequence_rollover_with_clock_back_is_ambiguous,
  test_multirecord_boot_frame_counts_one_boot,
  test_boot_clean_continuation_no_double_boot. Evidence: run
  37223946706.
- B11 (M2): IMPLEMENTED, TESTED, REVIEWED (no findings). Oracles
  (test_diag.py): test_unknown_time_kept_out_of_window,
  test_supplement_committed_when_unknown_present,
  test_supplement_committed_when_empty,
  test_aggregate_cap_prunes_oldest_first,
  test_latched_bundle_exempt_reports_over_budget,
  test_abandoned_tmp_reclaimed_but_fresh_survives,
  test_rotated_log_count_cap, test_retention_deletions_audited,
  test_latched_bundle_survives_pruning,
  test_rotation_cap_and_collector_restart,
  test_seven_day_stream_with_rotation. Evidence: run 37223946706.
- B12 (M2): IMPLEMENTED, TESTED, REVIEWED (no findings). Oracles
  (test_diag.py): test_declaration_required,
  test_manifest_contents_verified,
  test_records_carry_declared_and_observed_identity,
  test_mismatch_never_relabels_observed_frame,
  test_bind_firmware_gates_capture,
  test_candidate_role_never_gates_capture,
  test_swapped_artifact_fails_binding,
  test_observed_build_mismatch_noted, test_matching_build_silent;
  barrier chain binds with B12 declaration (2b51da8). Evidence: run
  37223946706.
- B13 (M3b 116bae5 + M4 4feb5e0): investigated BROKEN before edits,
  FIXED, TESTED, REVIEWED. Shell re-serializes mappings
  (`tojson if mapping else`); E2E staging now matches production
  (htmlsafe_json_dumps tojson + literal_eval parse_result on the
  shell_command handoff). Oracles: test_barrier.py boundary corpus +
  old-template negative control; test_automation.py S10 +
  S10b test_adversarial_payload_round_trips_shell_boundary (O'Brien
  payload qualifies and reaches stabilizing; pre-fix staging proven
  to break — shlex `No closing quotation` — by local mechanism probe
  m4_fidelity_probe.py, archived with the session, not the repo).
  Evidence: run 37236433781 success 5/5 at 4feb5e0; S10b ok in both
  BarrierAutomationTests and StabilitySchedulerTests (firmware verbose
  log), noop pin ok.
- B14: this ledger + acceptance doc (stale rows flagged below) + PR38
  body update + external completion report at seal. Internal reviewer
  raw verdicts archived; reviewer PASS does not close hardware checks
  or substitute supervisor acceptance.

## M4 review dispositions (all integrated or recorded)

Needs-fix (low) — E2E staging diverged from staged oracle: FIXED in
4feb5e0 (htmlsafe tojson + shell-path parse_service_value + S10b).
Advisories (accepted as documented limitations, no behavior change):
1. close weighs per-half traffic/ZDO existence, not per-observation
   counter-evidence (YAML comment overstates; semantics kept);
2. load_trigger_defs pins YAML by SHA but reimplements the predicate
   (manual sync; hash mismatch is the drift signal);
3. state triggers are trusted firings; direct CLI bypass is
   runbook-scoped;
4. weak noop test — FIXED (t832_status-only pin);
5. stability close gate is rc-only while CLI returns 0 with
   `status: failed` (sticky-safe via next-tick halt; info log only);
6. slow-suite worker threads are non-daemon (CI timeout is the
   backstop; sleeps are minimums so timing margins hold).
mqtt.publish staging untouched by design: its JSON-string payload is
consumed by json.loads on both sides (ZDO hook, Z2M); parse_result is
scoped to the shell_command handoff whose argv is the B13 boundary.

## Honest limits (not validated)

- No real-hardware timing/soak/fault-injection; hosted virtual clocks
  only. Real HW timing, SDRAM/NV behavior, and radio faults remain
  explicitly unvalidated — supervisor review pending.
- Production HA pin 6c934ba was read-only; confirm exact HA pin at
  deploy time (checkpoint B13 note stands).
- Issue 73 reset-domain uncertainty retained; firmware/transport
  attribution remains hypothesis.
- Acceptance doc T832_DIAG_R0_ACCEPTANCE_R2.md still carries R2-era
  rows; B14 flags it stale where it claims closure beyond the ledger
  above. PR38 body to be updated at seal with final SHA/jobs/artifact
  identities (no merge, draft stays unpublished).

## Next action

Seal: commit this ledger docs-only, push, confirm the seal commit's
own 5-job run green (DIAG + matched CTRL + interop + fast + negative),
then update PR38 body + external completion report with exact seal
SHA/run/jobs/artifact hashes, and stop with the ready-for-review
line. No flash/live/merge/deploy.
