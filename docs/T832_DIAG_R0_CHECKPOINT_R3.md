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

## B-row states (all pending until oracles evidence them)

- B01–B03 (M1): IMPLEMENTED, hosted CI pending. Impl: refusals never
  retire by header match (explicitly uncertain 15u + one gate unit on
  match; txRelease deleted); staged retirement by (seq, first_ms,
  repeat) with explicit 3u loss + re-stage; SRSP push+stamp+pending,
  NORMAL push+pending, AF confirm (gen re-validated, new 8u race code),
  AF evict+reuse all single-section (afRemove/pendingInc-split deleted).
  Fixtures: patched-site mirrors + test_b01_identical_headers_refusal
  (6 stages, owned-ambiguity, overflow, SRSP stamp), 3× B02
  (coalesce/saturated/reuse), 2× B03 (SRSP atomic, AF replacement +
  churn); old refusal tests re-based to the fixed semantics (justified:
  old expectations encoded the B01 defect).
- B04–B06, B10–B12 (M2): pending.
- B07–B09 (M3): pending. B13: investigated BROKEN, fix+oracle in M3.
- B14 ledger: this file + acceptance doc; final honest ledger at seal.

## Next action

M1 pushed: watch hosted run (5 jobs incl. new negative-control, which
must show the B01/B02 probes FAILING on pinned 8dd181b). On green:
M2. On red: diagnose from logs only. No local builds/tests.
