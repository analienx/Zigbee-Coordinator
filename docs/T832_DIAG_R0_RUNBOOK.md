# T832-DIAG-R0 capture-before-recovery runbook (candidate, not deployed)

For current firmware capability, fatal SWD capture, independent bridge/startup
evidence, identity and hardware gates, read [R5 closure](T832_DIAG_R0_R5.md)
first. The existing incident/recovery ordering below remains applicable.

This repository authors the integration but never executes it on hardware and never edits live Home Assistant. All commands below run on the HA host/operator side against already-written logs. The collector never opens the coordinator serial device.

## 1. Preconditions

- Diagnostic firmware T832-DIAG-R0 running; host file logging captures the
  herdsman `zh:zstack:znp` debug namespace. DEBUG.msg lines arrive in the
  stock serialization `AREQ: DEBUG - msg -
  {"length":N,"string":{"type":"Buffer","data":[...]}}` (decoded as
  `herdsman-buffer-v1`); a documented plaintext `T832D1:`/`T832D2:` line is
  accepted only as the versioned `text-fallback-v1` fallback. Configure the
  Z2M file log (path, rotation, UTC timestamps, debug level) per site; this
  candidate only reads it.
- Private store root, e.g. `/config/.private/t832-diag` (0700; JSONL 0600).
  Bind the deployed artifact before capturing:
  `t832_incident.py bind-firmware --artifact <T832-DIAG-R0.hex>`.
- Watchdog trigger defined as sustained loss of expected application traffic /
  bridge `online` false, not telemetry absence alone. Missing telemetry is
  loss of observability, never proof of CPU failure. Log timestamps must carry
  an explicit timezone (UTC); naive timestamps are rejected, never assumed.
- Current HA automation mode `single` is not a substitute for the persisted
  per-incident latch in `state/incident-latch.json`. All mutating commands
  hold an OS-exclusive lock; concurrent invocations serialize, they never
  interleave state.

## 2. Capture barrier (must precede any Z2M stop or control-line touch)

```sh
python3 firmware/t832/t832_incident.py \
  --root /config/.private/t832-diag \
  --config-fingerprint "$T832_CONFIG_FINGERPRINT" \
  capture --trigger "$TRIGGER_ID" \
  --triggers deploy/t832_capture_barrier.yaml \
  --window-seconds 900 --deadline-seconds 30 \
  --require-firmware-binding
```

`--trigger` accepts exactly one of `mesh_outage`, `bridge_offline`,
`radio_timeout` — any other string fails `unknown-trigger` and captures
nothing. `--triggers` pins the barrier automation whose definitions
(and SHA256) are recorded in the manifest; `radio_timeout` additionally
evaluates `--trigger-topic`/`--trigger-payload` against those
definitions. `--require-firmware-binding` refuses capture unless a
deployed-role binding for the re-hashed artifact exists (candidate/test
roles bind for bookkeeping only and never gate).

Expected: `status:captured` with `bundle` path containing `manifest.json`,
`SHA256.json`, `diag-15m.jsonl`, `host-events-15m.jsonl`. `manifest.json`
records trigger, 15-minute source-time window, latest diagnostic state, last
successful command stages within the latest boot group (record chronology,
not file arrival order), unknown-time counts, window truncation, collect
partiality, missing sources, firmware SHA, and the observability note. The
window is the newest chronological tail in SOURCE-time order: above-cap
windows shed the oldest rows first (never the newest fault within
same-day rotation skew) and record an explicit
`window-rows-capped` note; `latest_diagnostic_state` is the newest row by
source time, not whatever the traversal visited last. The bundle directory
is committed atomically; the latch moves to `captured` with
`reset_used:false`.

If capture exceeds the deadline, fails, or evidence cannot be saved: inhibit
automatic reset, surface a local operator alert per site contract, and stop.
Do not send notifications from this executor. Do not proceed to control-line
actions. A deadline failure never authorizes a later reset by itself.

## 3. Exactly one validated USB RTS R2 recovery (only after `captured`)

```sh
python3 firmware/t832/t832_incident.py --root /config/.private/t832-diag authorize-reset
# Stop Zigbee2MQTT, confirm stopped via the supervisor add-on state (bounded
# polls), then run ONLY the existing validated helper
# shell_command.mr4u_p10_rts_reset (DTR/RTS deassert; 100 ms; RTS assert
# 150 ms; deassert; 1.5 s; keep DTR deasserted; no erase/flash/restore).
python3 firmware/t832/t832_incident.py --root /config/.private/t832-diag mark-recovering
```

`authorize-reset` first re-verifies every committed bundle hash, then succeeds
once: latch `captured` → `reset_authorized` with `reset_used:true`. A second
call fails `automatic-reset-already-consumed`; tampered or missing bundles
fail `reset-permit-hash-mismatch` / `reset-permit-bundle-missing` and preserve
the `captured` latch. Failed-recovery latch states also refuse new resets.
Log the reset action, subsequent boot/startup records, and existing
post-recovery ZDO verification. Do not add periodic ZDO workload. SYS
responsiveness alone is not recovery.

## 4. Verification, stability observation, and latch close

Report recovery with observed traffic state (ZDO proof required):

```sh
python3 firmware/t832/t832_incident.py --root /config/.private/t832-diag \
  recovery-result --success true|false --normal-traffic true|false --zdo-ok true|false
```

`success=false`, `normal_traffic=false`, or `zdo_ok=false` moves the latch to
`failed` and prohibits automatic retry. Success moves to `stabilizing` with a
10-minute window and requires BOTH normal traffic and a bounded ZDO check.
During the window, record observations (every 5 minutes via the close
automation):

```sh
python3 firmware/t832/t832_incident.py --root /config/.private/t832-diag \
  stability-observation --bridge-up true|false --normal-traffic true|false --zdo-ok true|false
python3 firmware/t832/t832_incident.py --root /config/.private/t832-diag \
  close-if-stable --bridge-up true --normal-traffic true
```

Close requires: 600 s window elapsed; full observation coverage (no gap
over 360 s — one full missed /5 scheduler tick is tolerated, two are not);
EVERY observation bridge-up AND normal-traffic AND ZDO-ok (a single false
point anywhere fails, even beside good points); traffic+ZDO evidence in both
halves (the midpoint observation belongs to both); observations past
window-end + 300 s grace fail closed as out-of-window; no clock anomaly or
restart. Mid-window outage, coverage gaps, restarts, stale traffic, or
missing ZDO move the latch to `failed`, never `closed`. Early close fails
`stability-window-not-complete`. `manual-clear --reason` is operator-only,
audited in `host-events.log`; without `--force` it validates (never repairs
over) every present latch value — falsy JSON included — and refuses corrupt
state. `--force` is the explicit audited repair path. A cleared latch
carries an explicit unused boolean permit so the next capture accepts the
state the repair wrote. Migration: latches cleared before this candidate
lack the explicit permit and now read as corrupt — run
`manual-clear --reason <why> --force` once (audited) to rewrite them.

Check recorded ZDO proof without mutating anything:

```sh
python3 firmware/t832/t832_incident.py --root /config/.private/t832-diag \
  zdo-proof-state --transaction <zdo-transaction-id>
```

The probe shares the verdict's proof check (same transaction, age ≤300 s):
it reports what `recovery-result --zdo-ok` will accept, so a missed
automation wait can still reach the proof-gated verdict honestly. Boot
continuity is enforced separately at close (`stability-boot-mismatch`),
not inside the probe.

## 5. HA automation wiring

`deploy/t832_capture_barrier.yaml` (with `deploy/t832_shell_commands.yaml`) is
the candidate automation: it reuses the three production outage triggers and
runs `capture` → `authorize-reset` → `mark-recovering` → stop Z2M →
stop-confirm (bounded supervisor polls) → existing RTS helper →
start → bridge wait → bounded ZDO `permit_join` check → `recovery-result` →
stability observations → `close-if-stable`, where EVERY destructive step is
gated on the previous step's parsed `response_variable`. `mode: single`
everywhere; the latch is the cross-run guard. Reviewers must confirm control-
line actions are unreachable unless `capture` returned `ok:true` with a
matching incident id.

## 6. Persistent file-only collection (optional, undeployed)

`deploy/t832-collector.service` + `deploy/t832-collector.timer` run `collect`
every 60 s file-only. Status: `systemctl status t832-collector.timer`;
logs: `journalctl -u t832-collector.service`. Enable only after §1 holds.

## 7. First planned live window

72 hours HA/Z2M continuous or until reproduction, then separate
shutdown/reconnect tests if clean. Existing connections mean terminal RAM/fault
context may be lost on hard reset; if the first reproduction yields only
unexplained silence, recommend independent bench/debug/bridge observation
instead of tuning buffers/routes.
