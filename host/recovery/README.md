# Shared stock/R4 P7U recovery guard

This is the independent Home Assistant watchdog for [#143](https://github.com/analienx/Zigbee-Coordinator/issues/143), reviewed in [draft PR #146](https://github.com/analienx/Zigbee-Coordinator/pull/146). It never opens the Zigbee serial port. Version 0.2.0 corrects the first dry-run's persistence, evidence attribution and HA control boundaries. Source qualification and live acceptance are separate gates.

## Defaults and admission

The add-on defaults to `enabled:false`, `dry_run:true`, manual boot and private HTTP fallback disabled. Physical recovery additionally requires `serial_owner_approved:true`, `notify_on_confirmed_hang:true`, the pinned coordinator MAC/version, and both verified restart controls. Merely entering button entity IDs cannot qualify unrelated buttons. No automatic arming is part of deployment.

Configure the real MAC privately in add-on options. The reviewed SLZB-OS version is `v3.4.3.dev1`; its command script SHA256 is `1c281812686d1d78911ea8163daca74a8c7507e31305f09e505d5385a5e70834`. A version or script change requires new review. Native SMLIGHT buttons are preferred when installed. The optional private route permits only ESP restart command 3 and Zigbee radio restart command 1. Hard reset, power cycling, flash, NV restoration and connection-mode changes are absent from the guard.

`maintenance` and `firmware_flash_active` are live inhibition options, reloaded before actions. Operators must set maintenance before OTA/flash/recovery work outside this guard. Runtime checks also inspect OTA evidence, exact Supervisor tty identity, actual Z2M serial options, socat and the competing native watchdog. The explicit ownership approval is an admission assertion, not a claim that a container can inspect every host file descriptor.

## Detection and recovery algorithms

The observer requires an acknowledged MQTT subscription and a valid device inventory. Ordinary MQTT delivery, retained bridge state, cached startup publications, optimistic state, `NWK_NO_ROUTE` and an offline device cannot prove a hang or recovery.

Genuine receive evidence uses `advanced.last_seen: epoch`: a known device's integer millisecond timestamp must advance, follow the current watcher/recovery cutoff and fall inside the last 120 seconds. Repeated cached timestamps do not refresh it. Invalid evidence inhibits decisions. Enabling this supported live Z2M setting does not require a restart or ZNP probe.

The observer binds bounded Supervisor logs to the current container epoch. It bootstraps OTA lifecycle from the matching read-only current log file, without exporting raw history. Missing history, log gaps or unresolved OTA state inhibit recovery. SRSP wrappers resolve to a canonical known device, with semantic deduplication across repeated representations of one failure.

A running hang requires five current SRSP failures across three devices, no valid fresh device receptions, adequate application uptime, valid independent observation and two qualifying samples at least 30 seconds apart. An adapter-specific failed startup must belong to the current attempt. An unexplained manual stop inhibits recovery.

The bounded sequence is:

1. Preserve sanitized evidence and send warnings to HA System Log and persistent notification.
2. Stop Z2M and verify quiescence.
3. Restart ESP once, wait for exact USB re-enumeration, and start Z2M once.
4. Require real herdsman/application startup, fresh bridge state, advancing receive timestamps from at least three devices, no new SRSP failures and 120 seconds of continuously qualifying observations.
5. Only a new adapter-specific failure permits one radio-only reset and one final Z2M start. Otherwise HOLD and alert.

Boot wait is bounded to 180 seconds and verification to 240 seconds. A missing action/proof is bounded to 120 seconds. Observation gaps over 60 seconds restart stability. A six-hour cooldown and two incidents per 24 hours count physical attempts, including unsuccessful ones.

## Crash persistence and warnings

Each incident has a UUID. Every action is identified by UUID, phase and action name. An exclusive fsynced intent precedes external requests; a separate durable outcome precedes ledger advancement. A crash with no accepted outcome enters HOLD without replay. These are at-most-once operations; a crash before sending may mean the operation never occurred.

Mutable ledgers use unique private temporary files, fsync and atomic replace. Old temporary files cannot block saves. Invalid ledgers are preserved privately and become HOLD. Legacy pending transactions cannot import old unscoped acknowledgement booleans.

Dry-run has its own persistent shadow ledger. It can confirm `WOULD_RECOVER` across polls but cannot create real action receipts or erase real recovery budgets. Optional `notify_on_confirmed_hang` permits genuine warnings while physical recovery remains disabled.

Warnings use both `system_log.write(level=warning)` and one persistent-notification ID per coordinator. Delivery outcomes are durable. Notification retries are bounded and update the same ID; obsolete revisions are superseded. An ambiguous System Log write is not repeated. A synthetic acceptance test uses a separate notification ID and explicit TEST text, without calling an actuator.

## Qualification and deployment

Run the recovery and Python suites on the exact GitHub commit. They exercise fake APIs, crash boundaries, stale receipts, continuous stability, denied subscriptions, timestamp/cache handling, semantic error attribution, OTA transitions, native/private control admission and warnings. No production fault injection is needed for these regressions.

Deploy all Python modules, including `persistence.py`, with the matching Dockerfile and configuration from one SHA. Rebuild only `local_p7u_recovery`, preserve disabled reset options and verify hashes inside the running container. `/data/status.json` provides sanitized observation validity, receive counts, epoch, SRSP count, OTA state and whether resets are enabled.

Live acceptance requires at least ten minutes of valid observation, advancing timestamps from three devices, one labelled synthetic warning in both HA destinations and a guard-only restart proving ledger persistence. Source CI does not prove automatic hardware recovery or long-term radio reliability.

The separate [R4 F0/F2 collector #144](https://github.com/analienx/Zigbee-Coordinator/issues/144) must use the existing herdsman serial owner. [Stock deployment #145](https://github.com/analienx/Zigbee-Coordinator/issues/145) needs independent security/layout qualification. Neither is performed by this guard.
