# Native HA recovery result — 24 October 2026

Guard deployment succeeded. Original Zigbee service recovery failed.
No further ordinary reset/start attempts are permitted in this incident.

## Source and actual runtime

Qualified guard source: `06bc5964a82c484d4a073a43b1dc5afe77f47cad`.
Hosted release: https://github.com/analienx/Zigbee-Coordinator/actions/runs/40039373896
Image: `sha256:9a61186a57af776a39c17321aece53973cee6b472a69461c931e5af8c2915b4d`.
Version: `0.2.4-06bc5964a82c`. All nine installed runtime files verified.
Native current/legacy registry validation succeeds on actual HA registry.
The guard remains unarmed and private HTTP fallback remains disabled.

Guard-only deployment plan SHA256:
`7bb7ba05ecf158b527465337952522662e5e584a1baaf7dc780058f27d7a8ff1`.
The private receipt and original guard/options/source backups are under
`/share/p7u-native-guard-024/06bc5964a82c484d4a073a43b1dc5afe77f47cad/`.
Registry helper was stopped after installation; no HA-host package build.

## Bounded physical outcome (UTC on 23 October; Prague date 24 October)

The operator's later ESP reboot was treated as the essential Core restart;
no redundant Core restart was sent. Both previous R4 HOLD journals survive.
The incident identity remains `b2660c9538f540b295896864ed178210`.

| Time UTC | Action/evidence | Outcome |
| --- | --- | --- |
| 23:29:07 | One original Z2M start acknowledged | Exited; SYS ping SRSP timeout |
| 23:31:09 | One native Zigbee restart, correct HA button | HA button state independently advanced; recovery not implied |
| 23:32:02–23:33:05 | One final original Z2M start | Exited 1; AREQ ZDO stateChangeInd timeout after 60000ms |

The original image/version remain official Zigbee2MQTT 2.14.0-1 with
herdsman 10.9.1. The final container is
`325ef203ea49d483032258a4d202c88d4e563d2ec5a3967e1ecaa0b0d9e8de40`.
No resumed startup or genuine device RX was accepted.

The installed herdsman manager SHA256 is
`2d8e0cd36aa344e6c64415a11a47d28c2ad778ea008a2d4d494f7f8f86387853`.
Its beginStartup() reads UTIL device state, submits ZDO startupFromApp,
accepts command status SUCCESS or FAILURE, then waits for state 9. Therefore
this timeout does not establish erased NV, successful startup, or a proven
missed indication. The exact SRSP status is not exposed by the info-level log.
Current radio NV/security continuity has NOT been independently read back.

## Preservation and visibility

- All three Zigbee hosts inactive; manual boot; watchdogs disabled.
- Fresh source-qualified host-PID scan proved zero tty holders without opening
  serial. Guard options independently verified passive; inspector's restricted
  token cannot itself attest the private options.
- Database still matches approval: 107 identities, 128 rows; no temp database
  or pending manifest. Original coordinator backup SHA256 remains
  `8609d816976863702517d82bc80597b082e741e70747e008c0854b6c802f8de4`.
- Private cold backup rehashed successfully. No re-sealing or backup replay.
- Final private log: `/share/p7u-lifecycle/private/source-3921b7923025/native-final-start.private.log`;
  SHA256 `54e7f55f4bba16bd3335101ed6de2ae658e94b0829bfecd44b04b7d0a4fcf72b`.
- Existing HA reporter accepted both the system-log warning and persistent
  notification `p7u_coordinator_hang_warning`, title
  “WARNING — Zigbee recovery needs attention”. API acceptance is recorded;
  actual UI rendering was not inspected.
- Existing manual action attempts/results remain in guard `/data/evidence/`;
  native intent files remain beside the older source-3921 lifecycle journal.
  No old global active operation, intent or action receipt was removed.

No firmware flash, hard/factory reset, full power cycle, USB/Ethernet Zigbee
mode change, manual NV restore/write, counter edit, formation or re-pair was
performed. Normal original-host startup was not instrumented to prove zero
internal NV writes; disk backup continuity is not a live-NV equivalence claim.

## Acceptance still blocked

Read-only preservation diagnosis must precede any repair proposal. Ordinary
recovery budget is exhausted. Keep one owner; no ad-hoc serial reader.
The diagnostic hosts remain quarantined/inactive. Issue 144 still needs
three genuine F2 samples, retained security/identity acceptance, durable
restart persistence and uninterrupted 24-hour serving soak. Unattended
recovery remains a separately gated future activation.
