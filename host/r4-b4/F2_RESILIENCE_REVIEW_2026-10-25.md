# F2 host resilience review — 25 October 2026

Issue #144; PR #153. This change affects host software, not radio firmware.

## Observed incident and findings

The e063f6b collector served the retained network and saved eight genuine F2
responses, then stopped F2 sampling after a 1.2-second response timeout at
10:13:50 UTC. Device traffic continued: 27 device topics had post-timeout
`last_seen` values. A missed diagnostic reply did not establish a radio hang.

1. The transport waiter matched command/type/subsystem but not the echoed
   nonce. Nonce validation happened only after the waiter had consumed a
   frame. A late old response could consume a future request's waiter.
2. F0's permanent timeout latch was reused for F2 despite F2 having a request
   nonce. One ambiguous reply stopped all further optional reads for the
   owner lifetime.
3. The F2 timeout was also emitted as a passive production SYS timeout with
   `NO_DIAGNOSTIC_REQUEST`. This was false independent evidence and could
   mislead a downstream hang detector.
4. Diagnostic quarantine stopped the sampling timer entirely, so the journal
   stopped showing whether probes remained deliberately disabled.

## Corrected policy

- Match the exact eight bytes serialized on the F2 wire inside the existing
  Znp Waitress validator, before resolving the active request. A stale nonce
  cannot consume a later request. Continue full ABI/body/counter validation
  in ZStackAdapter; a correct nonce alone is insufficient.
- Use a bounded six-second response deadline. This tolerates replies later
  than the old 1.2-second deadline; it does not prove the cause of every lost
  native reply. A missing reply can hold the normal mutex for at most that
  deadline. Probes still never queue behind production work.
- Clean only the failed F2 waiter. A later fresh nonce read is allowed only
  after 60 seconds and a matched ordinary non-diagnostic SRSP after the
  timeout. Unsolicited frames, stale frames and cached MQTT do not reopen it.
- Three consecutive lost replies permanently quarantine optional probes for
  that owner. A fully validated F2 reply resets the consecutive-loss budget.
  A writer exception, owner close, invalid body or nonadvancing sequence
  retains hard quarantine. F0 keeps its original one-failure permanent latch.
- Do not record optional F0/F2 timeouts as production SYS failures. Genuine
  ordinary AF/ZDO/SYS/UTIL timeouts keep their independent passive path.
- Keep the minute timer recording no-wire QUARANTINED status. Disk/worker
  failure still disables sampling. Neither quarantine nor retry gates reset
  the radio, reopen UART, form a network, restore NV or force a production ping.

## Qualification requirements

All build and test evidence must come from exact-source GitHub-hosted Actions.
The compiled herdsman suite exercises delayed replies beyond 1.2 seconds,
cooldown without progress, progress without cooldown, stale replies while a
new waiter is active, production AF ownership, the three-loss cutoff, malformed
canonical bodies, F0 quarantine, genuine production timeout reporting and a
seeded 1,000-cycle mix of AF/SYS traffic, losses and out-of-order F2 responses.
Existing owner/OTA/close, redaction and durable-worker fault tests remain gates.

Live acceptance requires the exact qualified image, exclusive USB ownership,
unchanged retained inventory, fresh actual device traffic and three new
durable increasing F2 replies. Preserve pre-change history. Observe beyond the
previous approximately 36-minute owner window before claiming the long-run
timeout regression cured; synthetic tests are not hardware fault proof.

The installed radio's `0x2c` validity mask remains authoritative. Unsupported
SRSP fields remain null, and hardware boot epoch/runtime firmware attestation
remain UNKNOWN. This host repair does not authorize a radio flash or automatic
physical recovery, and does not close broader radio-internal observability gaps.
