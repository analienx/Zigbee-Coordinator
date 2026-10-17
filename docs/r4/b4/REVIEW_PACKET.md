# R4 B4 independent review packet (request, not a verdict)

**Artifact:** draft PR #100 targeting sealed B0; source branch `feat/p7u-r4-b4-issue98`. No Muse/Claude/other independent review has been claimed. **All lanes: NOT YET REVIEWED**.

## Lane A — native TI NPI/UART/RTOS

Audit `b4_native_patch.py`, exact symbol and callback path, NPI `npi_client_mt.c` and CS use, no unintended enqueue counter source, MT and AF dispatch, no priority change, early RX framing and UART2_write acceptance vs completion. Require real ELF, linker XML, CCFG, NV, memory and stack delta. Challenge stale source aliases, counter saturation, reset and reboot continuity.

## Lane B — ABI/host/ZNP owner

Audit `b4_protocol.py`, `B4_PROTOCOL_SCHEMA.json`, `host/r4-b4/herdsman_overlay.py`, genuine Node compiled tests, F0 collision and v2/v3 fallback refusal, fixed-buffer exact size, SRSP waiter lifecycle, fairness, 30s skip/backoff, OTA/timeout gate, no raw or external ZNP. Challenge plugin attempting second client and forged capability.

## Lane C — privacy/forensics

Audit `r4_passive_recorder.py`, `b4_replay.py`, persisted schema, 24h/count/size caps, fsync rename and attacker-controlled symlinks, late/wall-clock reversed events, evidence labels, alternate causes. Challenge post-reboot counter fallacy, synthetic times being mistaken for observed, USB detach misattribution, SIGTERM-not-crash, secrets in logs.

## Lane D — CI/provenance/memory/B1

Audit exact pinned sources and hashes, real CCS two native builds, actual ELFs and CCFG, compiler signatures, missing-key/toolchain fail-closed, GitHub Actions YAML and tamper controls, source-to-symbol proof, B1 HOLD no RF or NV bypass, B2/B3 boundary.

## Blind-spot challenger

Reproduce at least five *new* distinct failure paths not already in source tests, each with offending line, adverse observable, failing test then repair. Suggested starting points (do not count as independently executed): renamed SYS command alias, length truncation in Buffalo, stale host-issued probe after OTA begins, directory fsync post-rename hazard, NPI rollback with live waiter stuck; independently extend beyond these.

No reviewer PASSED, no unconditional source-ready label or merge.

## Current staged evidence for review, not independent approval

- [Host/TypeScript 39002832223](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39002832223): actual pinned `Znp` queue and Waitress exercised with 200 simultaneous F0 offers coalescing to one, 40 normal SYS_PING requests preserved; no live port.
- [Source 39002832220](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39002832220): exact Z2M 2.14.0 release dependency+public extension API mutation source gate. Installed Z2M remains unknown.
- These are automated self-authored tests, **not** the independent four-lens approvals required by #98.
