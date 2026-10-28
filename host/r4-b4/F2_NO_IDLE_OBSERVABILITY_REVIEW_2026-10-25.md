# P7U R4 F2 — no-idle evidence repair

Date: 2026-10-25. Scope: **host-only source**, built on GitHub at exact source commit. No change to radio firmware, ZNP wire protocol, UART owner, coordinator NV or retained network.

## Incident addressed

A single `networkmap` request with `routes:true` took 30m43s on the 59-router household. The bridge returned 107 nodes/1,192 links but 44 routing-table and 15 neighbor/LQI errors. There were three production AF SRSP timeouts. The original F2 collector stopped receiving native responses because admission was blocked on busy owner and recorded `OUTER_ADMISSION_GATED` without a reason or command-path metrics. A refused F2 attempt is **not** an F2 reply timeout or radio hang.

## Changes

1. On every 60s F2 sampler tick, persist the no-UART host-owner snapshot regardless of whether a native F2 request could be admitted. The data is emitted through the already existing bounded worker/manifest/hash chain. No new timer, MQTT transaction, host process, serial opening or ZNP request.
2. Replace the compound adapter gate with stable, mutually exclusive reasons: adapter queued, ZNP mutex busy, Waitress pending, OTA blocked, owner closing/disconnected, inter-PAN lock, disabled, guard revoked or timeout cooldown. Zigbee2MQTT-level early admission is separately named. F0 remains unchanged.
3. Passive **production SRSP** aggregate counters per AF/ZDO/SYS/UTIL: count successful matched request replies, count exact Waitress SRSP timeouts and report monotonic maximum/latest response time. These metrics are host-owner-lifetime and **not** evidence of radio uptime; they include no device identity, command payload, nonce or security material. Optional F0/F2 replies and F2 timeouts do not inflate production counters.
4. Add strict worker allowlist and nested-field/range/type validation. Unexpected keys or oversized records fail closed. The record limit stays 3072 bytes; existing historical records remain accepted.
5. New compiled-pinned-herdsman adversarial tests cover no-wire admission during mutex ownership and pending Waitress, owner/OTA checks, ordinary matched replies, genuine SRSP timeout and F2 exclusion; worker tests enforce nested privacy and durable replay.

## Correct interpretation

- `mutexIdle=false` means owner is occupied; it is **not** proof radio is frozen.
- `waitressPending>0` means outstanding host Waitress entries; original herdsman may retain timed-out stock waiters, so the count does **not** necessarily mean an active wire transaction. It is a useful diagnostic signal and may explain F2 starvation.
- `srsp.*.timeout` counts host-command SRSP failures, not RF `NWK_NO_ROUTE` failures; `srsp.*.ok` counts normal host SRSP acknowledgements, not end-device delivery.
- `lastLatencyMs` measures the local host wait for a matched reply, starting immediately after the synchronous writer call. It is not air latency.
- A permanently busy map can still prevent an optional F2 read; diagnostics then consist of passive owner/worker signals, not native radio queue data.
- Native R4 validity mask `0x2c` still means SRSP depth/high-water fields are UNKNOWN. No fabricated counters, reboot epoch or runtime radio attestation.
- This is a **visibility fix**, not proof the underlying AF timeout/root routing problem has been solved.

## Release and deployment gates

- Compile real pinned herdsman + Z2M sources on GitHub Actions and run regression/fault tests. Do not use the Windows worktree as release evidence.
- Before replacing a running host, verify currently deployed exact source and owner, retained 128-row/107-identity DB, cold backup, native management, recovery guard off, one serial owner and no running scan/OTA. Never start two Z2M owners.
- Reuse the reviewed single-use handoff path with fresh unique intents and evidence. Do not replay old one-use receipts. No automatic reset/flash/re-pair.
- Post-install require new owner and image attestation, fresh device MQTT, at least three valid native F2 reads, and at least one bounded intentional no-idle admission observation **without active RF stress**. Do not claim a long soak passed before it does.
