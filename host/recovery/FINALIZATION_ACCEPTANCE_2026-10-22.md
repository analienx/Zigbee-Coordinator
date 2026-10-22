# Shared P7U recovery guard: finalization evidence — 22 October 2026

## Implemented and deployed

Guard **0.2.2**, exact runtime source [`5f9b53f`](https://github.com/analienx/Zigbee-Coordinator/commit/5f9b53ff03f808b383b691570a2152c35cdfa00b), is deployed to the existing HA local add-on. All eight Python modules inside the running container match their Git source hashes.

The final correction includes crash-safe UUID transactions, durable results and startup reconciliation, continuous stability, genuine RF timestamps, canonical SRSP attribution, subscription admission, current-process and rotated-log replay, bounded gzip decoding of SLZB command source, exact identity/control gates, and two-destination warning delivery.

Exact-source hosted verification: [recovery safety — 103 tests PASS](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39844961163) and [Python tests PASS](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39844961389). No local build/test result substitutes for these checks.

## Physical host acceptance

| Gate | Observed result |
|---|---|
| Consecutive valid observation window | 620 seconds / 31 samples |
| Genuine RF devices per rolling 120-second sample | 10–37 |
| Largest SRSP count in those samples | 1 |
| MQTT subscription, inventory, RF capability, process/log evidence | Valid |
| OTA state during accepted window | Known, inactive |
| Guard-only restart | PASS; real ledger preserved byte-for-byte |
| Post-restart observation and RF evidence | Valid again |
| Physical recovery action intents | 0 |
| Zigbee2MQTT after acceptance | Started; original application epoch retained |

The approved `last_seen: epoch` live option was acknowledged with `restart_required:false`. No Zigbee2MQTT restart was requested for it. A read-only database count found 107 saved IEEE rows: one coordinator and 106 non-coordinator devices; this distinguishes total saved identities from joined-device rows.

One labelled synthetic WARNING was accepted by both HA services and independently found through HA's native API in System Log and the persistent-notification list. Its dedicated ID is `p7u_coordinator_recovery_acceptance_test`; it is not a genuine hang incident. The test was not repeated when verification was queried again.

Both permitted SLZB controls qualified read-only against the actual device. SLZB-OS serves the script compressed: wire SHA256 `1c281812686d1d78911ea8163daca74a8c7507e31305f09e505d5385a5e70834`, decoded source SHA256 `2d50552d71bf55f8f87aeabece9f4dae01d589d9e2e88699ec0b15e8e8e600ed`. Admission pins the decoded source and exact integer mappings. Neither control was actuated.

## Operational limits

The guard remains **enabled=false, dry_run=true, boot=manual**, private fallback disabled and ownership approval false. Production confirmed-hang notifications retain their separate default-disabled option; the explicit synthetic test above proves delivery. No automatic reset was armed.

This accepts source correctness, deployment, real passive observation, restart persistence and notification integration. It does not establish automatic physical recovery, multi-day radio stability or the cause of the stock/R4 SRSP hang. Radio firmware, NV, CCFG, network security and connection mode were not changed; no radio reset, flash, re-pair or power cycle was performed.

Draft PR #146 remains the review vehicle. Independent activation approval and actuator acceptance precede arming. R4 single-owner F0/F2 collection remains #144; stock deployment remains #145.
