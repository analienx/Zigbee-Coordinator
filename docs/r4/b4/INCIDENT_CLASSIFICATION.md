# R4 B4 incident classification / alternative-explanation ledger

No root-cause assignment is made from a single correlated symptom. Use source labels **DIRECT_OBSERVED, SOURCE_PROVEN, HOSTED_SYNTHETIC, HOSTED_NATIVE_LINKED, HYPOTHESIS, NOT_MEASURED, UNKNOWN, PHYSICAL_UNVERIFIED** independently from event category.

| Evidence | Safe observation | Cannot conclude | Alternatives to retain |
|---|---|---|---|
| Host SIGTERM/code0 | HOST_STOP_OBSERVED | spontaneous crash, radio failure | service stop, supervisor policy, routine restart |
| USB disappears/re-enumerates | USB_DISCONNECTED_OBSERVED; MT unavailable | firmware hang | USB bridge, cable/power, host device/driver |
| Serial exists but SYS+AF+ZDO SRSP timeouts | request/response path unresponsive | coordinator MCU hung | host parser, UART bridge, NPI queue, radio task |
| F0 responds but AF/ZDO SRSP fails | SYS handler can reply at sample time | AF/ZDO RF failure is proven | subsystem queue, pending waiter, bridge/parser |
| AF SRSP timeout | local acceptance not observed | AF confirm, ZCL timeout or RF delivery proven | host waiter, coordinator AF dispatch, stack congestion |
| AF_CONFIRM without ZCL response | stack completion category | application success | endpoint asleep, ZCL unsupported, APS route |
| NWK/route source failure | RF routing event if actual B2 hook | UART/USB diagnosis | stale path, routing table, mesh topology |
| UART2_write accepted, no TX callback | write submitted | byte delivered to host | UART state, callback, bridge |
| UART TX callback but no host frame | callback observed | host saw valid packet | USB framing, parser and process queue |
| OTA overlaps symptom | CORRELATED_ONLY | OTA caused fault | independent routing or host load |
| Host restarts, unknown radio boot | HOST_PROCESS_EPOCH only | same or different radio epoch | continuity unverified; NO delta |
| Radio boot validity absent | RADIO_EPOCH_UNKNOWN | monotonic counter comparison | reset/wrap/time ambiguity |

**Receipt limits:** `b4_replay.py` publishes only sanitized event counts, observed category and bounded alternatives. It intentionally omits raw logs, device IDs, network addresses, keys, packet contents and per-waiter IDs. The 24-hour offline recorder is not installed; no production host evidence is claimed. `root_cause: UNKNOWN` unless independent multi-source proof is introduced in a separately reviewed version.

## Executable conservative classifier (offline only)

`firmware/slzb-06p7u/r4/b4/b4_inference.py` implements this table as a strict allowlisted boolean-evidence classifier. `classify()` outputs explicit `root_cause=UNKNOWN`, source class `OFFLINE_EVIDENCE_ONLY`, alternatives and unknown B2/B3/HOLD fields; `uart_interval()` returns no deltas unless both counters are valid 32-bit and same-radio-epoch continuity has been separately source-qualified by the caller. It never treats transport write acceptance/completion as a host receipt, late AF_CONFIRM as ZCL success, OTA overlap as causation, SIGTERM as spontaneous crash or USB detach as radio freeze. Untrusted keys, PAN/IEEE/device fields, raw packets and contradictory simultaneous detached/connected USB states are rejected.

`tests/test_r4_b4_inference.py` contains 15 hostile offline counterfactual tests; executed in source workflow stage [39003058774](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39003058774). This is an interpretation reference, **not a sensor**; absent radio/USB/B1/B2/B3 producers remain `NOT_MEASURED`. Confidence remains observational and no physical test is claimed.
