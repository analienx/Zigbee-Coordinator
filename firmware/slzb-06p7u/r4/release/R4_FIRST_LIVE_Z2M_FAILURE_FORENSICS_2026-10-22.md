# R4 first real full-size live failure: stock-class ZNP/SRSP starvation (2026-10-22)

## Outcome — physical, observed, unresolved

**R4 reliability qualification: FAIL. Root cause: UNDETERMINED.**
The sole production SLZB-06P7U / CC2652P7 running exact
`323949a95c9a07901c4ffc3d026fca414982c148` completed
source-bound 3-sector APP-only flash, preserved NV4/CCFG, booted with a genuine
state-9 marker, and operated on the retained 107-device Zigbee installation,
but reproduced the stock firmware's progressive ZNP response loss. No
additional radio reset, flash, NVM restore or re-pair was performed to
investigate. Preserve pre-existing private flash/boot receipts.

## Real source comparison

Ground truth is the actual HA Zigbee2MQTT `log.log` (not merely MQTT retained
state, a synthetic incident trace, or Github CI). Script:
[`p7u_r4_failure_compare.py`](p7u_r4_failure_compare.py). No raw logs, IEEE,
keys, PAN, or payload values are exposed in its printed summary.

| Event | Stock, 16-Oct (boot 08:25:21) | R4, 22-Oct (boot 18:38:27) |
| --- | --- | --- |
| First AF SRSP dataRequest timeout | 09:00:57 (~35m) | 18:53:44 (~15m) |
| AF dataRequest SRSP timeout text lines | 64 | 19 |
| AF dataRequestExt SRSP timeout lines | 2 | 1 |
| ZDO SRSP timeout lines | 6 | 10 (includes MQTT echoes) |
| No-route text | 7 | 31, mostly startup |
| Buffered join command failure | not established | 19:05:01, 19:05:03; `BUFFER_FULL 0x11` |
| Full stop | SIGTERM 09:43:58 | SIGTERM 19:29:10 |
| Basic SYS_PING after the failure | NOT MEASURED | fails 19:30:02 |

**Do not compare raw event totals as failure rates:** operating durations, join
activity and OTA differed. The stock 16-Oct session included stalled OTA
activity; R4 had repeated Permit Join requests. Neither is proven causal.
Text `ZDO -` in an MQTT response also repeats the original error, so count
underlying requests separately. The current R4 root cause is not identified.

Chronology: early R4 `NWK_NO_ROUTE` gradually eased, and genuine device MQTT
publications continued. Some AF SRSPs began failing at 18:53; join broadcasts
showed `BUFFER_FULL` at 19:05. At 19:22 the previously offline
`WorkRoomSwitchLedMain` rejoined with original IEEE and new NWK; seven stored
binding rows survived. One device-specific configure at **19:27:10** failed
`SRSP - ZDO - bindReq after 6000ms`; user-initiated/other Permit Join requests
at **19:27:36/42/54 and 19:28:16** failed with
`SRSP - ZDO - mgmtPermitJoinReq after 6000ms`. HA Supervisor shows application
stop at 19:29:10 and container exit 137 after delayed stop, then app startup
19:29:40. The initiator of the stop is UNKNOWN, not a proven spontaneous app
crash. Serial opened but new zigbee-herdsman startup failed with
`SRSP - SYS - ping after 6000ms` at **19:30:02**, with app state `error`.
No safe basis for another join/bind/startup attempt while radio unresponsive.

## Radio-vs-bridge evidence

HA `dmesg`: SMLIGHT USB CDC device enumerated at 18:33:46 as ttyACM0, and
**no subsequent detach/re-enumeration appeared in kernel ring buffer**
through roughly 19:42. Vendor SLZB-OS ESP management APIs still responded,
including GET-only `/ha_info`, `/metrics`, and `/api2?action=5`.
The ESP startup log shows normal USB device mode / Zigbee UART2 115200
without hardware flow; no radio UART crash diagnostics were emitted into
the small management log. This does not rule out a **logical UART bridge stall**,
radio RTOS/MT dispatcher deadlock, or SRAM/queue exhaustion.

## Why the original initiative existed and what remains missing

[#85](https://github.com/analienx/Zigbee-Coordinator/issues/85),
[#87](https://github.com/analienx/Zigbee-Coordinator/issues/87) and
[#98](https://github.com/analienx/Zigbee-Coordinator/issues/98) explicitly
targeted the Oct16 stock progression: 64 AF SRSP, 6 ZDO join SRSP and 69
later data-request TIMEOUT, with **zero live P7U queue measurements**.
R4 built reproducible full capacity/security boot and linked **B4 SYS F0
(132 bytes) / F2 (160 bytes)** diagnostic interfaces in the native ELF.
However the **host-side B4 overlay is default-off, not deployed**:
`host/r4-b4/UPSTREAM.json` says `default_enabled: false`,
`installed_host_changed: false`; official production Zigbee2MQTT logged no
contemporaneous F0/F2 snapshots. By the endpoint, ordinary SYS_PING failed,
so new F0/F2 request cannot reconstruct the lost earlier internal state.

**This is a production observability gap.** Do not present native counters or
hosted fake/synthetic replay as captured physical crash diagnostics.

## Highest-priority corrective acceptance

1. **First instrument, then reproduce.** Install and accept the already coded
   canonical B4 existing-single-owner host collector in the actual
   Zigbee2MQTT/herdsman runtime, with explicit manual/approved sampling,
   30s-scale (not aggressive) bounded/redacted periodic last-good history
   while idle, and first-AF-SRSP failure escalation. Require source-bound ABI,
   no second tty owner, no raw keys/frames, no OTA interference, and proof the
   snapshots are actually persisted **on HA** before a fault. Define
   callback-safe collection when host busy; static opt-in default-off cannot
   meet the current incident-forensics acceptance.
2. **Interpret live counter deltas only when valid.** Separate SREQ parser
   received, MT task dispatch, SRSP enqueued, UART write accepted,
   UART_TX_FINISHED, host receipt, AF confirmations, per-queue depth/HWM,
   heap/stack headroom, radio epoch, and ESP bridge resets. Numeric counter
   delta needs valid boot epoch and monotonic continuity. If MT is already
   stuck, F2 cannot answer; last-good samples and a stronger independent
   crash-state retrieval mechanism are needed. No arbitrary diagnostic NV
   writes that risk retained security.
3. **Fix only a measured reason.** Review current full-capacity
   TC300/APS3/associations97/source192/neighbors64/routes128 resource profile
   and old stock 20260310 baseline, plus TI task/NPI UART queueing and
   SLZB-OS ESP serial bridge. Do not assume routing, joining, OTA, or firmware
   flash is causal. Keep the sole radio/security snapshot safe; plan any
   controlled recovery independently.

Public context: https://github.com/Koenkk/zigbee2mqtt/issues/32837,
https://github.com/Koenkk/zigbee2mqtt/issues/31092. Those are useful external
comparators, not proof that this specific P7U R4 failure is an ESP bug.
