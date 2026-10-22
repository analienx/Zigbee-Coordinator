# Shared stock/R4 recovery watchdog — policy module only

**Status: source-only draft; never installed, never armed.** [Issue #143](https://github.com/analienx/Zigbee-Coordinator/issues/143) is the implementation/acceptance record. The exact current HA radio firmware is irrelevant to this **shared** state machine. R4-only read-only B4 collection is tracked separately in [#144](https://github.com/analienx/Zigbee-Coordinator/issues/144); stock qualification separately in [#145](https://github.com/analienx/Zigbee-Coordinator/issues/145).

`policy.py` intentionally has **zero dependencies, networking, GPIO, SLZB HTTP, ZNP, HA API or MQTT code**. Nothing happens unless a separately independently reviewed HA-hosted executor consumes the returned `Decision.action`. All commands must be wrapped in an **atomic durable write-ahead attempt journal** (fsync file + rename + exclusive lock) *before* being sent. Pending state after process crash means **do not replay** that action. A proposed action is neither an instruction to immediately issue it nor a claim that the target acknowledged it.

## Source-grounded physical failure and recovery

On 22 October 2026, exact native R4 `323949a` reproduced the stock-class AF/ZDO/UTIL/SYS hang. Owner-approved once-only physical recovery demonstrated:
1. Official SMLIGHT Zigbee Restart (`action=4&cmd=1`): HTTP 200 `ok`; one Z2M start subsequently **failed at `SRSP - AF - register`**.
2. Official ESP32 Restart (`action=4&cmd=3`): HTTP 200 `ok`; USB re-enumerated; one Z2M start **succeeded** with herdsman running, MQTT connected and real device reports. At 19:56:36 Z2M showed 106 used-entry joined rows; database still retains 107 identities. Initial `NWK_NO_ROUTE` device warnings must not count as radio failure.
3. No true power cut, `cmd=9` hard reset, flash, NV restore, factory reset, serial-mode change or network re-pair was done.

**Never use `cmd=9`:** 'hard reset' is ambiguous and not covered by the approved radio+ESP reboot recovery procedure. Never infer that an ESP restart fully removes CC2652 power. If USB and PoE supply power simultaneously, a PoE outlet cycle alone is *not* a real power cut. True power cycling requires a separate independent supply controller and direct hardware proof; default strictly OFF.

## Adapter integration contract (not implemented yet)

A genuine deployed watchdog on HA must consume **current-epoch** data from:
- HA Supervisor add-on `45df7312_zigbee2mqtt` state and bounded *new* log lines, ideally directly from Supervisor rather than SSH.
- MQTT broker presence and Zigbee2MQTT bridge state/health age, excluding retained messages and bridging events.
- At least 3 distinct non-bridge real device message topics and recent timestamps; health `messages` counters must have advanced, not merely exist.
- SMLIGHT `/ha_info` identity/mode and device by-id on HA; mode USB, serial owner exclusive; ESP reachable on LAN.
- Maintenance/flash/OTA, manually triggered stops or HA service restarts must **inhibit** recovery. If bridge is online but UART starved, plain Z2M process state and MQTT bridge health may remain misleading.
- Optional R4-specific last-good F2 counters from the existing single-owned herdsman without opening a second UART.

Sampling proposals: 30–60-second low-priority windows, two independent observations 30s apart for serious adaptive faults; adapter-specific errors from the current process epoch, not October historical log lines. Use a persistent monotonic-in-boot sequence and wall-clock jump check. Never use raw IEEE addresses, network keys or packet payloads in persisted reports. Synthetic fault-injection must cover repeated offline state, a single router offline, planned supervisor restarts, MQTT broker outage, partial HTTP response, start command accepted but no herdsman, and counters stalling during ordinary quiet windows.

### Actuation executor requirements

The `policy.py` decision is only a proposal. A separate executor must:
- Require explicit feature enablement, allowlist identity, HA native SMLIGHT button identity and installed version; prefer `button.press` Zigbee Restart via supported HA integration. Private SLZB-OS web fallback is undocumented and version-fingerprinted; do **not** send >1 req/s or internet-bound control.
- For `STOP_Z2M`, do nothing when already errored/stopped; otherwise require independent stopped proof before resetting. Preserve logs/forensics first.
- Execute `RESET_RADIO` once, record time and HTTP/native HA service response, never retry on ambiguous network failure.
- For `START_Z2M`, wait for USB re-enumeration and expected by-id, then request one HA add-on start. 'HA start returned ok' is not proof. New startup may fail at AF registration even when SYS responds.
- For `RESTART_ESP`, verify actual SMLIGHT `Core Restart` entity or installed web `CMD_ESP_RES:3`; no factory reset, no firmware flash or power cut. Since this may disconnect/re-enumerate USB, verify the stable by-id port before one more Zigbee2MQTT start.
- Confirm `zigbee-herdsman started`, `Zigbee2MQTT started!`, fresh MQTT bridge/state online, >=3 actual non-bridge device reports, and 120s stability. Restarts are capped by the policy, with six-hour cooldown and maximum two radio resets per 24h; exhaustion alerts a human.
- Persist a redacted immutable report on HA's persistent filesystem with hash and version. Start disabled/dry-run; enable only after exact source CI + local dry run + independent review. Only ONE watchdog/serial owner must be active.

## Tests

```bash
python -m unittest tests.test_p7u_shared_recovery_policy -v
```

Tests intentionally **do not connect to HA** or touch a device. Work from pinned deterministic sample inputs, including the actual 22-Oct `SYS ping` → radio reset → `AF register` failure → ESP reboot → restored live MQTT-traffic sequence. GitHub CI gates source correctness; physical product acceptance remains a separate gate.

References: https://www.home-assistant.io/integrations/smlight , https://smlight.tech/support/manuals/books/slzb-os/page/slzb-os-api-endpoints , https://github.com/Koenkk/zigbee2mqtt/issues/32837 and https://www.zigbee2mqtt.io/guide/usage/health.html .
