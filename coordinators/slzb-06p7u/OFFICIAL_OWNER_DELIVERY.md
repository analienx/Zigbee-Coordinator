# P7U firmware delivery with the official Zigbee2MQTT app as owner

Since 31 October 2026 the official Zigbee2MQTT app (`45df7312_zigbee2mqtt`, 2.14.2-1) is the only serial owner. The custom host, owner inspector and fallback containers take no part in a delivery. This document covers the `official-z2m-v1` owner mode and the runner that automates a delivery. It authorizes no hardware action.

## What changed in the tooling

| Area | Official-owner behaviour |
|---|---|
| Owner identity | Pinned in [`host/flash/p7u_paired_binding.py`](../../host/flash/p7u_paired_binding.py): slug, app version and image ID. It is accepted only for the firmware sources in `OFFICIAL_SOURCES` (V54 `20a2474a` over installed V53 `8ec1439`). |
| Exclusive serial proof | The operator runs a read-only process scan from the pinned owner image (`--rm`, `--pid=host`, no network). Every process holding the coordinator TTY must belong to the owner container, or there must be none when quiescent. This replaces the retired inspector container. |
| App policy | The owner must be manual boot with watchdog and auto-update off. Retired custom apps may stay installed only if they are stopped with manual boot. |
| Backup size | The coordinator backup is admitted for 100–200 peers (previously 100–107). |
| Package | `package-p7u-paired-operator.yml` with `owner_mode=official-z2m` takes no host release. |
| Hang capture | Refuses explicitly with the official owner (review F1 is still open). |

## Runner

[`tools/p7u_official_delivery.py`](../../tools/p7u_official_delivery.py) wraps the flash driver. Its defaults pin the V54 delivery.

```sh
python tools/p7u_official_delivery.py preflight --package-run <run>    # read-only checklist
python tools/p7u_official_delivery.py automation off                    # flash window only
python tools/p7u_official_delivery.py prepare --package-run <run>       # fetch, stage, plan (Z2M keeps running)
python tools/p7u_official_delivery.py flash --authorize <operation id>  # deploy, boot, finish, serving
python tools/p7u_official_delivery.py automation on                     # after serving is accepted
```

`flash` stops Zigbee2MQTT for the write and boot window. It then performs one protected APP+AC000 write and one native boot, starts Zigbee2MQTT, and checks for fresh MQTT device traffic. Each step runs once. An ambiguous result is inspected with `status`, never replayed.

## Preflight blockers

- **SLZB management and `button.slzb_06p7u_zigbee_restart`.** The operator checks board identity over the SLZB web API and resets the radio into the new image with that button. Both need the board's network side (ESP32 Ethernet) online.
- **`automation.boot_deterministic_emqx_then_zigbee2mqtt` and `automation.zigbee2mqtt_p7u_auto_recovery_3_attempts` must be off** for the window, because both start Zigbee2MQTT and the second also resets the radio. The runner toggles both and logs the changes in the delivery workdir.

## Recovery after an SLZB power cycle

After a cold SLZB power-up (1 Nov 2026), Zigbee2MQTT failed twice with `SRSP - SYS - ping after 6000ms`. One SLZB radio-only restart (`button.slzb_06p7u_zigbee_restart`) with Zigbee2MQTT stopped, followed by a plain start, resumed the network. The HA automation `z2m_p7u_auto_recovery` does this: up to 3 attempts after the app has been stopped for 2 minutes. It never enters the bootloader, flashes or restarts the ESP. A running app with an offline bridge is only notified.

## Resilience: prediction, automatic restore, owner acknowledgements

- **Prediction before any outage.** `preflight`, and `prepare` just before `plan`, run both retained-security gates with the staged package's own modules. They compare the newest NV capture for the firmware source against the live Zigbee2MQTT coordinator backup. A predicted refusal blocks there, with no outage. The same analysis is available directly with `tools/p7u_addrmgr_diff.py [--live] [--ack JSON]`.
- **Automatic restore after a zero-write HOLD.** When `deploy` holds, the runner first proves nothing was written: no write or boot record, and a read-only capture receipt. It then presses the SLZB radio-only restart if the bootloader was entered, starts Zigbee2MQTT, waits for the bridge and turns the automations back on. A HOLD after a write is never handled automatically.
- **Owner acknowledgements.** These are the "migration authorized" path named by `ADDRESS_MANAGER_RETAINED_ROWS_CHANGED_NO_MIGRATION_AUTHORIZED` and `CURRENT_UNEXPECTED_PEER`. Pass `acknowledged_changes` to the package workflow, for example `[{"ieee":"0x…","change":"NEW_PEER"}]` or `"ASSOC_GAIN"`. The list is pinned in `PACKAGE.json` and admits exactly those devices and change classes. `NEW_PEER` covers a device added since the historical reference: a vacant address slot filled, plus the owner gate's new-peer check. `ASSOC_GAIN` covers a known device that became a direct child of the coordinator, with its security bit kept. `KEY_REROLL` covers a known device whose VERIFIED trust-centre link key was re-derived from the unchanged seed (a rejoin key update): only the seed shift may differ, while slot, attributes, key type and install-code index stay equal and counters may not regress. Nothing else is relaxed: keys, identity, counters, the trust-centre peer set, APS and replacement of an occupied row stay exact.
