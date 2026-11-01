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
- **`automation.boot_deterministic_emqx_then_zigbee2mqtt` must be off** for the window. The runner toggles it and logs the change in the delivery workdir.
