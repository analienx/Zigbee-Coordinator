# P7U Recovery Guard — HA local add-on

**Default: dry-run, not armed.** This add-on independently observes Supervisor state, error logs, MQTT and SLZB-OS identity. It never connects to or opens the Zigbee ZNP serial port.

The deployment packaging step copies the reviewed repository source files from `host/recovery/*.py` into this directory *before* copying to HA `/addons/local/p7u_recovery`. The Supervisor locally builds the Dockerfile; no arbitrary scripts are installed into Zigbee2MQTT.

Zigbee2MQTT remains the exclusive owner of the USB radio. The SMLIGHT integration is preferred for Core restart and Zigbee restart. The user currently has no SMLIGHT entities in the HA entity registry, so an optional source-fingerprinted local fallback is defined in the agent. It is **disabled by default**; enable only after strict identity, USB mode, exact API mapping and dry-run acceptance.

Do **not** enable at the same time as a competing HA automation, external reset watchdog or active firmware flashing. If any required API or MQTT signal is missing, the watchdog must not reset.

Physical recovery requires `enabled: true`, `dry_run: false`, `serial_owner_approved: true`, `notify_on_confirmed_hang: true`, the private MAC/version binding and both source-qualified controls. These are independent admission requirements; setting only enabled/dry_run does not arm an unqualified device. In dry-run, the watchdog retains shadow decisions without calling its hardware actuator. `boot: manual` prevents an unaccepted watchdog from auto-starting at system boot.

Version 0.2.2 adds transaction-scoped crash persistence, genuine `last_seen: epoch` evidence, rotated-log bootstrap and bounded decoding of the installed compressed SLZB script. See the repository's `host/recovery/FINALIZATION_ACCEPTANCE_2026-10-22.md` for exact-source CI and live acceptance. Automatic physical recovery remains unarmed.

**Never** use manufacturer web API `cmd=9` or `flash` from the watchdog.
