# One-shot P7U host handover

The manager image is built by `test-p7u-lifecycle-manager.yml`. The release
workflow packages it with the exact-source diagnostic, protected fallback,
and host-PID inspector. Installation is a separate, authorized Supervisor
operation. This manager cannot install images or change protection settings.

The release receipt binds source SHA, generated add-on configuration, Docker
archive hash, and immutable image ID. Supervisor must install the prebuilt
profiles from the loopback-only registry using the generated configurations;
there is no compilation or application patching on Home Assistant.

Create a private plan below `/share/p7u-lifecycle/private/`. That directory,
every intervening directory, and the operation directory must have mode
`0700`; the plan must have mode `0600`, with no symlinked path component.
The plan fields are:

```json
{
  "schema": "p7u-one-shot-plan-v1",
  "source_sha": "EXACT_40_HEX_HOSTED_SOURCE_SHA",
  "operation_id": "LOWERCASE_UUID",
  "serial_by_id": "/dev/serial/by-id/EXACT_PRODUCTION_DEVICE",
  "original_slot": "official",
  "target_slot": "diagnostic",
  "original_owner": {
    "container_id": "EXACT_64_HEX_CONTAINER_ID",
    "pid": 12345,
    "started_at": "EXACT_DOCKER_STARTED_AT",
    "image_digest": "sha256:EXACT_64_HEX_IMAGE_ID"
  },
  "diagnostic_image_sha256": "EXACT_64_HEX_RELEASE_IMAGE_ID_WITHOUT_PREFIX",
  "fallback_image_sha256": "EXACT_64_HEX_RELEASE_IMAGE_ID_WITHOUT_PREFIX",
  "image_references": {
    "diagnostic": "localhost:50144/p7u-r4-diagnostic:0.2.1-SOURCE_FIRST_12_HEX",
    "fallback": "localhost:50144/p7u-r4-fallback:0.2.1-SOURCE_FIRST_12_HEX"
  },
  "preserved_backup_path": "/backup/EXACT_PRIVATE_PRESERVED_HOST_ARCHIVE",
  "preserved_backup_sha256": "EXACT_64_HEX_ARCHIVE_SHA256",
  "mqtt": {
    "host": "core-mosquitto",
    "port": 1883,
    "username": "PRIVATE_BROKER_USERNAME",
    "password": "PRIVATE_BROKER_PASSWORD"
  },
  "expected_topics": ["EXACT_DEVICE_ONE", "EXACT_DEVICE_TWO", "EXACT_DEVICE_THREE"],
  "ha_entity_id": "sensor.exact_existing_entity"
}
```

Use the actual private source bytes to calculate the SHA256 in the manager's
add-on options. Options have exactly `plan_path`, `plan_sha256`, and `execute`.
Keep `execute=false` for the initial privileged preflight. It inspects host
PID/cgroup/tty ownership, both installed image IDs, passive guard policy,
service options, backup hash, and retained DB; it makes no service changes.
All three owner add-ons must have manual boot and watchdog disabled.

The two one-shot helpers declare `host_pid`, `SYS_PTRACE`, `DAC_READ_SEARCH`
and `apparmor: false`. Protection mode must be off for those helpers. A
host-wide FD scan must inspect processes confined under other AppArmor
profiles, so Docker's default profile is insufficient even when the Linux
capabilities are present. This exemption applies only to the two manual
one-shot helpers; it does not alter host AppArmor or the owner add-ons.
Neither helper uses `full_access`. Any inaccessible FD still causes HOLD;
incomplete enumeration must never be interpreted as an unowned UART.

For the authorized one-shot execution set `execute=true` and start the
manager once. A global lock excludes other managers using different plans.
The durable `active-operation.json` pointer and per-operation
`journal/events.jsonl` are written before a stop/start. They survive failure
and completion. A repeat invocation cannot repeat an ambiguous request;
reconcile those files with actual Docker/Supervisor/tty state before any
separate subsequent operation. Never delete an interrupted intent to retry.

After one graceful stop, three fresh observations must establish zero tty
holders. The manager preserves a fresh private `cold-host-data.tar`, verifies
its database against the latest committed database, then seals or verifies
the retained DB approval before one start. The three known extension
`node_modules -> /app/node_modules` links are archived as links without
following them; other symlinks and special files cause HOLD.

Successful serving admission requires three fresh non-retained device topics
and a valid cached HA state read. F2 collection is separately evaluated from
its durable history and does not trigger an automatic restart. An ambiguous
stop, failed start, or incomplete serving evidence causes HOLD and preserves
the journal. This image never resets the radio, forces container termination,
restores NV/counters, or automatically starts another owner.
