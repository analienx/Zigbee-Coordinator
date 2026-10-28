# P7U F2 v4.3: comprehensive half-hour diagnostic archive

## Operational contract

This is a **passive** export of the *existing* zigbee-herdsman/Zigbee2MQTT F2 diagnostic journal. It NEVER accesses USB/serial, sends a ZNP command, publishes MQTT, restarts HA/Z2M, flashes, reforms the network, or changes NV/security.

The deployed P7U radio/host pair on 2026-10-28 uses F2 `minor=3`. The exporter works with the retained `p7u-f2-worker-v2` journal format and fail-closes if its hash chain or manifest is invalid. See issue #144 for root-cause evidence and current qualification status.

**Schedule:** every UTC half-hour boundary + 20 seconds, while Home Assistant Core is running. Export the *previous completed* UTC 30-minute interval. Prague local time may be CET/CEST; filenames are always UTC. The exporter does not backfill missing intervals after a long HA outage.

**Output:** `/config/zigbee2mqtt/p7u-b4-diagnostics/30min-dumps/`

- Immutable `f2_YYYYMMDDTHHMMSSZ.json`: full allowlisted safe fields of every VALID / FAILED / SKIPPED F2 event in the interval, plus per-host counter deltas, latency, errors, device-independent wire/queue metrics, intervals and provenance.
- `<filename>.json.sha256`: SHA-256 sidecar (actual file naming is `<filename>.sha256`).
- `latest.json`: latest export name, hash, status and issue flags, atomically replaced.
- Retention: **24 hours from window end**. Archive and source journal are local to HA; never publish MQTT payloads, raw IEEE/PAN/security, node identities or NV dumps to this archive.

Data integrity: strict single-generation current pointer / stable manifest snapshot, SHA-256 chain reconstruction, manifest sequence/bytes/head and last-valid identity, then atomic fsync+rename and separate checksum file. An integrity failure prevents a false healthy dump. A valid dump containing no F2 records is marked DEGRADED; AF timeouts, F2 failure events, radio UART errors or a stale final-five-minute section are flagged, not suppressed.

## Install on Home Assistant

The source file must be present at:

`/config/p7u-f2-dumps/export.py`

Its v1 deployment on 2026-10-28 was SHA-256 `fe4d9ab686477a05f5e370d2daeb8f17fd08a77aadf02341b0f3f4efae19b6e8`.

Home Assistant's `configuration.yaml` already includes `shell_command: !include shell_command.yaml`. Add to `/config/shell_command.yaml`:

```yaml
p7u_f2_halfhour_dump: "python3 /config/p7u-f2-dumps/export.py"
```

Add to `/config/automations.yaml`:

```yaml
- id: p7u_f2_comprehensive_halfhour_20261028
  alias: "P7U F2 - comprehensive diagnostics every 30 minutes"
  description: "Passive journal-only export; no Zigbee, radio, serial or MQTT access."
  trigger:
    - platform: time_pattern
      minutes: "/30"
      seconds: "20"
  condition: []
  action:
    - service: shell_command.p7u_f2_halfhour_dump
  mode: single
```

Use **Home Assistant configuration check**, then reload only `shell_command` and `automation` integrations; no HA/Z2M reboot needed. Confirm the automation entity is `on`. Restrict the exporter source, output, and any configuration backup to owner-only permissions.

## Read-only acceptance

On the HA host (inside its own core container), run:

```sh
docker exec homeassistant python3 /config/p7u-f2-dumps/export.py --dry-run
```

This validates the journal and prints only summary metrics without creating a file.

To create an immediate actual export of the last completed half-hour:

```sh
docker exec homeassistant python3 /config/p7u-f2-dumps/export.py
```

An existing period is never overwritten. Independently recompute SHA-256 and inspect `latest.json` for `status`, `validF2`, `issues` and the selected UTC interval. The HA automation action can be manually triggered to verify service wiring.

**2026-10-28 physical receipt:** the 09:30–10:00 UTC interval produced a 78,532-byte verified JSON dump, 16 VALID F2 minor3 samples among 23 events, and an intact sidecar hash. HA configuration check and integration reload passed; the automation was registered/enabled and manually triggered. Zigbee2MQTT continued serving with Docker restarts=0. The recurring time trigger was not yet independently witnessed at its next :00/:30 boundary.

**Residual:** Sampling is admission-gated; busy adapter queue can cause prolonged SKIPPED F2 records even while host device traffic succeeds. Exporter reports such gaps; it must not force native F2 reads. This archive is diagnostic evidence, not proof that the progressive SRSP hang is cured.
