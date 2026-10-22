# P7U R4 original-owner F2 — exact-source deployment / acceptance gate

Status: **GitHub-built OCI candidate; not yet installed or hardware accepted.**
Parent PR #142; collector PR #147, issue #144. One production SLZB-06P7U,
USB serial by-id, 106 non-coordinator devices. The retained Zigbee network
is serving users. No separate experimental P7U or second UART owner exists.

## 1. Source and binary integrity

- Actual serving host: Zigbee2MQTT 2.14.0-1, herdsman 10.9.1, image
  `ghcr.io/zigbee2mqtt/zigbee2mqtt-aarch64@sha256:97246758dab5099113c5a46fcbc1b9a36968a0eb9fd95ce8df6e2868cc7f533f`.
- The hosted source pipeline `.github/workflows/test-r4-b4-host.yml` compiles
  both pinned upstream TypeScript trees and all existing-owner overlays. It
  builds a **new** arm64 OCI image from the exact installed image digest,
  rather than modifying live `node_modules`.
- `p7u_native_image_audit.py` compares the actual exported OCI layer
  controller, OTA bridge and critical herdsman files to the recorded
  compiled-source SHA256 values. A successful tar export alone is not enough.
- Read `SOURCE_RECEIPT.json`, `OCI_SOURCE_AUDIT.json`, `oci.sha256`
  and the associated exact-head hosted test run together.
- The older release-folder `candidate.json` under
  `C:/Workspace/artifacts/p7u-r4-release-323949a` identifies a
  **STOCK20260311 donor/unsealed** image. It is not attestation of the
  physically flashed R4 SYS F2 handler. Separate flash/startup receipts
  establish state9 and source marker `323949a`, **not** F2 binary capability.

## 2. Admission before touching the serving Z2M host

1. Establish the actual installed radio F2 ABI: full canonical 160-byte
   SYS F2 payload; fixed v4 header/version, nonce echo at offsets 132–139;
   linked native read-only handlers and code-image provenance. A matching
   8-byte firmware source marker on its own is insufficient.
2. Attest the exact current Z2M container epoch, image digest, Supervisor
   slug/config and options without printing passwords, keys or full database.
   Validate source-to-image and Z2M/herdsman pin matches.
3. Preserve the current Z2M data directory (including database and current
   backup) privately, with hashes and verified rollback ownership. This is
   host-data preservation, NOT counter replay or a reason to restore NV.
4. Stage the verified arm64 image as a **separate managed HA add-on**
   matching the official Zigbee2MQTT add-on's startup/options and required
   `/config`, `/addon_config`, `/share`, `/dev` semantics. Ensure its
   Z2M data path and original by-id path match production, and that its
   diagnostic opt-in `P7U_B4_COLLECTOR=1` is explicit in the reviewed
   managed service. Do **not** start a duplicate owner just to test admission.
5. The proposed new add-on must have manual boot and watchdog disabled.
   The existing `45df7312_zigbee2mqtt` add-on must be stopped and its
   auto-boot prevented before the new host can start. Confirm no second
   process has opened the tty. Do not overwrite the current official image
   tag or edit its immutable application files in place.
6. Keep `local_p7u_recovery` passive. Any changed process/startup epoch
   must be learned from fresh native logs, not copied from old history.

## 3. Single change window and rollback

The hosted image is a reviewed *candidate*. The production switch is not
covered by a green offline test alone. First stage the image and its full
rollback payload with the production service still up. At the change window:
stop original Z2M once, assert original owner closed, start only the managed
candidate, and verify normal network identity/traffic without a radio reset,
flash, re-pair, NV erase, USB/Ethernet change or counter replay.

If the candidate fails to initialize, can't own the existing port, or causes
a device identity/network mismatch, stop it and revert to the previously
installed exact vendor image and original Z2M host data. Never run both at
once or automatically repeat failed starts.

## 4. Real F2 acceptance

- At least **three** consecutive F2 records with `kind=VALID` in private
  `/config/zigbee2mqtt/p7u-b4-diagnostics/history.json`, followed by the
  matching durable `last-good.json`. Samples must originate from the live
  *original* serial owner, with measured host receive times and valid
  monotonically advancing native sequence under one boot identity.
- Verify real nonce echo, exact frame size/version, OTA/queue/owner gates,
  native counter validity, no unexpected reboot, no raw nonce or raw boot
  token in logs, bounded storage, and no serial command by a second process.
- Verify normal Zigbee device messages remain fresh and no SRSP/AF regression.
  Never claim a successful radio recovery based on MQTT retained state.
- A missing/poisoned diagnostic session becomes `UNKNOWN`: do not force a
  second F2 request or restart radio to make the test pass.
- A host collector/Z2M restart is a separate acceptance action requiring a
  controlled window. Genuine F2 records must survive that restart.
- **Do not deliberately trigger pairing/Permit Join load** until these
  samples exist. Stop on first SRSP timeout if later reproducing.

## 5. Separate warning and physical-recovery policy

Guard 0.2.3 is independent of B4. Real warnings may be enabled via
`host/recovery/enable_warning_only.py` only while the policy still has
`enabled=false`, `dry_run=true`, `serial_owner_approved=false` and
`allow_private_http_fallback=false`. That operation MUST NOT arm a reset.

Unattended ESP/radio recovery remains a separately authorized operation;
neither an image swap, debug sampling, successful compilation nor green
recovery-guard tests grant that authorization.

## Source/operation truth

| Capability | Requirement to say DONE |
|---|---|
| Source compiled | Green exact SHA GitHub native test |
| Host image built | OCI artifact + matching OCI_SOURCE_AUDIT |
| Installed | HA slug/image hash and live process attested |
| Native collection | 3 genuine full-ABI serial-owner F2 samples |
| Root cause fixed | Direct before/after measured evidence |
| Automatic recovery ready | Independent physical admission/acceptance |

Preserve these distinctions in PR/issue comments; never close #144 based on
host compilation or mark #143 unattended recovery from a passive soak alone.
