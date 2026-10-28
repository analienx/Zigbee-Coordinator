# P7U R4: USB/Zigbee2MQTT acceptance and fast-flash audit — 2026-10-22

**Production board:** SLZB-06P7U, CC2652P7, one physical board, no spare.
**Firmware:** `323949a95c9a07901c4ffc3d026fca414982c148`; flash/restore operation already accepted as recorded in [PR #136](https://github.com/analienx/Zigbee-Coordinator/pull/136).
**No reflash, NV replay, factory erase, radio power cycle, counter rewrite or device re-pair has been performed during this session.**

## Genuine USB recovery

Owner switched SLZB mode to **USB**. HA read-only detection:
`/dev/serial/by-id/usb-SMLIGHT_SMLIGHT_SLZB-06p7U_SLZB-06p7U115236-if00 -> /dev/ttyACM0`.
Zigbee2MQTT add-on `45df7312_zigbee2mqtt` already configured with that
path, `adapter: zstack`, `baudrate: 115200`, `rtscts: false`, watchdog OFF.
**Do not switch Zigbee2MQTT to TCP** or undo the user's mode change.

Versioned `p7u_z2m_usb_acceptance.py` asserted source-bound,
`COORDINATOR_STATE9_MARKER_PASS` startup receipt, 3-sector validated flash
with NV/CCFG untouched, USB enumeration, and matching HA options. A **single
durably locked** HA add-on start was then issued at approximately 18:38 local
using `ha apps start 45df7312_zigbee2mqtt --raw-json` and returned success.
No automatic retry. Startup was subsequently proven by read-only log evidence:
- zigbee-herdsman started
- Zigbee2MQTT started
- MQTT server connected
- natural Zigbee reports and availability messages published to MQTT
- add-on state continues `started`

**Important diagnostic script correction:** the initial v0 tail-anchor observer
exhausted its log window under heavy publication volume and wrote a conservative
`WATCH_TIMEOUT_NO_PASS` receipt **despite the add-on running**. That receipt
must remain unchanged as evidence of a monitor bug, not a coordinator failure.
The revised script falls back to the exact timezone-aware one-shot start
timestamp when the prior log tail is evicted. See focused regression tests.

The independent read-only `p7u_z2m_usb_health.py` analysis of the larger
start-window log yielded **790 MQTT publications, 125 distinct Zigbee2MQTT
device/group topics**, 59 topics publishing after the first 90 seconds, no
startup failure signatures, and verified running HA add-on. These are topic
counts, **not a claim that all 107 original devices are online**.

## Routing remains degraded

Some devices returned **NWK_NO_ROUTE** during Zigbee2MQTT ping/availability
refresh after the successful startup. Distinct sources included several
living-room bulbs/dimmers and workroom/bedroom devices; multiple warnings
persisted **after 90 seconds**, so they are not all attributable to the
very first startup moment. This is **partial operational acceptance**:
Zigbee2MQTT and MQTT are working, but full 107-device routing reliability
has not been demonstrated. The diagnostic script explicitly returns
`overall_acceptance=PARTIAL_ROUTING_DEGRADED` and reports per-device no-route
counts after warmup. It does not probe or alter any device.

### Repeatable diagnosis — no manual log inspection

From the Windows repo with Home Assistant reachable through audited SSH
alias `ha` (Windows/Python only, no WSL):

```text
python firmware/slzb-06p7u/r4/release/p7u_z2m_usb_acceptance.py --private C:\Workspace\.analienx\zigbee-private\p7u-r4-323949a-reconciled-20261022
python firmware/slzb-06p7u/r4/release/p7u_z2m_usb_health.py --private C:\Workspace\.analienx\zigbee-private\p7u-r4-323949a-reconciled-20261022 --lines 4500 --save
```

The first command is **read-only preflight**. The one-time **optional**
`--start-once` starts Z2M only when not already running, after the gates
and an exclusive persistent `start-attempt.json` marker; **do not use it on
this already-started coordinator**. No retry support, even if the observer
times out. The second command is purely read-only, reports parsed startup,
timestamped MQTT activity, per-device routing failures and post-warmup
state, and writes only aggregated nonsecret evidence.

Private evidence is held in:
`C:\Workspace\.analienx\zigbee-private\p7u-r4-323949a-reconciled-20261022\z2m-usb-once\`.
Keep original Zigbee and NV backups/keys outside Git and issue comments.

## Future 'seconds-fast' web flashing — independent qualification

A second versioned **GET-only** `p7u_slzb_ui_flash_audit.py` was executed
against the actual P7U's SLZB-OS. The onboard UI supports custom Zigbee
firmware staging (`/fileUpload?customName=/fw.bin`) followed by
`flashZBstartProgress` invoking `API_FLASH_ZB` with `local=1`.
The SHA256 of the served uncompressed JS is
`3414b5c9a1ff3abb62350bba47ed462b46cfe4e5be52fa362ed8e645f773bb23`.
The script also verified exact candidate APP-only HEX and 8192-byte
AC000 handoff hashes from GitHub run `39801711808`.

**Outcome: `HOLD_BACKEND_ERASE_SCOPE_UNPROVEN` (expected, safe).**
The JavaScript and public `smlight-tech/pysmlight` implementation prove
the **request**, not the ESP32's target-sector erase/write logic. SMLIGHT
SLZB-OS web API documents endpoints as **internal/undocumented**. There is
no independently verified guarantee that arbitrary uploaded APP-only
firmware plus separate AC000 handoff will be programmed at the right
addresses with **NV4 (0xA4000–0xABFFF)**, **CCFG (0xAE000–0xAFFFF)**
and current Zigbee security preserved. Disabling a UI "erase NVM" option
is **not evidence** of safe TI sector scope; this particular option appears
conditioned on EFR32 hardware in the actual JavaScript.

Do not promote ESP-local upload to production flashing based on speed alone.
Require firmware backend source/vendor-controlled address/erase contract and
nonproduction proof including sparse APP+AC000, vectors-last, exact sector
postwrite hashes, and unchanged NV4/CCFG, or stay with the already verified
ROM-BSL fallback. No HTTP POST, flash or mode toggle was performed.

References: https://github.com/smlight-tech/pysmlight/blob/main/pysmlight/web.py
and https://smlight.tech/support/manuals/books/slzb-os/page/slzb-os-api-endpoints
