# R2 essential diagnostics — existing G6 endpoint, actionable host tooling

**Software-only; no physical Zigbee/P7U qualification, flash or production deployment.**

## Finding: no new firmware endpoint is needed

The composed G6/G7 R2 P7U firmware **already implements and links** read-only
ZNP `SYS 0xF0` v1. Its handler calls `p7_g6_response`, which calls the G5
CRC-protected recorder `p7_diag_snapshot`. The original G5 header's disabled
endpoint flag refers to an older standalone G5 stage, *not* to the composed
R2 image. Adding a second handler would cause an actual collision.

The existing endpoint request is exactly:
- MT **SREQ SYS 0xF0**, two-byte body `01 00`
  (G6 protocol version 1, read-only operation 0).
- Entire MT request: **`FE 02 21 F0 01 00 D2`**.
- Response: standard **SRSP SYS 0xF0**, versioned **`P7G6`** envelope,
  wrapped around a CRC-checked **`P7D1`** snapshot containing the
  latest eight of 64 volatile RAM events, tick period, known NV state,
  event totals and recorder contention drops. **Reset cause is not actually
  collected in the current image** (`p7_diag_init(1, 0, 0)`) and boot
  generation repeats as 1; neither is presented as reboot evidence.
- G6 negative statuses are LENGTH, VERSION, OPERATION, BUSY and
  WRONG_COMMAND_TYPE. Missing data is not a healthy zero.

The pinned herdsman SDK contains no named SYS F0 method; send the raw ZNP
SREQ only through the **sole existing ZNP owner**, never a second serial
owner alongside running Zigbee2MQTT.

## Implemented for R2 operator use

- `firmware/slzb-06p7/ti832/g7/r2_diag_gate.py`: independently verifies
  the real G6 source endpoint and linked native TI CCS chain
  `MT_SysCommandProcessing -> p7_g6_response -> p7_diag_snapshot`.
  Verified against the actual R2 #82 CCS ELF disassembly/symbols.
- `r2_diag_report.py`: strict **offline** parser for raw `P7G6`
  response or full MT SRSP `FE...` bytes; checks both CRC and MT
  FCS, exact schema/version/length/status, timestamps and event types.
  Distinguishes measured UART/NPI/NV evidence from UNMEASURED
  AF/CCA/route/ZCL/queue-high-water/physical NV durability. No guessed
  cross-reboot timing.
- `r2_diag_capture.py`: **opt-in bench-only** USB/serial reader. Requires
  a named COM port or `/dev/serial/by-id`, independent prior expected
  coordinator IEEE, an explicit **isolated P7U** acknowledgement and
  confirmation that Zigbee2MQTT has been stopped. Reads and verifies
  `SYS_GET_EXTADDR` **before** issuing SYS F0. Fails on a different
  coordinator IEEE, malformed responses, timeout or existing output
  file. Valid unsolicited AREQ frames are skipped with CRC + strict cap;
  unexpected SRSP and corrupt traffic fail closed. Transient G6 BUSY
  retries at most twice. No deliberate radio reset or NV/CCFG/ESP/flash
  operation is issued. RTS/DTR are requested disabled *before opening*,
  but USB bridge line glitches/reset effects remain **unverified hardware
  risk**. It cannot independently prove board model: visually verify
  the one P7U first.
- `tests/p7-diagnostics-host/test_r2_diag_endpoint.py`: hostile
  protocol/identity/response validation, existing-G6 linked/source
  gate, pinned herdsman collision acceptance. Real native CI runs
  source and call-edge checks; R2 **firmware bytes unchanged**.

Offline:
```sh
python firmware/slzb-06p7/ti832/g7/r2_diag_report.py --print-request
python firmware/slzb-06p7/ti832/g7/r2_diag_report.py --response-hex FULL_MT_SRSP_HEX
```

Future, **only when the single P7U is independently identified, isolated,
stock recovery verified and Zigbee2MQTT isn't owning its serial port**:
```sh
python firmware/slzb-06p7/ti832/g7/r2_diag_capture.py \
  --device COM17 --expected-ieee YOUR_PREVIOUSLY_RECORDED_16_DIGIT_IEEE \
  --isolated-p7u --z2m-stopped --out PRIVATE_NEW_REPORT.json
```
The port and IEEE here are placeholders, not real discovered values.
The command is **not** to be run against the active production MR4U/P10.

## Limits and next hardware gate

This makes existing debug **retrievable and interpretable**, rather than
porting all P10 R11/R12 telemetry. The eight-event window can wrap quickly;
per-event lifetime counters, AF/CCA/source-route counters and queue high-water
aren't implemented in the current R2 firmware. The decoder labels them
unmeasured rather than displaying fake zeroes. If physical trial shows that
we need one of those measurements, instrument the specific proven failure
path in a **separate measured change** and re-verify the strict 23-sector
app/stock rollback plan together if firmware size increases.

Bench acceptance: confirm P7U model and exclusive serial bridge, ordinary
SYS PING / VERSION / Z2M operation, F0 response with both checksums valid,
normal non-destructive event change, and no regression under small network
traffic. No physical device has been contacted or flashed for this software.

## Optional Zigbee2MQTT in-service diagnostics (NOT DEPLOYED)

The live network **must** be queried through the ZNP connection already
owned by Zigbee2MQTT; opening a second direct socket corrupts request/response
ownership. The existing zigbee-herdsman command table cannot decode variable
length P7G6 raw SYS/F0 replies using a simple `BUFFER` field: it assumes a
preceding length field that G6 does not send.

To avoid that unsafe workaround, there are two opt-in, separately qualified
pieces:

1. `firmware/slzb-06p7/ti832/g7/r2_herdsman_inprocess_overlay.py`
   stages **three small pinned-herdsman** TypeScript changes in a *separate
   output directory*. They register read-only SYS F0, pass its raw SRSP
   payload without assuming a length field, and expose
   `ZStackAdapter.getP7UDiagnosticSnapshot()`. This calls the existing
   `znp.requestWithReply` **through herdsman's transaction queue**.
   It fails if the upstream checkout is not the exact pinned SHA
   `0968f979d558874b17396c96b66382d4236bbdcd` or if SYS F0 collides.
   The script never changes an installed Zigbee2MQTT package.
2. `firmware/slzb-06p7u/qualification/r2_z2m_existing_owner.mjs` is
   a Zigbee2MQTT external extension, **disabled by default**. It requires
   both `P7U_DIAG_BRIDGE_ENABLE=I_ACCEPT_PINNED_P7U_OWNER` and
   `P7U_DIAG_COORDINATOR_IEEE=<previously verified P7U IEEE>`, rejects
   other adapters and unknown owner method, then accepts exactly
   `{"action":"snapshot"}` at `<mqtt.base_topic>/bridge/request/p7u_diag_snapshot`.
   It publishes a bounded G6 diagnostic status and raw P7G6 hex via the
   **relative** `bridge/response/p7u_diag_snapshot` topic (Zigbee2MQTT's
   MQTT publisher prepends the configured base exactly once), yielding
   `<mqtt.base_topic>/bridge/response/p7u_diag_snapshot`, with a five-second
   request throttle, one in-flight query and bounded BUSY retry. It validates
   the G6 and P7D1 CRCs and makes **no** NV/flash/permit-join changes.

Both pieces have automated host-level regression tests. **Neither has been
installed or tested inside a real running Zigbee2MQTT/P7U process.** The
live implementation uses pinned herdsman internals and must be compiled and
smoke-tested against the exact intended Zigbee2MQTT installation in an
isolated pilot before opt-in. Extension loading is disabled by default on
new Zigbee2MQTT installations since v2.11; do not enable external JS on the
production MR4U merely to run these tests.

No secret network keys or payloads are returned by this endpoint. The
response remains a volatile eight-event snapshot, not a routing/AF lifetime
counter. Do not conflate software unit tests with field acceptance.

## Independent pre-flash review — 15 October 2026

- **Software at 516edb9:** nine of nine GitHub CI workflows passed, including native TI CCS three-profile acceptance. Software CI is not physical flash authorization.
- **New critical live-debug defect fixed in PR #83:** Zigbee2MQTT's `mqtt.publish()` adds `mqtt.base_topic`. The external extension previously provided a fully qualified topic and therefore duplicated the base. The request now matches the configured full topic, and the publisher receives only a relative topic. Host tests cover default and custom bases. Verified against actual Zigbee2MQTT MQTT and external-extension sources, not only mocks.
- **Real pinned herdsman compilation:** `Koenkk/zigbee-herdsman` at `0968f979d558874b17396c96b66382d4236bbdcd` (10.9.1) was checked out independently. The three staged TypeScript overlay source files passed `corepack pnpm install --frozen-lockfile --ignore-scripts` and `corepack pnpm run build` (`tsc`) in a separate review worktree. No installed Zigbee2MQTT package was modified.
- **Hardware access BLOCKED:** read-only Zephyrus pyserial enumeration showed **zero serial ports**. No attached P7U ROM BSL, installed CCFG, vendor app, UART bridge, radio identity or successful stock rollback has been physically established.
- **Initial NV5 BLOCKED:** the stock P7U's nonblank NV2 overlaps the R2 NV5 region. The strict writer correctly rejects nonblank NV5. A separately approved same-device NV5 preparation and restoration path backed by verified original bytes is not yet available. Never bypass blank-state checks or substitute a bank/chip erase.
- **Field test OPEN:** the same-process Zigbee2MQTT bridge remains disabled, not installed, and unqualified with the P7U. No network/HA/MR4U changes or any radio flash were performed.

**Pre-flash decision: STOP.** First establish and verify repeated ROM BSL entry and original-state recovery on the sole P7U, then separately review the identity-bound NV5 operation and exact R2/stock rollback pair. Keep issue #80 physical checkboxes unchecked.
