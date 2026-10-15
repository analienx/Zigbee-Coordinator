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
  reset source if available, event totals and recorder contention drops.
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
  file. No radio reset or NV/CCFG/ESP/flash operation. It cannot
  independently prove board model: visually verify the one P7U first.
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
