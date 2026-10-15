# Read-only coordinator health evidence

The composed G6/G7/F07 R2 firmware installs **SYS `0xF0`**. G5 alone does not:
`P7_DIAG_MT_ENDPOINT_ENABLED=0` describes the older standalone proposal, while
`P7_G6_MT_ENDPOINT_ENABLED=1` describes the actual G6 dispatcher. Pinned SDK and
Herdsman command collision checks, source dispatch and native linked evidence
must pass for each candidate. This endpoint remains a vendor extension; stock
Herdsman's named-command API has no definition for it.

Both operations are read-only, use existing MT SRSP transport, allocate no
diagnostic storage, and never erase/reset/seal, write NV, or export keys,
addresses, endpoints, transaction IDs or payloads. They do not bypass normal
single-owner MT serialization. Their presence is software evidence, not a
board, UART, RF, stack-load or migration acceptance result.

## Requests and compatibility

* `[1,0]` preserves the original version-1 G6 recent-event snapshot, at most
  144 payload bytes. Its wire layout and status codes are unchanged.
* `[2,0]` returns health counters, actual concentrator RAM settings and heap
  samples, exactly **118 payload bytes** on success, or an 18-byte error envelope.
* `[2,1]` prepends one uint8 payload length to that same health/error envelope:
  119 bytes on success or 19 on busy. The inner payload and CRC are identical.
  This makes the existing Herdsman owner's public `length` + `BUFFER` parser
  usable without changing a transport parser or opening another connection.
* Any other length, version, operation or command type is rejected. Both
  snapshots make one attempt to claim the existing recorder ownership guard;
  contention returns status 4, with no retry loop. ISR/task writers never wait.

Outer envelope offsets 0–15 retain `P7G6`, version, status, BIOS tick source,
unknown reboot identity and compiled tick-period fields documented in
[README.md](README.md). Version 2 identifies the following body at offset 16;
the last two bytes are CRC16-CCITT over the complete preceding envelope.

| Body offset | Bytes | Meaning |
| --- | ---: | --- |
| 0 | 1 | Counter count = 16 |
| 1 | 1 | First fault present: 0 or 1 |
| 2 | 2 | Reserved, zero |
| 4 | 64 | Sixteen little-endian uint32 counters, order below |
| 68 | 2 | First fault kind, or zero |
| 70 | 2 | First fault numeric argument, or zero |
| 72 | 4 | First fault tick; zero means unavailable for the NV-driver observer |
| 76 | 4 | Sampled BIOS tick, modulo 2^32 |
| 80 | 4 | Recorder writer-contention drops |
| 84 | 4 | Actual RAM enable, route-cache, discovery seconds, radius bytes |
| 88 | 4 | Actual OSAL heap total capacity, uint32 |
| 92 | 4 | Current OSAL total free bytes, uint32 |
| 96 | 4 | OSAL already-free error count, uint32 |

Counter order: `af_success`, `af_no_route`, `af_cca_failure`, `af_no_ack`,
`af_other_failure`, `uart_rejected`, `queue_rejected`, `rx_overflow`,
`parse_error`, `fcs_error`, `nv_ambiguous`, `nv_failure`, `queue_accepted`,
`uart_tx_idle`, `af_confirm_total`, `zdo_dispatch`.

The actual `MT_AfDataConfirm` hook counts only its reported ZStatus. Pinned
`zcomdef.h` defines success `0`, `ZNwkNoRoute=0xCD`,
`ZMacChannelAccessFailure=0xE1`, and `ZMacNoACK=0xE9`. All other failures stay
in `af_other_failure`; they are never relabelled as CCA. The original AF AREQ
payload and completion handling remain unchanged. AF confirmation does not
prove receipt by the destination application or identify the root cause.

The NV observer runs when the real NVOCMP fatal status is assigned. It records
only the numeric **status and stable failure-site ID** using the existing
recorder, with no clock dependency before BIOS. The argument's low byte is the
NVINTF status; its high byte is the site ID. The matching candidate's
`NV-HARDENING-SOURCE.json` maps all 16 IDs to the operation, function/macro and
source status expression; no NV identifier, key or payload is recorded.
`nv_failure` counts observed fatal assignments, not unique failed transactions.
The first `NV_FAILURE`/`FAULT` kind and argument remain latched
after the recent-event window rolls away. Untimed NV events have tick zero;
the decoder exempts them from clock regression checks, without treating them
as a boot boundary. `nv_ambiguous` records startup decision evidence separately.

Counters saturate and reset on ordinary recorder boot initialization; neither
previous-boot persistence nor a unique reboot identity is claimed. Writer
contention can lose events/counter updates, and that loss is exported. Queue
acceptance and UART idle are cumulative progress observations, not current queue
depth, queue high-water or frame-specific physical transmission proof.

Concentrator bytes are sampled together from `zgConcentratorEnable`,
`zgConcentratorRC`, `zgConcentratorDiscoveryTime` and `zgConcentratorRadius`
under the existing OSAL critical section. They describe RAM at the sample,
including any values loaded from NV, rather than compiled defaults. Compare
them to separately captured persisted values with
[`p7u_runtime_settings.py`](../../../../deploy/p7u_runtime_settings.py).
This does not prove that many-to-one advertisements or source-route traffic
work over RF. The same short critical section samples the linked OSAL driver's
uint32 `HEAPMGR_SIZE`, `heapmgrMemFreeTotal` and `heapmgrMemFreeError` globals.
Free totals include allocator accounting rather than a guaranteed contiguous
allocation size. `MemFreeError` counts detection of an already-free block;
it is **not an allocation-failure count**. No heap scan, coalescing operation,
profiling define or extra interrupt-disabled loop is added. The host reports
the minimum observed free sample as sampled data, not the true low-water mark;
largest free block, fragmentation and missed transient pressure remain unknown.

## Host integration and bounded recovery

[`deploy/p7u_health.py`](../../../../deploy/p7u_health.py) defaults to
offline saved-frame decoding and assessment. `DiagnosticClient` accepts an
async exchange callback from the **existing** ZNP/MT connection owner; it opens
no port/socket and offers no reset, reconnect, NV or flash command. An owner
adapter must support raw vendor SREQs or add a reviewed command definition.
This module is not automatically installed into Zigbee2MQTT or Herdsman.

```python
from deploy.p7u_health import DiagnosticClient

# owner_exchange serializes all MT traffic and returns exactly the matched
# complete SYS/F0 SRSP. It must honor cancellation/deadlines and invalidate
# late responses on timeout. Do not open a second serial/TCP connection.
client = DiagnosticClient(owner_exchange, session="opaque-owner-generation")
observation = await client.probe(version=2, timeout_seconds=2)
```

One probe is allowed at a time, its configured deadline is at most ten seconds,
and there are zero automatic retries. A timeout, cancellation, owner failure or
unmatched/malformed reply invalidates that client generation. SYS/F0 has no
transaction nonce: the owner must drain/invalidate its old response matcher and
establish a new session boundary before another client can be used. A successful
reply proves the MT round trip only.

```text
python deploy/p7u_health.py decode <complete-saved-MT-frame-hex>
python deploy/p7u_health.py assess saved-observations.json
```

The assessment accepts at most 256 observations and never acts on the device.
Counter deltas require an explicit independent same-boot assertion, one host
session, no observed counter reset, and unsaturated counters. A session token
alone is not firmware boot evidence. Missing/unsupported diagnostics and a lone
RTT remain unknown, rather than proving a crash or a healthy mesh.

Silent-hang qualification must add ordinary application traffic through the
existing host owner. Record attempted/successful/timed-out operations, verified
awake representative routers, observation window and host connection state.
Three timed-out operations to at least two known awake routers over at least
30 seconds while the host remains connected produce **possible network stall**,
even if diagnostics still answer. This is an investigation threshold, not a
root-cause claim; sleeping devices or unverified routers do not satisfy it.

On suspected failure, pause the soak, preserve counters and private owner logs,
and inspect host transport and representative devices. The suggested recovery
budget is at most one owner-managed reconnect after evidence capture, then stop
if it fails. Automatic radio resets/retry loops have budget zero. A radio reset
or stock rollback is an operator decision using the separately proven recovery
procedure for the single P7U. NV fault evidence stops the trial immediately;
do not clear NV or re-form the network to make the warning disappear.

## Evidence and remaining acceptance

`tests/p7-g6-host/test_g6.py` compiles the actual pinned AF confirm/MT dispatcher
and composed recorder with ASan/UBSan: legacy/error/busy replies, all named AF
status buckets, unchanged AF payload, altered RAM settings, first NV failure
after 200 events, and boot initialization are checked. The Python decoder
cross-checks that compiled response. `test_health.py` checks whole-frame
matching/FCS/CRC, owner timeout/cancellation and late-response quarantine,
counter domains, wrap/reset/session boundaries, saturation and silent-hang
false positives. The complete NV2/NV5 driver tests also assert numeric observer
evidence while preserving all mutation/failure checks.

Native CCS evidence must still establish linked hooks, exact ELF/HEX, CCFG/NV
protection and resource use. Physical soak must then verify diagnostics during
AF bursts, route/CCA failures, host disconnects and actual network stalls;
firmware queue depth, radio queues, true allocator high-water/fragmentation, route
occupancy, RF root cause and retained previous-boot evidence are not supplied by
these counters. Track those explicit limits in the authoritative
[36-feature ledger](../phase0/feature-parity.json) and
[R2 acceptance matrix](../phase0/R2_ACCEPTANCE_MATRIX.md).
