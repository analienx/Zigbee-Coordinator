# P7U R4 v4.3 — live hard-hang forensic RCA, 28 October 2026

**Status:** High-confidence *failure domain*; exact defective source instruction not yet proven. This is a **read-only, source-linked investigation**, not a change to the installed coordinator. The operator reported the subsequent hard hang after the last directly inspected passive observations. Access to run further live capture on the authorized Windows/HA path was rejected by execution safety checks; **do not claim** a fresh post-hang raw archive, physical FIFO trace, or a current zero-SRSP plateau from this session.

**Physical source identifiers:** CC2652P7 SMLIGHT SLZB-06P7U; installed R4 image source `899f179031aae74db2e48699900f1cf5722bb4de`, host `acaa002519fe801429e981de2e815ec5af6f1d36`, F2 protocol ABI4 minor3. Transport: existing Zigbee2MQTT/ZNP single-owner USB path. Earlier accepted B1 UART-busy self-post correction, AF handoff error fixes, conditional TX-error cleanup, and F2 v4.3 telemetry are **already present**. A return to these same fixes cannot explain recurrence.

## Capture chronology and invariant boundaries (UTC)

| UTC 28 Oct | Native / host evidence | Implication |
|---|---|---|
| 13:40:50 | Native VALID F2: asyncDepth=0, async HWM=119, all response stages through TL balanced, AF SRSP timeout count=44, host pending=1 | Usual baseline |
| 13:58:29 | Native VALID F2: asyncDepth=0, HWM=125; all AF/MT response stages balanced; F2 latency 2299ms, AF timeout count=56; host pending=1 | Errors present before measurable sustained queue pressure |
| 14:00–14:10 | Host pending reaches ~49 then 208; AF timeouts accelerate; native F2 admission increasingly SKIPPED | Host backpressure starts; cannot infer cause from SKIPPED |
| 14:20:10 | Native F2 FAILED, `F2_REPLY_TIMEOUT`, `SENT_OR_UNCERTAIN`; host pending=356 and AF timeout count=136 | Host/native F2 response unavailable within 20s; no proof radio received this request |
| **14:28:23** | **VALID F2 minor3**: `asyncDepth=69`, `asyncHighWater=428`; `allProduced=allEnqueued=allNpiReceived=allFramedQueued=28275`, `allTlSubmitted=28270`, `allTlRejected=0`; AF analogous `27304 → 27299`; host pending=467 and active Waitress=14; AF OK=27141, timeout=178; native F2 latency=12227ms | **Radio's own asynchronous response path is under pressure simultaneously with host serial-request queue. Five reply frames are pending between NPI framing and TL submission.** |
| 14:35:42 | Passive SKIPPED with host queue **658**, AF matched SRSP OK=27271, timeout=**234**. Host USB raw receive and UNPI parsing had continued in prior windows with no new parse errors | Progressive, not just a container crash; final full outage time still requires post-hang raw log |
| After last directly inspected window | Operator confirms hard hang | Post-hang request/response boundary **not directly sampled in this session** |

Local Prague time on 28 Oct is UTC+1 (CET). The 14:28:23Z snapshot is 15:28:23 Prague.

The late F2 snapshot has `uartProgress.npiRequests=28145`, `mtEntered=mtReturned=28141`, difference **4 consistent with the baseline**. `uartWriteAccepted=uartCallbackOk=163186`, `uartWriteRejected=uartCallbackError=uartLengthMismatch=0`, `firstFaultKind=0`, `b1FirstFailure=0`. These are **RAM instrumentation counters**, not proof of wire-completed transmission after the snapshot.

### New source-verified `stateFlags` decode — **high-value discriminator**

Physically observed `uartProgress.stateFlags=604045312 = 0x24010000`. In exact deployed `tools/r4_f2_v43_progress.py`, the low status bits are:

- bit0 `npiTxActive`: **0** (not transmitting according to native TL state at snapshot).
- bit1 `b1_management_transport_unavailable()`: **0** (no B1 physical UART HOLD).
- bit2 `B4_V43_MtActive`: **0** (no MT handler currently active).
- bit3 `B4_V43_Progress[10]`: **0** (no frozen first-fault record).
- bits16+ contain `B4_V43_LastCommand=0x2401` (last seen AF command; do not interpret this as a hardware error code).

**Native asyncDepth=69, transmit-active=false and HOLD=false together point to work waiting for NPI scheduler/queue draining despite an idle TL state.** This is highly suggestive of an **insufficient or missed TX-ready wake, work scheduling fairness, or a stalled transmission-to-next-frame handoff**. It is *not* by itself proof of a permanently missing wakeup: the snapshot may be an inter-frame idle interval.

`npiWakes` was **645015 at 13:58:29Z** and **720884 at 14:28:23Z** (+75869): wake events **continued throughout the degraded interval**. Thus an unqualified claim of a *globally dead* NPI semaphore/task is contradicted. The correct issue is **failure of the queue to sustain sufficient drain rate / bounded latency under load** or a temporary race, not proven no wakeups ever.

The same native interval advanced `uartCallbackOk` from 147894 to 163186 (+15292), consistent with *continued logical UART callback progress*. Actual UART FIFO TX_FINISHED events and physical ESP UART forwarding would discriminate further; a callback may mean accepted buffered write rather than completely shifted bytes.

### Relation to earlier 26–27 Oct incident

Earlier sealed 1177-record archive (see `host/r4-b4/P7U_SRSP_ROOT_CAUSE_BOUNDARY_20261027.md` and issue #144) showed native async high-water **83→90→148→312** while AF timeouts rose, followed by host AF→ZDO/UTIL SRSP success cessation. Native F2 became unavailable **13+ hours before** last AF SRSP success; therefore F2 blackout alone did not mean radio hung. This new incident adds a native **nonzero asyncDepth=69** captured while pressure peaks, an important advance over earlier only historical HWM measurements.

Prior hardware recovery succeeded by entry/exit from TI ROM/BSL without changing APP/NV, whereas ordinary reset and ESP reboot alone had failed in that incident. Persistent flash-image corruption alone is an inferior explanation, but the exact reset/bridge/pin differential is still open.

### Causal hypothesis ranking

1. **NPI async TX work-drain scheduling / wakeup / starvation / response-service fairness** (leading). Real queue depth and high-water growth, F2 >12s, TL/MT 5 pending, idle `npiTxActive`/no HOLD. Audit `npi_task.c::NPITask_process`, `NPITask_ProcessTXQ`, `NPITask_transportTxDoneCallBack`, `NPITASK_TX_READY_EVENT`, `TX_DONE_ISR_EVENT_FLAG`, `npi_tl.c::NPITL_writeTL` and callback/critical-section ordering for a lost transition from idle to queued and for burst drain starvation. Prior busy-spin fix removes unconditional self-post while UART busy and relies on callback wake; exact interleavings (producer enqueues while TX callback/event is being consumed, multiple pending frames, event flags cleared, UART TL idle) deserve adversarial testing. A busy-period self-post loop **was already fixed**, so do not simply reapply it.
2. **UART2 FIFO drain / transport capacity / ESP32-S3 bridge forward-progress** (important competing explanation). No UART2 rejection/error recorded and callback counters balance, but accepted writes and callbacks do **not** prove physical FIFO drained; verify native `uartTxFinishedEvents` from retained full F2 dump and independently ESP UART RX→USB CDC forwarding, with zero secondary serial owners. TI documents finite NPI serial throughput/overflow risk. The B1 startup event coalescence was previously fixed, but steady-state drain under burst is a separate boundary.
3. **Host ZNP 6-second AF-SRSP lock and backlog feedback** (strong amplifier, possibly initiating one of the pressure spikes). Zigbee-herdsman `znp.requestWithReply` serializes requests under `AsyncMutex`, creates Waitress SRSP matcher keyed by subsystem/command and waits 6s. Adapter work queue is separate. When AF responses are delayed, subsequent requests and retries accumulate; `adapterQueuePending` rose from 1 to 658. Normal AF SRSP has **no request nonce/transaction ID** (unlike F2), so a late matching reply must not be interpreted as proof the intended request succeeded. The first radio anomaly may precede this cascade, or host load may be a trigger; no definite ordering established at sub-second resolution.
4. **High Zigbee traffic / route discovery / device-request storms** (load trigger/amplifier). Early `NWK_NO_ROUTE`, pings and ZCL timeouts existed; many `genOta.queryNextImageResponse({status:152})` failures appeared **after** previous SRSP errors and sharp host queue rise. Z2M `disable_automatic_update_check: true`, so an automated firmware download was not demonstrated. Do not call OTA the root cause based on a generic `OWNER_OR_OTA_BUSY` F2 skip label (the deployed source emits it for several admission vetoes).
5. **MT allocation failure, NPI write rejection, sticky transport HOLD, host UNPI frame corruption** (currently lower priority). Latest valid native all allocation/send/framing/reject counters were 0, B1 HOLD=0, MT entry/return balanced, native write callback errors=0; host USB RX/UNPI parsed continued without new parse errors. These findings exclude *sustained observed faults at those stages*, not events emerging after the last valid sample.
6. **Permanent invalid NV/security/flash, global CPU or process OOM** (not supported by observed evidence). The host was running, ~217MiB RSS and modest CPU during earlier pressure; native handler and host callbacks made progress. Security/flash remained untouched. A later hard freeze can still have a different mechanism, so hardware and OS are not categorically excluded.

### Key instrument-specific limitations

- F2 v4.3 mask `0x00FFFFEC` has **SRSP depth/HWM/enqueued fields NULL** (NPI_SREQRSP disabled); do not invent zero values. `asyncDepth/HWM` are valid.
- `allTlSubmitted` is an NPITL write *submission return*, not proof of physical completion.
- The 5-frame gap at one point is **in-flight count**, not five proven lost responses. Recheck persistence or delta across two VALID frames if available.
- `Waitress rawMapEntries` includes expired tombstones; use `waitressAccounting.active` (14 at 14:28, peak 28), not raw Map.size.
- A time window with rising UNPI frames may be composed entirely of unrelated AREQs; it does not prove AF matched SRSP.
- F2 admission SKIPPED records carry host evidence, **not a fresh radio snapshot**.
- Collection itself should not be forced into a blocked owner; native F2 is optional, nonce-bound and guarded, with a possible 20-second timeout during severe congestion. It might amplify overload once admitted but **cannot explain earlier failures beginning before that request**.

### Specific code-fix direction and minimal acceptance

**Source-first, not speculative flash:** inspect TI SDK 8.33 exact-source `npi_task.c`, `npi_tl.c`, `npi_tl_uart.c` and already-applied B1/AF/F2 overlays at radio source `899f179`. First choose whether queue drains are blocked by:

A. TX is idle, queue nonempty, but TX_READY event/semaphore absent (lost transition).
B. TX callback events occur but queued replies are delayed/starved by higher-priority work or AREQ flood.
C. TX callback succeeds but FIFO-drain/ESP bridge cannot forward bytes.
D. TX not completed because B1 or UART error path, only after final F2 sampled.

A targeted candidate should provide a **bounded, idempotent queue-kick on idle+nonempty transition** with robust callback/producer interleavings and no UART spin, or a **bounded response-service budget/fairness** ensuring SRSP progress under AREQ load. Do not enable `NPI_SREQRSP` casually: different transport semantics require end-to-end analysis. Do not extend host timeout or increase queue size as a purported root fix. No drop/reorder that violates ZNP request/SRSP correspondence.

**GH-runner native C acceptance fixtures** should extract the *actual fused TI function bodies*, not replacement algorithms, and adversarially test:
1. callback finishes before/after TX_READY event clearing, producer queues one/multiple SRSPs in each interleaving;
2. queue nonempty + TX inactive + no B1 HOLD always eventually submits a frame;
3. continuous AREQ flood cannot starve synchronous AF/ZDO response beyond a bounded deadline;
4. one physical FIFO-drain callback covering multiple writes and one accepted-write callback that does **not** imply FIFO drain;
5. short/error callbacks retain sticky B1 safety HOLD, do not fabricate SRSP success;
6. mixed AF_DATA_REQUEST, ZDO, UTIL and SYS F2 servicing with one hardware UART owner, consistent OSAL critical sections, correct free/ownership, no duplicate or delayed SRSP matched to wrong host waiter;
7. negative C mutants that intentionally drop TX-ready kick or invert callback state, detected by tests.

Then run exact-head ARM native build, full regression/security/NV/CCFG/flash geometry gates using **GitHub runners**. Physical validation requires exact-source provenance, a *single-owner* cutover and safety approval. Do not reset, reflash, replay backups or re-pair to perform analysis.

### High-value remaining post-hang evidence, if already retained (no extra UART access)

1. Last two completed `/config/zigbee2mqtt/p7u-b4-diagnostics/30min-dumps/f2_*.json` with SHA sidecars and pointer; do not lose them to 24h retention.
2. Last 60–120 mins of **passive** host `SKIPPED` records, separated by owner generation; determine first timestamp when `AF.ok` stopped while `AF.timeout` rose, and whether `wire.rxRawBytes`/`wire.unpiParsedFrames` continued.
3. Last native F2 full `uartTxFinishedEvents` and TX write/callback and `stateFlags`; compare physical FIFO event count against a previous snapshot and the last host RX progress.
4. Whether `SYS` was actually *requested* during the hang; a flat SYS.ok counter with zero SYS requests is not a SYS failure proof.
5. ESP RX/TX/bridge counters only through **existing passive telemetry**, if supported by installed vendor firmware. Do not open or reconfigure the radio serial path.

TI reference: [SimpleLink SDK NPI limitations](https://dev.ti.com/tirex/explore/content/simplelink_cc13xx_cc26xx_sdk_8_32_00_07/docs/ble5stack/ble_user_guide/html/ble-stack-common/npi-index.html): finite serial throughput can induce data/stack overflow if input traffic exceeds service. This is an architectural risk warning, *not proof* of the failure here.

**Bottom line:** The new native sample narrows the best next source review to **NPI async TX queue fairness / wake transitions with TL idle and queue nonempty**, while preserving **physical UART FIFO/bridge** as a first-class alternative. The actual first missing ZNP response and whether a specific UART notification was lost remain unproven.