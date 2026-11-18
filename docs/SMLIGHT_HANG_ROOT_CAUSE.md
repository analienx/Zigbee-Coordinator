# SLZB-06P7U coordinator hangs: root cause and fixes (for the SMLIGHT firmware team)

This note is written for SMLIGHT's firmware engineers. It explains why our SLZB-06P7U stopped answering Zigbee2MQTT on a dense network, what we measured over five weeks of investigation (16 Oct – 18 Nov 2026), and the changes that fixed it, so they can be checked against SMLIGHT's own builds. Everything below is reproducible from this repository. We are happy to share the composed patch or answer questions.

SMLIGHT's own [known-issues page](https://smlight.tech/support/manuals/books/slzb-os/page/all-os-versions) says CC2652P, CC2652P7 and CC2674P10 coordinators "may hang" under high load because of a long-standing TI SDK bug, typically seen as `SRSP - SYS - ping after 6000ms`. We believe section 1 is that bug.

## Summary

**Root cause:** TI Z-Stack reads the active network key from flash (NV) on **every secured frame**, and each read is a linear search taking about 10 ms on a large NV. On a dense mesh this keeps the Stack task permanently busy. TI's task priorities and service scheduler then turn a busy CPU into a dead host link, in three distinct ways (section 2). A RAM read cache in front of NV removed the cause; there has been no runtime hang since.

| # | Failure seen by the host | Cause | Fix | Status |
|---|---|---|---|---|
| 1 | AF/ZDO/SYS SRSP timeouts after 15–35 min, then total silence | **NV read storm**: per-frame NV read of the active NWK key | 8-line RAM read cache in front of `osal_nv_read` (V53/V54) | **Fixed.** No runtime stall since 31 Oct 2026 |
| 2a | Same, at runtime: replies produced but sent 22–55 s late | Busy Stack (priority 5) starves NPI/MT (priority 4) | Raise NPI while an SRSP is pending (V46), and permanently after retained start (V50) | Mitigation; kept |
| 2b | After a radio reset: `SRSP - AF - register` / `SYS ping` timeouts, coordinator never finishes startup | Busy NWK service starves ZDApp INIT in TI's fixed-order scheduler; NPI starved at boot | ZDApp INIT/START selected first during retained start (V48); service aging (V50); NPI boost at startup (V47) | Mitigation; kept |
| 2c | Heap slowly lost under load (source analysis) | Expired OSAL timers freed only by the last, most-starved Stack service | Free expired timers after every dispatch; O(1) enqueue (V52) | Fixed; shown not to be the main driver |
| 3 | Cold start: `SYS ping` fails on several Zigbee2MQTT starts, 9–11 min to come up | MT frame parser: no inter-byte timeout, no length bound; a stray `0xFE` at power-on swallows host frames | 500 ms idle resync, length bound 250 (V57) | **Fixed.** 5 / 5 first-attempt cold starts since, versus 4 failures in 11 mornings |
| 4 | `0xC7 NWK_TABLE_FULL` on `ZDO extRouteDisc` | Route-discovery table `MAX_RREQ_ENTRIES` 8 | 40 entries (V58) | **Fixed.** 0 refusals in 65 discoveries, versus 6 in 37.5 h |
| 5 | Occasional MT frame dropped | UART RX overrun at 115200 baud, no flow control, 32-byte buffers | Counted (V58) | Open, about 1 per 9 h, recovered by fix 3 |

Section 4 lists further TI source defects we found and fixed along the way. They are real, but none was the cause of our hangs.

## Test system

- **Hardware:** SLZB-06P7U R1.73, TI CC2652P7, USB CDC through the ESP32-S3 (`303a:4002`) to Home Assistant; Ethernet for management only.
- **Firmware base:** TI SimpleLink low-power F2 SDK `lpf2-8.33.00.16` (`simplelink-lowpower-f2-sdk` `3615ad5d`), Z-Stack ZNP, coordinator. NPI UART 115200 baud, no RTS/CTS.
- **Host:** Zigbee2MQTT 2.14 (zigbee-herdsman 10.10) as the only serial owner.
- **Network:** 106–109 devices, 57 routers, channel 11. NV: 893 active records (address manager 406 rows, about one TC link-key entry per device).
- **Stock reproduces it:** SMLIGHT stock `20260310` on this network, 16 Oct 2026: first AF SRSP timeout 35 min after boot, then 64 AF and 6 ZDO SRSP timeouts and 69 downstream timeouts until the service was stopped. Our first R4 build (22 Oct, without the fixes below) failed the same way 15 min after boot ([forensics](../firmware/slzb-06p7u/r4/release/R4_FIRST_LIVE_Z2M_FAILURE_FORENSICS_2026-10-22.md)). Zigbee2MQTT [#32837](https://github.com/Koenkk/zigbee2mqtt/issues/32837) reports the same AF-wide SRSP timeouts on another CC2652P7 network of about 96 routers.

## 1. Root cause: the NV read storm

### Mechanism

1. Every NWK-secured frame needs the active network key. TI's closed NWK library (`libZStack_nwk_all.a`) gets it through `ZDSecMgrReadKeyFromNv(ZCD_NV_EX_LEGACY, ZCD_NV_NWK_ACTIVE_KEY_INFO, …)`.
2. `ZDSecMgrReadKeyFromNv` (`source/ti/zstack/stack/zdo/zd_sec_mgr.c`) keeps no RAM copy. It calls `osal_nv_read(ZCD_NV_NWK_ACTIVE_KEY_INFO, offsetof(nwkKeyDesc, key), SEC_KEY_LEN, …)`.
3. `osal_nv_read` → `NVOCMP_readItemApi` searches the NV page linearly. With 893 active records one read took **about 10–12 ms** on this board.
4. The read runs inside the NWK service (Stack service index 2, input `0x2070`: `RTG_TIMER_EVENT | NWK_DATABUF_SEND | NWK_BCAST_TIMER_EVT | NWK_BROADCAST_MSG_EVT`). On a busy mesh that service is ready again before it finishes, so the Stack task never idles.

The cost grows with both traffic and NV size, which is why it shows up on large networks and gets worse as a network grows.

### The measurement that found it (V52 evidence pages, 30 Oct 2026)

During a live stall, our RAM-only scheduler and NV pages showed:
- the NWK service busy **310 s of a 6.5-minute window, 304 s of it inside NV reads**;
- about **30,000 NV reads, one per received frame**, each a linear search of item 0x3A;
- every MAC data request succeeding and OSAL timers not spinning, so the load was not retries or timers.

### Fix (V53, guarded in V54)

An exact-match read cache in the NV driver path (`tools/r4_v50_stack_service.py`, blocks `B4_V53_*` and `B4_V54_CACHE_HOLD_AND_SECRET_GUARD`):
- 8 lines × up to 32 bytes, keyed by system ID, item ID, sub ID, offset and length.
- **Invalidated on every NV create, update, write, delete, compaction, `doNext` and erase**, before and after the driver call. A generation counter stops a read that races a mutation from being cached.
- Never caches the TCLK seed; NULL or zero-length reads bypass it; our fail-closed NV mode bypasses and wipes it.
- No API change: callers still call `osal_nv_read`.

| | Before (V52, during a stall) | After (V53 onwards) |
|---|---|---|
| NWK time in NV reads | 304 s in 6.5 min | 0.9 s in 10 min |
| Stack task busy | saturated | 1–3.5 %, 0 saturated 10 s windows |
| NV read cache hits | n/a | 99.5–99.9 % (18 Nov: 698,323 hits / 3,558 misses in 9 h) |
| SRSP timeouts | repeated | none at runtime since 31 Oct; none at all since 13 Nov |

On 18 Nov the remaining uncached 0x3A reads still averaged 12.4 ms each, so the cache saved about 2.4 hours of CPU in 9 hours of uptime.

**Simpler alternative for SMLIGHT:** keep the active and alternate NWK keys in RAM inside `ZDSecMgrReadKeyFromNv`, refreshed wherever `zd_sec_mgr.c` writes `ZCD_NV_NWK_ACTIVE_KEY_INFO`. That is the only per-frame item we observed. A generic cache, as above, also covers less frequent hot items.

**Reproduce:** about 100 devices with many routers, or several hundred NV records. Count `osal_nv_read` calls for item 0x3A per second, or time the Stack task. On ours the rate tracks received frames, about 20 per second normally and far more during bursts.

## 2. How a busy Stack becomes a dead host link

TI's ZNP runs the Stack task at priority 5 and the NPI task, the only owner of the MT/UART host link, at priority 4. The Stack task picks its services in fixed index order, first ready first. With the NWK service never idle, three things go wrong. Each was captured on hardware before the root cause was found, and each has its own mitigation, which we kept.

### 2a. Replies wait behind the Stack (runtime)

- **Evidence (V5 image, 29 Oct):** SRSPs already framed and queued waited **22–35 s** to be sent, and the gap from "ready to send" to "sent" reached **54.7 s**, well past herdsman's 6 s deadline. No UART error, no fail-closed latch. 9,588 bytes of unsolicited AREQs were queued behind them.
- **Escalation (28 Oct):** host timeouts make herdsman queue more work. The host adapter queue peaked at 1,218 jobs and the radio's async queue reached its 500-frame high-water mark. Then the radio stopped sending any bytes at all (host USB RX frozen at 4,746,076 bytes while AF timeouts kept rising), and only a reset recovered it.
- **Mitigation:** temporarily raise the NPI task to priority 6 while a framed SRSP is pending (V46), and keep NPI at 6 for the rest of the boot once the retained network has started (V50). This needs SysConfig `Task.numPriorities` raised from 6 to 8.

### 2b. Startup never finishes after a reset

This is why a plain radio reset often did not recover a hung coordinator: the restarted stack hit the same saturation during its own startup.

- **Evidence (V6, V47, V48, 29–30 Oct):** after a reset onto the existing network, herdsman got `SRSP - AF - register after 6000ms`, or no bytes at all for `SYS ping`. Our startup page showed ZDApp's `ZDO_NETWORK_INIT` posted but never dispatched (`INIT_POST=1`, `INIT_DISPATCH=0`). The Stack was inside an NWK dispatch on every sample, about 57 NWK dispatches per 0.76 s poll with input `0x2070`.
- **Cause:** `stackTaskFxn` in `source/ti/zstack/startup/zstackstartup.c` rescans the service events from index 0 on every wake. A continuously ready NWK (index 2) is always chosen before ZDApp's later INIT event. Separately, the NPI task at priority 4 cannot run to read the host's startup commands.
- **Mitigation:** select ZDApp's pending INIT/START first during the retained start (V48); serve any ready service that has been passed over 4 times in a row (V50); boost NPI to 6 from the retained-start event (V47, made permanent in V50).

### 2c. Expired timers are freed by the most-starved service

- **Source analysis (V52):** in `osal_port_timers.c`, each expired one-shot OSAL timer leaves a `TimerEntry_t` and a dynamic `Clock` object that only `ZStackTaskProcessEvent` frees. That is the last of the 10 Stack services, so it is the first to starve. `timerCb` also appended each expiry with an O(n) walk in Clock Swi context. Under starvation this would turn into heap loss and growing Swi time.
- **Fix (V52):** free expired timers after every Stack dispatch; prepend in O(1).
- **Result:** V52's timer page showed timers were not spinning during the next stall, which pointed the investigation to NV. Worth fixing; not the main driver.

## 3. Separate failure classes

### Cold start: the MT parser swallows the host's first frames (V57)

`NPIFrame_collectFrameData` (`npi_frame_mt.c`) waits **indefinitely** for length + 3 bytes after any `0xFE`, and it accepts lengths 251–255 although `MT_RPC_DATA_MAX` is 250. One stray `0xFE` plus a length byte around power-on swallows the next host frames. Each Zigbee2MQTT start sends 26 bytes, so several restarts pass before the parser is back in sync.

- On 4 of 11 mornings after the nightly power cut, Zigbee2MQTT needed four starts and 9.5–11 minutes. The radio had not reset and reported no internal fault.
- Replaying one `0xFE` plus a length of 82–86 into TI's unmodified parser reproduces the exact pattern of answered and unanswered pings.
- We never captured the stray bytes, so their source is unknown; ESP32-S3 / USB activity at power-on is a candidate.
- **Fix:** if a chunk arrives into an incomplete frame more than 500 ms after the previous byte, drop the partial frame and hunt for `0xFE` again; treat a length above 250 as not a length. A failed frame's bytes are not rescanned, so a command the host has already timed out on never runs late.
- **Result:** five nightly cold starts in a row (14–18 Nov) connected on the first attempt.

### Route discovery refused: `NWK_TABLE_FULL` (V58)

Herdsman sends `ZDO extRouteDisc` only after a unicast has failed, as its recovery step. With `MAX_RREQ_ENTRIES` at 8 the coordinator refused it with `0xC7` (6 of 6 `NWK_TABLE_FULL` errors in 37.5 h, 5 of them on two bulbs during automation bursts). Building with `MAX_RREQ_ENTRIES=40` costs 320 B of RAM: 65 of 65 discoveries succeeded since. We left `MAX_BCAST` at TI's default.

### UART RX overruns (open)

115200 baud, no flow control, a 32-byte DMA read buffer (`UART_ISR_BUF_SIZE`) and a 32-byte UART2 ring buffer. TI's UART2 driver counts overruns only when `UART2_EVENT_OVERRUN` is in the event mask, and the ZNP mask holds only `TX_FINISHED`, so stock builds cannot see them. With the event enabled we counted one overrun in 9 hours, recovered within seconds by the parser resync. Hardware flow control, if the board routes RTS/CTS, or larger RX buffers would remove it.

## 4. Other TI source defects found along the way (fixed, not the cause)

Each was found by reading the pinned TI 8.33 source and was fixed with a compile-and-mutate test. Each fixed build still hung until V53 removed the NV storm, so none of these was the cause. They are worth checking in SMLIGHT's builds because each can strand the host link on its own.

| Where | Defect | Fix |
|---|---|---|
| `npi_tl.c` `NPITL_writeTL` | `npiTxActive` is set before `transportWrite`. An immediate UART write rejection returns 0 with no completion callback, so `NPITL_checkNpiBusy` stays true forever. | Clear the busy state when no bytes were accepted; unwind on callback error (V43) |
| `npi_task.c` TX path | A pending TX self-posts the NPI event while the UART is busy, spinning the NPI task | Pend instead of self-posting while busy (PR #154) |
| NPI → MT handoff | Failed allocation or dispatch leaked the message, or reported success on failure | Free only untransferred objects; return failure (PR #154) |
| MT SRSP producer (`MT_BuildAndSendZToolResponse`, `NPIFrame_frameMsg`, queue record) | Three heap allocations per reply; under heap exhaustion an SRSP silently disappears | Three statically reserved complete-frame slots for SRSPs (V45) |
| `npi_task.c` queue drain | A producer running between the queue-empty check and the `TX_READY` clear can leave a non-empty queue with an idle transmitter (proven possible in source; not observed) | Re-check both queues and the UART under the critical section before pending (V44) |
| NPI RX callback | RX ring overflow lands in a `for(;;)` trap | Fail-closed, observable transport HOLD instead |

We also found and fixed defects in our own early R4 code: a UART2 callback overwritten at open, a startup barrier that assumed one `TX_FINISHED` per write, and an over-broad fatal latch on AF_REGISTER. They do not apply to stock builds.

## 5. Ruled out, and still unexplained

**Ruled out by evidence:**
- MAC retries: every data request succeeded during the stall.
- OSAL timer spinning: V52 measured it directly.
- RX overflow as the trigger: our trap replacement reported no overflow before the hangs.
- USB runtime suspend on the host: the device stayed `active` with zero suspended time.

**Not settled:**
- During the 28 Oct terminal stop we could not tell whether the CC2652P7 stopped transmitting or the ESP32-S3 stopped forwarding UART to USB CDC. Nothing between the two is observable without a logic analyser on the radio UART.
- On 27 Oct a radio-only reset and an ESP restart both failed to recover, while a ROM BSL entry and exit restored the same, unmodified firmware and network. Section 2b explains why the resets failed. Why the BSL round trip succeeded is not known; the longer outage may simply have let mesh traffic subside.

Neither has recurred since V53 (31 Oct), so both are consistent with the NV storm being the common driver.

## Investigation timeline

| Date (2026) | Finding |
|---|---|
| 16 Oct | Stock `20260310`: AF SRSP timeouts 35 min after boot on the 107-device mesh |
| 22 Oct | First R4 build reproduces it after 15 min, so it is not stock-specific |
| 25–27 Oct | TI NPI TX defects fixed (section 4); the hang persists. 27 Oct: ROM BSL round trip restores service after resets fail |
| 28 Oct | Captured escalation: async queue at its high-water mark, host queue 1,218 jobs, then total output stop |
| 29 Oct | V5/V46: replies wait 22–55 s behind the Stack task; NPI priority boost |
| 30 Oct | V47/V48/V50: startup starvation of NPI and ZDApp INIT captured and mitigated |
| 30 Oct | V52 evidence: NWK spends 304 s of 6.5 min in NV reads, one ~10 ms read per frame |
| 31 Oct | **V53 NV read cache installed: Stack 1 % busy, cache 99.7 %, no runtime stall since** |
| 13 Nov | V57 parser resync: cold-start failures end |
| 16 Nov | V58 route-discovery table 40: `NWK_TABLE_FULL` ends |
| 18 Nov | No SRSP timeout of any kind since 13 Nov; five first-attempt cold starts in a row |

## Source pointers

| Fix | Stage (edits pristine TI SDK source) |
|---|---|
| NV read cache (V53/V54), Stack aging and NPI floor (V50) | [`tools/r4_v50_stack_service.py`](../tools/r4_v50_stack_service.py) |
| Timer cleanup (V52) | [`tools/r4_v52_osal_timers.py`](../tools/r4_v52_osal_timers.py) |
| Retained ZDApp fairness (V48), startup NPI boost (V47) | [`tools/r4_retained_zdapp_fairness.py`](../tools/r4_retained_zdapp_fairness.py), [`tools/r4_startup_ingress_priority.py`](../tools/r4_startup_ingress_priority.py) |
| SRSP service, reserve and priority (V44–V46) | [`tools/r4_srsp_service.py`](../tools/r4_srsp_service.py), [`tools/r4_srsp_reserve.py`](../tools/r4_srsp_reserve.py), [`tools/r4_srsp_runtime_priority.py`](../tools/r4_srsp_runtime_priority.py) |
| UART TX liveness (V43) | [`tools/r4_uart_tx_liveness.py`](../tools/r4_uart_tx_liveness.py) |
| MT parser resync (V57) | [`tools/r4_v57_npi_rx_resync.py`](../tools/r4_v57_npi_rx_resync.py) |
| Route-discovery table (V58) | [`tools/r4_t6_full_capacity.py`](../tools/r4_t6_full_capacity.py) (`ROUTE_DISCOVERY`) |
| UART error accounting (V58) | [`tools/r4_v58_route_uart_evidence.py`](../tools/r4_v58_route_uart_evidence.py) |
| Composition order | [`tools/r4_b0_b4_composite_stage.py`](../tools/r4_b0_b4_composite_stage.py); [`tools/p7u_compose_source_locally.sh`](../tools/p7u_compose_source_locally.sh) produces the full composed TI patch locally |

Engineering notes: [V43](r4/b4/R4_V43_UART_TX_LIVENESS_20261027.md), [V44](r4/b4/R4_V44_SRSP_SERVICE_20261028.md), [V45](r4/b4/R4_V45_RESERVED_SRSP_20261028.md), [V46](r4/b4/V5_SRSP_RUNTIME_PRIORITY_20261029.md), [V53 review](../coordinators/slzb-06p7u/REVIEW_V53_2026-10-31.md), [release notes](../coordinators/slzb-06p7u/RELEASE_NOTES.md), [18 November status](../coordinators/slzb-06p7u/STATUS_2026-11-18.md). Issue history: [#143](https://github.com/analienx/Zigbee-Coordinator/issues/143), [#144](https://github.com/analienx/Zigbee-Coordinator/issues/144), [#161](https://github.com/analienx/Zigbee-Coordinator/issues/161), [#180](https://github.com/analienx/Zigbee-Coordinator/issues/180).

The installed firmware is source `1e7944e16de49237beb14647660676a927e1c4b5`, built by GitHub Actions [run 43708299735](https://github.com/analienx/Zigbee-Coordinator/actions/runs/43708299735).
