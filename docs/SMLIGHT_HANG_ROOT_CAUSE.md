# SLZB-06P7U coordinator hangs: root cause and fixes (for the SMLIGHT firmware team)

This note is written for SMLIGHT's firmware engineers. It explains why our SLZB-06P7U stopped answering Zigbee2MQTT on a dense network, what we measured, and the changes that fixed it, so they can be checked against SMLIGHT's own builds. Everything below is reproducible from this repository. We are happy to share the composed patch or answer questions.

## Summary

| # | Failure seen by the host | Root cause | Fix | Status |
|---|---|---|---|---|
| 1 | Runtime "hang": AF/ZDO/SYS SRSP timeouts after minutes to hours, then Zigbee2MQTT restarts | **NV read storm.** TI Z-Stack reads the active network key from NV on every secured frame. Each read is a linear NVOCMP item search, about 10–12 ms on a large NV. The Stack task saturates and the MT/NPI task, which runs at lower priority, cannot answer the host. | 8-line RAM read cache in front of `osal_nv_read`, invalidated by every NV mutation | **Fixed.** No runtime stall since 31 Oct 2026 |
| 2 | Cold start: `SRSP - SYS - ping after 6000ms`, several Zigbee2MQTT attempts, 9–11 min to come up | **MT frame parser has no inter-byte timeout and no length bound.** One stray `0xFE` plus a length byte at power-on swallows the host's next frames. | Resync after a 500 ms RX idle gap; reject lengths above 250 | **Fixed.** 0 of 5 cold starts failed since, versus 4 of 11 before |
| 3 | `0xC7 NWK_TABLE_FULL` from `ZDO extRouteDisc` (herdsman's recovery step) | TI default route-discovery table, `MAX_RREQ_ENTRIES` 8, too small for a mesh of 57 routers | `MAX_RREQ_ENTRIES=40` (320 B RAM) | **Fixed.** 0 refusals in 65 discoveries, versus 6 in 37.5 h before |
| 4 | Occasional MT frame dropped | UART RX overrun at 115200 baud, no flow control, 32-byte RX buffers | Counted only so far (overrun event enabled) | Open: about 1 per 9 h, recovered by fix 2 |

Fix 1 is the one that matters most. Fixes 2 and 3 address separate, smaller failure classes.

## Test system

- **Hardware:** SLZB-06P7U R1.73, TI CC2652P7, USB to Home Assistant (Ethernet used for management only).
- **Firmware base:** TI SimpleLink low-power F2 SDK `lpf2-8.33.00.16` (`simplelink-lowpower-f2-sdk` `3615ad5d`), Z-Stack ZNP, coordinator role. NPI UART 115200 baud, no RTS/CTS.
- **Host:** official Zigbee2MQTT 2.14.2-1 (zigbee-herdsman 10.10.0) as the only serial owner.
- **Network:** 106 joined devices, 57 routers and 49 end devices, channel 11. NV: 893 active records (address manager 406 rows, about one TC link-key entry per device).
- **Stock comparison:** SMLIGHT stock `20260310` showed the same runtime symptom on this network on 16 Oct 2026. The first AF SRSP timeout came at 09:00:57, followed by 64 AF and 6 ZDO SRSP timeouts and 69 downstream timeouts before the service was stopped ([#145](https://github.com/analienx/Zigbee-Coordinator/issues/145)). Our own early builds, before fix 1, reproduced it about 15 minutes after start.

## 1. Runtime hang: NV read storm

### Mechanism

1. Every received or sent NWK-secured frame needs the active network key. In TI's closed NWK library (`libZStack_nwk_all.a`), that lookup calls `ZDSecMgrReadKeyFromNv(ZCD_NV_EX_LEGACY, ZCD_NV_NWK_ACTIVE_KEY_INFO, …)`.
2. `ZDSecMgrReadKeyFromNv` (`source/ti/zstack/stack/zdo/zd_sec_mgr.c`) does not keep the key in RAM. It calls `osal_nv_read(ZCD_NV_NWK_ACTIVE_KEY_INFO, offsetof(nwkKeyDesc, key), SEC_KEY_LEN, …)`.
3. `osal_nv_read` → `NVOCMP_readItemApi` searches the NV page for the item. The search is linear in the number of records. With 893 active records it took **about 10–12 ms per read** on this board.
4. With a dense mesh, frames arrive often enough that the Stack task spends most of its time in NV reads. TI's task priorities put Stack at 5 and NPI (the MT/host link) at 4, so the NPI task starves and host requests miss herdsman's 6 s SRSP deadline. From the host this looks like a hung adapter.
5. **Likely escalation to a hard hang (inferred, not captured):** in stock TI NPI, an RX ring overflow lands in a `for(;;)` trap in the UART ISR path. A starved NPI task with a host that keeps retrying is exactly the condition for that overflow. It would explain why some stalls needed a reset (or a ROM BSL round trip) rather than recovering by themselves.

### Measurements

| | Before (V52, 10-min capture during the problem) | After (V53+) |
|---|---|---|
| NWK task time in NV reads | about **98 %**; 304 s of NV time | 0.9 s |
| Stack task busy | saturated | 1–3.5 %, 0 saturated 10 s windows |
| NV read cache hit ratio | n/a | 99.5–99.9 % (18 Nov: 698,323 hits / 3,558 misses in 9 h) |
| Hottest NV item | `ZCD_NV_NWK_ACTIVE_KEY_INFO` (0x3A), read per frame | same item, served from RAM |
| SRSP timeouts | repeated | none since 31 Oct (runtime) |

On 18 Nov the remaining uncached 0x3A reads averaged 12.4 ms each (304 reads, 3.76 s). Multiplied over 698,323 cached reads, the cache saved about 2.4 hours of CPU in 9 hours of uptime.

### Fix (V53, guarded in V54)

An exact-match read cache in the NV driver path (`tools/r4_v50_stack_service.py`, blocks `B4_V53_*` and `B4_V54_CACHE_HOLD_AND_SECRET_GUARD`):

- 8 lines × up to 32 bytes, keyed by system ID, item ID, sub ID, offset and length.
- **Invalidated on every NV write, delete, compaction, `doNext` and erase**, before and after the driver call. A generation counter stops a read that races a mutation from being cached.
- Never caches the TCLK seed. NULL or zero-length reads bypass it. Our fail-closed NV mode bypasses and wipes it.
- No API change for TI's code: callers still call `osal_nv_read`.

**Simpler alternatives SMLIGHT could consider:** keep the active and alternate NWK keys in RAM inside `ZDSecMgrReadKeyFromNv`, refreshed wherever `zd_sec_mgr.c` writes `ZCD_NV_NWK_ACTIVE_KEY_INFO`, which is the only per-frame item we observed. A generic cache, as above, also covers less frequent hot items.

### How to reproduce

Use a network of about 100 devices with many routers, or any build with several hundred NV records. Count `osal_nv_read` calls for item 0x3A per second, or time the Stack task. On ours, the call rate tracks received frames, about 20 per second at normal load and far more during bursts and route discovery.

## 2. Cold start: MT frame parser swallows the host's first frames

### Mechanism

TI's `NPIFrame_collectFrameData` (`npi_frame_mt.c`):

- After any `0xFE` it takes the next byte as a length and waits **indefinitely** for length + 3 more bytes. There is no inter-byte timeout.
- It accepts lengths 251–255 even though `MT_RPC_DATA_MAX` is 250.

A stray `0xFE` plus one byte on the RX line around power-on therefore swallows the next host frames. Each Zigbee2MQTT start sends 26 bytes (pings, `0xEF`, pings), so it takes several restarts before the parser is back in sync. On 4 of 11 mornings, after the nightly power cut, Zigbee2MQTT needed four starts and 9.5–11 minutes. Live evidence showed the radio had not reset and had no internal fault. Replaying one `0xFE` plus a length of 82–86 into TI's unmodified parser reproduces the exact pattern of unanswered and answered pings. We never captured the stray bytes, so the source of the `0xFE` is unknown: ESP32/USB bridge activity at power-on is a candidate.

### Fix (V57, `tools/r4_v57_npi_rx_resync.py`)

- **Idle resync:** if a new chunk arrives into an incomplete frame more than 500 ms after the previous byte, the partial frame is dropped and the parser hunts for `0xFE` again. Herdsman writes each frame at once, so a real frame is never split by 500 ms.
- **Length bound:** a length above 250 ends the candidate frame.
- A failed frame's bytes are not rescanned, so a command the host already timed out on is never executed late.

**Result:** five nightly cold starts in a row (14–18 Nov 2026) connected on the first attempt. Before V57, 10–13 Nov each needed several attempts.

## 3. Route discovery refused: `NWK_TABLE_FULL`

Zigbee-herdsman sends `ZDO extRouteDisc` only after a unicast has failed, as its recovery step. With TI's default `MAX_RREQ_ENTRIES` of 8, the coordinator refused it with `0xC7`, so the recovery itself failed. In V57's first 37.5 h, 6 of 6 `NWK_TABLE_FULL` errors were these refusals, 5 of them to two bulbs during automation bursts.

**Fix (V58):** compile with `MAX_RREQ_ENTRIES=40` (TI's closed NWK library reads it through `gMAX_RREQ_ENTRIES`). It costs 320 B of RAM. Result: 65 of 65 discoveries succeeded and no refusals in 2.2 days. We left `MAX_BCAST` at TI's default, because more broadcast entries add broadcast load on a busy channel.

## 4. UART RX overruns (open, low impact)

The NPI UART runs at 115200 baud with no flow control, a 32-byte DMA read buffer (`UART_ISR_BUF_SIZE`) and a 32-byte UART2 ring buffer. TI's UART2 driver counts overruns only when `UART2_EVENT_OVERRUN` is in the event mask; the ZNP mask holds only `TX_FINISHED`, so overruns are invisible in a stock build. With the event enabled (V58) we counted **one overrun in 9 hours**, followed within seconds by fix 2's resync. No host-visible failure. If the board routes RTS/CTS, hardware flow control would remove this class; otherwise larger RX buffers are the next step.

## Other changes in our build (context, not hang causes)

- MAC queue sizes raised from TI's 5 / 8 / 5 to 50 / 80 / 50 for the dense mesh; 0 refused MAC requests in every sample since.
- Address-manager, device-list, routing (128), source-route (192) and neighbor (64) table capacities raised for 100+ devices.
- Fail-closed NV with read-back verification, preserved network identity, keys and frame counters across firmware changes.
- RAM-only diagnostic pages (MT SYS 0xF1) for scheduler, heap, timers, NV cost, parser and route-discovery counters, readable through the running host.

Details: [release notes](../coordinators/slzb-06p7u/RELEASE_NOTES.md), [R4 vs stock](R4_VS_STOCK.md), [18 November status](../coordinators/slzb-06p7u/STATUS_2026-11-18.md), [V53 review](../coordinators/slzb-06p7u/REVIEW_V53_2026-10-31.md).

## Source pointers

| Fix | Stage (edits pristine TI SDK source) |
|---|---|
| NV read cache | [`tools/r4_v50_stack_service.py`](../tools/r4_v50_stack_service.py) (`B4_V53_*`, `B4_V54_*`) |
| MT parser resync | [`tools/r4_v57_npi_rx_resync.py`](../tools/r4_v57_npi_rx_resync.py) |
| Route-discovery table | [`tools/r4_t6_full_capacity.py`](../tools/r4_t6_full_capacity.py) (`ROUTE_DISCOVERY`) |
| UART error accounting | [`tools/r4_v58_route_uart_evidence.py`](../tools/r4_v58_route_uart_evidence.py) |
| Composition order | [`tools/r4_b0_b4_composite_stage.py`](../tools/r4_b0_b4_composite_stage.py); [`tools/p7u_compose_source_locally.sh`](../tools/p7u_compose_source_locally.sh) produces the full composed TI patch locally |

The installed firmware is source `1e7944e16de49237beb14647660676a927e1c4b5`, built by GitHub Actions [run 43708299735](https://github.com/analienx/Zigbee-Coordinator/actions/runs/43708299735).
