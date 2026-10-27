# P7U R4: Physical SRSP hang — evidence-led root-cause localization

**Updated:** 2026-10-27 UTC
**Status:** Serving network recovered by TI ROM BSL round-trip, *specific defect not proven*. All new code is source-only, not deployed; no reset/flash/second radio owner authorized by this report.
**Grounded in:** physical [issue #143 recovery](https://github.com/analienx/Zigbee-Coordinator/issues/143#issuecomment-6438517051), [issue #144 F2 and host SRSP evidence](https://github.com/analienx/Zigbee-Coordinator/issues/144), previously sealed **1177-record** HA F2 hash-chain archived privately at the Zephyrus before recovery.

## First-failure chronology (not merely the final ping error)

**UTC; from existing owner’s numeric host SRSP counters; timestamp precision is approximately the collector’s ~60-second observation interval.** SRSP progress means the existing host matched a reply; this is **not** RF reachability evidence. Source file path is intentionally private, only aggregate numeric results appear here.

| Time | AF matched SRSP OK | AF SREQ timeout | ZDO SRSP OK | UTIL SRSP OK | Host Waitress Map.size (includes expired) | Adapter queue pending |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Oct 26 15:19 (last native F2) | 14,381 | 186 | 353 | 6 | 0 | 0 |
| Oct 27 02:00 | 57,870 | 341 | 1,671 | 16 | 7 | 2 |
| Oct 27 03:00 | 61,663 | 510 | 1,701 | 24 | 16 | 86 |
| Oct 27 04:00 | 66,162 | 660 | 1,782 | 63 | 12 | 119 |
| Oct 27 04:15 | 66,286 | 789 | 1,782 | 63 | 79 | 378 |
| Oct 27 04:30 | 66,321 | 929 | 1,782 | 63 | 282 | 393 |
| Oct 27 05:00 | **66,321** | 1,229 | 1,782 | 63 | 880 | 221 |
| Oct 27 07:17 | **66,321** | 1,804 | 1,782 | 63 | **2,028** | 0 |

The final *observed increments* were **ZDO ~03:59 UTC**, **UTIL ~04:00 UTC**, **AF ~04:20 UTC**. **SYS ok=22 was already static since Oct 26 11:43 because no additional SYS successes were observed, not proof that SYS failed earlier**. Its actual new-process SYS ping failure is separate, subsequent hardware evidence. The *first* exact missing on-radio SRSP remains unknown.

**Source-proven secondary artifact: the 2,028 `Waitress pending` count is not 2,028 active waits.** In the exact pinned [zigbee-herdsman `Waitress`](https://github.com/Koenkk/zigbee-herdsman/blob/0968f979d558874b17396c96b66382d4236bbdcd/src/utils/waitress.ts), timeout callback sets `waiter.timedout=true` and rejects, but **does not delete the Map entry**. The Map normally sweeps expired entries on `forEachMatching` when later frames are processed (or on explicit removal). The deployed host getter `b4PendingCount()` returned raw `this.waiters.size`; therefore the jump from ~81 at 04:20 to 2,028 at 07:17 **is strongly consistent with timed-out tombstone accumulation after incoming response processing ceased**, not proof of >2,000 active simultaneous Zigbee requests or an initiating queue overload. The new passive getter in PR #169 keeps the legacy count unchanged for historic comparability **and also exposes active vs timedOut vs resolved vs rawMapEntries**. Do not use raw Map.size to infer pressure or root cause.

**Strong falsifier of naive F2 interpretation:** there were **51,940 further successful AF SRSPs after last VALID native F2** (Oct 26 15:19). Collection inactivity started **13+ hours before the final AF-success plateau**, so a stale F2 record is not evidence of NPI failure at that timestamp. The collector recorded many SKIPPED due adapter queue/Waitress admission. During an apparent healthy run after recovery, native F2 met the 30-minute SLO without restarting the device; new SLO warnings are in [PR #168](https://github.com/analienx/Zigbee-Coordinator/pull/168), not yet installed.

**Observed early pressure but no threshold proof:** sampled native F2 asyncHighWater increased **83 (Oct26 11:54) → 90 (13:27) → 148 (14:08) → 312 (15:16)** while AF timeouts accumulated **1 → 4 → 23 → 185**. *The sampled native asyncDepth remained 0 at those read times*, and full AF throughput continued for another ~13h. High-water is a historical peak, not instantaneous queue depth; neither buffer overflow nor memory exhaustion is proven. Current recovered host saw a normal increase from async HWM 128 to 208 with AF successes still progressing. **Do not treat HWM=312 as a discovered magic failure limit** or increase buffering without source proof.

**Post-failure functional differentiation:**
1. Single source-fingerprinted normal Zigbee restart changed boot behavior but new host failed **AF register SRSP**.
2. Separate ESP restart (USB reenumerated, ESP uptime reset) led to subsequent **SYS ping** failure.
3. Entering TI ROM BSL, reading ROM chip ID 0xF000 and 2 sector CRCs, exiting to unchanged exact R4 APP restored genuine MQTT device traffic. No flash, CCFG, NV, network replay or power-off. This strongly disfavors permanently invalid APP/NV bytes as *sufficient* explanation but does not distinguish the individual reset/boot/UART pin effects.

## Cross-repository corroboration, NOT causal proof

- [Koenkk/Z-Stack-firmware#592](https://github.com/Koenkk/Z-Stack-firmware/issues/592), cross-posted to [SMLIGHT #5](https://github.com/smlight-tech/slzb-os-scripts/issues/5), originally seemed to support a CC2652P7 UART corruption analogy; **SMLIGHT's explicit correction invalidates the report's radio attribution, reboot interpretation and stated version**. It is **excluded from causal evidence** pending independently verified log mappings.
- [Koenkk/zigbee2mqtt#32837](https://github.com/Koenkk/zigbee2mqtt/issues/32837) reports a similar CC2652P7 ZNP stall recovered by Zigbee reset+client restart without removing power; recovery recipes differ by incident and device.
- [Legacy SMLIGHT source](https://github.com/smlight-dev/slzb-06-firmware/blob/main/src/etc.cpp): ordinary radio reset asserts RST only ~250ms; legacy BSL asserts FLASH select before RST, then holds ROM for ~2s. [Current SLZB-OS Berry API](https://github.com/smlight-tech/slzb-os-scripts/blob/main/docs/modules/zb.md) says ESP32-S3 U-series reset/boot-select pins can run through a TCA9555 expander (pin IDs 100+n), and UART driver restart is separate. **The actual v3.4.3.dev1 compiled BSL-vs-RST implementation and expander timings are not publicly established**.
- [Official v3.4.3.dev1 release](https://smlight.tech/support/manuals/books/slzb-os/page/changelog-slzb-os) explicitly notes adaptive UART FIFO/timing configuration. The TCP socket-server fixes in the same notes **must not be mislabeled as USB evidence**.

## External corroboration retraction after reading SMLIGHT's own issue review

**DO NOT use Koenkk/Z-Stack-firmware#592 (cross-post smlight-tech/slzb-os-scripts#5) as verified evidence isolating CC2652P7 serial framing.** Its report labels ZB1 as CC2652P7 and ZB2 as EFR32MG21, but [SMLIGHT contributor Tarik2142 explicitly corrected that ZB1 is EFR32](https://github.com/smlight-tech/slzb-os-scripts/issues/5#issuecomment-3919177925), pointed out that "Reboot reason: SOFTWARE" is a *commanded reboot*, not evidence of a crash, and noted that the described firmware/log versions were inconsistent. The reported 35 packet-length errors might be real text but **their radio attribution and interpretation are disputed**. The dual-radio numeric comparison cannot currently distinguish CC2652P7 from EFR32. Treat it as **unreliable and excluded from root-cause likelihood ranking**, not independent proof of a TI/ESP bridge fault.

The separately documented [Koenkk/Z-Stack-firmware#518](https://github.com/Koenkk/Z-Stack-firmware/issues/518) reports user-perceived stability issues after a CC2652P7 firmware change, but without causal counters; it does **not repair the credibility defect** of #592. **Our local one-radio P7U counters and source-pinned ROM recovery remain the dominant evidence.**

## Falsifiable first-missing-boundary matrix

| During an initial AF SRSP timeout | What the observation actually localizes | Next code-level owner |
| --- | --- | --- |
| Host requests are still **queued**; existing CDC→UNPI parser receives **zero new raw bytes**; AF SRSP count stops | Failure is at/before the HA USB IN boundary; may be **radio MT/NPI UART TX, ESP UART RX/forwarding, USB CDC**, or radio reset | Compare physical radio F2 UART-TX-finished to independent ESP UART RX/USB forwarding counters; no single source identified |
| Raw USB RX byte count **increases**, but complete UNPI frame count remains flat and parse errors/buffer grow | Bytes reach HA but **framing/incomplete-packet/parser** path is suspect; radio or ESP may have produced damaged bytes | Source-review SLZB UART/FIFO config + parser checksums/framing; preserve only counts, no payload or Zigbee secrets |
| Valid UNPI frames keep arriving, AF SRSP successes flat while AF **timeouts rise** | Link is not wholly silent. Valid frames could be unrelated AREQs; missing AF SRSP needs TI MT dispatch/SRSP queue evidence | Record accepted SREQ, producer enqueue/reject, NPI queue, UART completion and matched SRSP |
| Raw RX, valid UNPI and AF SRSP all progress | No current serial-response outage in observed window; device RF failures or partial stall possible | Do not reset/flash; investigate scoped device/timeouts |

No passive host counter proves *on-chip reception* of a specific request or physical UART TX completion; the existing writer measures **queued bytes only**. 30-minute *valid F2* still cannot be guaranteed if the radio itself becomes unresponsive. The compiled F2 response currently has validityMask **0x2c**: async queue and UART-TX-finished valid, **SRSP depth/enqueued/HWM and hardware boot identity unqualified**. Avoid converting null fields into 0.

## Immediate source work and safety

[PR #169](https://github.com/analienx/Zigbee-Coordinator/pull/169) implements a **passive existing-owner RX/UNPI/TX boundary counter** extension and an offline same-owner-epoch classifier, building on [PR #168 30m native F2 SLO](https://github.com/analienx/Zigbee-Coordinator/pull/168). This does **not** add listeners opening a serial device: RX counting is in the existing parser transform; TX counting is in the existing writer methods; raw frame contents and identities are never persisted. Strict worker validator accepts only known nonnegative integers and known schema. Negative/adversarial tests confirm owner isolation and bad nested payload rejection. **Not deployed** to running Zigbee2MQTT; production collector is already taking multiple VALID F2 snapshots in rolling 30m.

**After exact-head source CI:** qualify a separately gated, single-owner host package deployment only if needed to capture the next incident; preserve recovered service, backups and the ROM recovery gate. Do not add an extra UART owner, perform “diagnostic” NPI requests during a hard hang, install Berry UART manipulation on the live coordinator, increase buffers speculatively or force a reproduction outage.

**What we can currently conclude:** A reversible serial/MT **response-path** loss is strongly supported; the precise failing component (**TI MT/NPI vs ESP UART/FIFO/USB vs host framing**) **remains unknown**. The next genuinely discriminating evidence is at the USB→UNPI boundary during the earliest AF timeout, paired with physical radio TX progress and ESP bridge metrics if safely available. If that boundary remains ambiguous, a different exact-source firmware/ESP build may be necessary, but only *after* the first-stage evidence, never to mask failure with a blind reflash.
