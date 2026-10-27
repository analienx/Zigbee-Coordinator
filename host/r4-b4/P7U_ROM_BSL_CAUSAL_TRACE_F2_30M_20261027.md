# P7U: ROM recovery vs ordinary reset — source investigation and F2 30-minute SLO

**2026-10-27; source-only changes, production radio remains serving on R4 `4cfe317`.**

## Evidence already established on the only P7U

- Hard hang progression: host AF success ceased, then ZDO/UTIL/SYS became unresponsive. Fresh Z2M `SYS ping` timed out; normal SMLIGHT Zigbee restart allowed a later `AF register` timeout. A separate ESP reboot reset ESP uptime and enumerated USB, but a subsequent startup still failed `SYS ping`.
- With **all UART owners stopped**, a single identity-checked remote SMLIGHT `CMD_ZB_BSL=2` entered TI ROM, TI `SYNC` and `CHIP_ID=0xf000` succeeded along with APP0/CCFG CRC. After ROM port close and source-verified `CMD_ZB_RST=1`, the *unchanged* R4 app and security state served fresh MQTT traffic. No flash/NV/CCFG writes or physical power cut. [Actual #143 receipt](https://github.com/analienx/Zigbee-Coordinator/issues/143#issuecomment-6438517051).
- The recovered Z2M diagnostic host is `0.2.1-c5d8b0ce6fdf`, with existing **60–90 second jittered** F2 attempts and strict owner/OTA/adapter/Waitress admission. At a read-only snapshot on 27-Oct ~10:45 UTC, the verified-generation journal had 1254 events overall (96 native VALID across owner epochs), **10 VALID native F2 in the trailing 30 minutes**, latest at 8m16s age, live host `started` and guard disabled. Many SKIPPED records continue under `ADAPTER_QUEUE_PENDING`, so future **freshness cannot be assumed**.
- The previous incident had only 76 valid native F2 until ~13 hours before failure; F2 then wrote safe passive SKIPPED records while the adapter/Waitress remained busy. The host did not collect a final native firmware snapshot. [#144 postmortem](https://github.com/analienx/Zigbee-Coordinator/issues/144#issuecomment-6436979523).

## Concrete source differential from the older SMLIGHT firmware

The publicly available [`smlight-dev/slzb-06-firmware` `src/etc.cpp`](https://github.com/smlight-dev/slzb-06-firmware/blob/main/src/etc.cpp) contains:

- `zigbeeRestart()`: assert **only `CC2652P_RST=0`** for **250 ms**, then release `RST=1`.
- `zigbeeEnableBSL()`: assert **`CC2652P_FLSH=0`**, wait **100 ms**, assert `RST=0` for **250 ms**, release `RST=1`, **wait 2000 ms while FLASH remains asserted**, then release `CC2652P_FLSH=1`.
- Older `src/web.cpp` maps separate `CMD_ZB_RST`, `CMD_ZB_BSL` and `CMD_ESP_RES` handlers. Older `src/config.h` uses dedicated separate ESP GPIO pins for RESET and FLASH. [TI SWRA466E](https://www.ti.com/lit/an/swra466e/swra466e.pdf) confirms the ROM serial bootloader backdoor is entered using a designated CCFG pin level sampled at reset, and the ROM UART protocol is separate from a running ZNP application's NPI task.

**Qualification limit:** this repository describes a legacy SLZB-06 / older CC2652P ESP platform, **not actual source for the present 06P7U ESP32-S3 SLZB-OS `v3.4.3.dev1`**. The real firmware's `/js/httpApi.js` JS fingerprint confirms **handler command numbers** (BSL=2, RESET=1) but **does not expose its backend GPIO implementation or timing**. Therefore the pin/timing sequence above is a **specific, evidence-supported architectural precedent**, NOT an assertion that current OS has exactly the same timings or pin numbering.

The actual vendor [`v3.4.3.dev1` changelog](https://smlight.tech/support/manuals/books/slzb-os/page/changelog-slzb-os) explicitly mentions **adaptive UART timing and FIFO settings** and new `ZB.initUart` hardware-flow handling, making ESP bridge behavior an important candidate to audit. It is NOT proof of an introduced bug; no before/after OS comparison or UART overrun count exists.

## Updated causal ranking

1. **Runtime NPI/MT/UART app-path lock, with different bootloader-backdoor reset sequencing** clearing the wedged state. Supported by same APP/NV serving after ROM entry/exit; **not a proven hardware root cause**, because ordinary RST also toggles MCU reset.
2. **ESP32-S3↔CC2652P7 USB/UART bridge / FIFO / pin transition, reset-order race** affecting application UART but not ROM UART. BSL explicitly exercises a distinct radio boot path; published newer SLZB-OS has adaptive UART FIFO logic, raising diagnostic priority but NOT proving culpability.
3. **Transient service-load/resource or startup-ordering race**. Production AF/ZDO/SYS timeout sequence and F2 high-water support probing first missing SREQ/SRSP boundary, not claims of observed queue overflow at the moment of the hang.
4. A **permanently corrupted flash image** as the sufficient root cause is weak: identical firmware returned to service with no writes. Two ROM CRC checks alone do not attest the complete APP.

**The difference to isolate:** Is the decisive action (a) asserting the bootloader/backdoor pin at reset, (b) holding the CC2652P7 in ROM for an extended period, (c) disposing and reopening the ESP↔radio UART stream, or (d) later application boot timing? These are currently **confounded in one physical recovery**. Do not deliberately recreate a household outage to compare them.

## Next minimal firmware / bridge analysis (no disruptive testing)

1. Find the actual closed/provided `SLZB-OS v3.4.3.dev1` Zigbee reset and BSL backend implementation, or obtain its reset GPIO timing and UART reinitialization contract from the vendor. Do not assume old ESP GPIO numbers apply to the new S3 board.
2. Review exact installed R4 source around `MT SRSP formation → NPI enqueue → UART Tx callback` and failure counters. Latest F2 `validityMask=0x2c` supports async queue and UART `TX_FINISHED`, **but SRSP queue depth/enqueued/HWM and hardware boot epoch were invalid or null**. Patch correctness first, not buffer scaling.
3. Use **single-owner**, bounded first-production-SRSP-timeout callback to capture a real F2 while possible, plus independent ESP UART RX/TX counters where vendor supports it read-only without stealing serial ownership. F2 cannot be expected to reply after its own MT dispatcher stalls.
4. Continue serving without Zigbee2MQTT stop/start, flash, bridge switch, reset, join/map load or forced RF tests until there is specific source evidence requiring a qualified hardware change.

## Native F2 30-minute collection contract

**SLO:** At least **one successfully decoded AND durably committed** original-owner native F2 record in each rolling **1800-second** window. A timer callback, `SKIPPED`, `FAILED`, stale previous-owner VALID or uncommitted IPC message **DOES NOT** satisfy this objective. Existing safe sampling rate 60–90s remains unchanged; sampling does not bypass the adapter queue, ZNP Waitress/SRSP mutex or OTA quarantine.

This branch implements:
- Collector commit-ACK-aware last-native-valid tracking; a small single-owner warning if **30 minutes** elapse without a durable native F2; no extra ZNP traffic, no reset and no self-healing.
- Separate offline verifier `native_f2_30m_objective = MET / BREACHED / NOT_YET_OBSERVED_FOR_30M` and `native_f2_in_last_30m`, independent of the passive sampler-feed staleness horizon (3 minutes). All checks are owner-epoch scoped and distinguish unsupported radio SRSP counters from zeros.
- GitHub-hosted unit regression coverage on missed native snapshot while passive host evidence continues, prior-owner contamination, current-owner first-valid grace period and no automatic recovery.

**Safety/realism:** No software can guarantee a **VALID** reply if the radio itself has hung, and optional probes must not compromise real traffic. A missed 30-minute window is a **visible observability SLO breach**, **never a reset trigger**. The currently running host is still the previously qualified `c5d8` image until a separate, reviewed single-owner cutover; source merge/CI alone does not change its runtime warnings or radio firmware. The current live host is **already meeting** the 30-minute snapshot target.
