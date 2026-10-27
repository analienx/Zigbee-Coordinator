# SLZB-06P7U: Priority-1 hard-hang recovery — ROM/BSL round-trip

**Operational decision (verified 2026-10-27):** When this P7U's local ZNP command/response path hangs, **first preserve evidence and perform a guarded ROM-bootloader round-trip, returning to the unchanged firmware**. Do not first repeat radio-only or ESP restarts; both failed in the October 27 incident. A physical power cut or reflash is **not required by this verified method**.

**Scope:** the sole production SMLIGHT SLZB-06P7U, board R1.73, TI CC2652P7, SLZB-OS v3.4.3.dev1, USB mode, retained ~107-device network. Other coordinators, SLZB-OS versions and modes are *not automatically qualified*. Root-cause firmware work remains separately prioritized by [FIRMWARE_FIRST_POLICY.md](FIRMWARE_FIRST_POLICY.md).

**Proven receipt:** [2026-10-27 #143](https://github.com/analienx/Zigbee-Coordinator/issues/143#issuecomment-6438517051). **Diagnostics:** [#144](https://github.com/analienx/Zigbee-Coordinator/issues/144#issuecomment-6438518225).

## First-response decision

1. **Confirm a hard ZNP hang**, not merely an offline device or mesh NO_ROUTE. Look for locally failing SYS/AF/ZDO SRSP, frozen response counters, real device freshness loss while the MQTT broker itself is healthy, and a hung or failed Z2M initialization. Record first/last response timestamps, host Waitress/adapter queue, and last *valid* F2 snapshot. A skipped F2 is not a diagnostic response.
2. **Freeze evidence and ownership.** Privately hash/copy F2 journal, live logs, database.db, coordinator_backup.json, config and current NV/security/frame-counter baseline. Verify only one serial owner, no OTA/flash job, no Z2M/HA automation or recovery watchdog racing. Quiesce the single current production owner and show old/managed add-ons stopped/error and port holders zero. Never open ROM over a running Z2M UART.
3. **Use ROM/BSL round-trip FIRST**, as detailed below. It is one bounded new incident operation, *not* an unattended watchdog action. Do not reuse consumed October 27 intent IDs/scripts.
4. **Only if ROM reentry cannot recover:** inspect fresh ROM and current APP+paired AC000 provenance for a separate, explicitly authorized guarded APP flash; protect all NV4, CCFG, network keys, TCLK and monotonic counter floors. Do not blindly flash or use stock restore as a shortcut. If ROM is inaccessible, stop and diagnose the physical bridge. No broad erase, factory reset, re-pair, new PAN, or CMD_HARD_RESET=9.

## The physically successful no-power-cycle procedure

**These are controlled procedure requirements, not a paste-and-run shell recipe.** Use pinned, audited Python operator modules and fresh incident-specific, immutable private journals. Failure at any guard means **STOP, not retry**.

### A. Exact-device, security and policy preflight

- Match **SLZB-06P7U**, **CC2652P7**, SMLIGHT coordinator **USB coord_mode=2**, physical MAC, expected SLZB-OS version and pinned HTTP API source. Existing USB by-id path on the qualified unit: `/dev/serial/by-id/usb-SMLIGHT_SMLIGHT_SLZB-06p7U_SLZB-06p7U115236-if00` resolving to `/dev/ttyACM0`, baud 115200, `rtscts=false`. Never switch USB ↔ Ethernet as part of this operation.
- Confirm current Zigbee2MQTT is stopped/error, no active owner of that character device, other Zigbee2MQTT add-on stopped, host boot/manual, watchdog off, recovery guard `enabled=false`/`dry_run=true`/`serial_owner_approved=false`. Require a fresh approved database/coordinator backup and retained security/counter invariants. No backup replay is part of ROM recovery.
- Source-fingerprint the vendor firmware's actual `/js/httpApi.js` against the installed release and verified model/MAC, independently recheck control-opcode mapping. On **SLZB-OS v3.4.3.dev1 only**, the reviewed JS SHA-256 was `2d50552d71bf55f8f87aeabece9f4dae01d589d9e2e88699ec0b15e8e8e600ed`, with `API_CMD=4`, `CMD_ZB_BSL=2` and `CMD_ZB_RST=1`. These are **version- and device-gated**, not universal private commands. **Never** invoke `CMD_HARD_RESET=9`.
- Acquire the existing HA lifecycle/exclusive-port lock. Allocate a **new** incident operation ID. Before each side effect, write a private fsynced `CONSUMED_BEFORE_SEND` intent and fsync its directory. On ambiguous HTTP/SSH outcomes, inspect rather than replay. Vendor API throttle ≤1 request per second.

### B. Enter and verify the TI ROM bootloader — without writing firmware

- With no radio serial owner, issue exactly **one** approved SMLIGHT management **Zigbee BSL entry** using the source-verified action (on this pinned OS, `/api2?action=4&cmd=2`). The management `ok` ACK **does not alone prove** ROM entry.
- After it settles, open **only** the pinned USB by-id at 115200 through the exact-source Python `SafeFastUsbRom` / `p7u_rom_lowlevel` transport from the qualified R4 release. Send one ROM SYNC, require the chip ID **`0xF000`**, and optionally read bounded, read-only ROM CRCs for APP sector 0 and CCFG. The 27-Oct incident measured APP sector-0 CRC32 `f713de7d` and CCFG-sector CRC32 `3c032e08`. These two checks prove ROM access, **not** full-image equality.
- **Always close the ROM UART before proceeding.** No erase, download, send-data, BSL re-entry retry, DTR/RTS probing or NV write. Failure to synchronize, unexpected chip ID, unexpected boot/CCFG or unexplained UART state is a STOP.

### C. Exit BSL to the **unchanged existing** R4 application

- Write a new durable one-shot app-boot intent with the ROM read-only receipt and port-release proof.
- With no ROM/Z2M owner, issue **one** source-verified **SMLIGHT Zigbee restart/application boot** action (qualified `CMD_ZB_RST=1`). This is **not** an ESP reset, factory reset, firmware flash or full power cut.
- Permit application startup and confirm the exact USB by-id still exists. The radio image that previously served the network on 2026-10-26 was R4 source **`4cfe317083c2a3d1b784350b0ab960e27218e618`** with its paired APP+AC000. **No flash was executed in the 27-Oct recovery**.

### D. Start exactly one host and prove **real serving**

- Reconfirm port ownership zero and all recovery automation disabled. Write and fsync a **new** single-start intent before Supervisor starts the already installed host `local_p7u_r4_native_host` (27-Oct: `0.2.1-c5d8b0ce6fdf`). A Supervisor API call can time out while the container **has actually started**: inspect state and logs before any subsequent action; **do not repeat** the start on HTTP timeout.
- Require full herdsman startup past SYS/AF registration, `Zigbee2MQTT started!`, an authenticated MQTT connection and no fatal NPI/SRSP errors. Do not run another UART diagnostic owner concurrently.
- Independently sample a **read-only authenticated MQTT v5** subscriber on `zigbee2mqtt/+` using `retainHandling=2` (RH 2), discard `packet.retain=true` and broker bridge topics. Verify **new non-retained traffic from ≥3 distinct Zigbee device topics**. Initial Z2M startup publications alone are not sufficient evidence.
- On **27-Oct**, Supervisor moved to `started`, Docker was `Running=true` with **RestartCount=0**, and the independent read-only subscriber captured **24 fresh non-retained messages from 5 device topics in 5.7 seconds** with no retained deliveries. This proves *initial household service restored*, not an unattended 7-day reliability soak.

### E. Seal results

Write a private immutable receipt: device/source/host version, fresh operation ID and consumed intents, ROM ID/CRC, single boot and start results, first real MQTT times and number of unique devices, whether NV/CCFG/APP were written (**false**) and any unresolved failures. Keep raw backup, keys, IEEE tables, frame counters and management MAC out of public Git. **Never rerun the historical single-shot Python recovery script**; it contains consumed per-incident markers. Leave the watchdog disabled until a separately reviewed recovery controller is safe and approved.

## October 27 diagnostic chain — why this is method #1

| Action actually tried | Physical result |
| --- | --- |
| Radio-only SMLIGHT restart, then new Z2M start | USB opened, SYS initialization advanced, but **`SRSP - AF - register after 6000ms`**. NO service. |
| ESP32-core restart, followed by one new host start | ESP uptime reset, USB re-enumerated; **`P7U HOLD_EXISTING_NV: ping unavailable`**. NO service. |
| **Enter ROM BSL → SYNC/CHIP_ID/CRC → close port → Zigbee APP boot → one host start** | ROM responsive; original existing firmware booted; host `started`; **24 new non-retained messages from 5 devices**. PASS. No physical power-off and **no flash**. |

Earlier [22-Oct physical evidence](https://github.com/analienx/Zigbee-Coordinator/issues/145#issuecomment-6347602487) found a one-time radio restart failure followed by ESP restart success. That **did not repeat** on 27-Oct. Therefore first prioritize the method that **actually worked on the current firmware and hard-hang state**.

## Root-cause implications: observations vs inferences

**Established from the incident:**
- During the original hang AF/ZDO/UTIL successful responses stopped progressing while AF timeouts and host pending work increased; later fresh Z2M process could not obtain SYS ping. This is not merely an MQTT outage or mesh no-route.
- ROM SYNC, chip ID and memory CRC were received on the **same physical USB path after entering BSL**, so the CC2652P7 ROM and USB/UART link were capable of two-way traffic at that moment.
- The **same R4 application and original network data** resumed device service *without writing APP/AC000/NV/CCFG*, arguing against permanently damaged flash content as the sufficient explanation.
- ROM BSL entry itself may exercise a different hardware reset, boot strap, UART pin/mux, ESP bridge transition and boot timing from `CMD_ZB_RST`; **which difference mattered has not been measured**.

**Ranked hypotheses, not proven conclusions:**
1. **CC2652P7 application NPI/MT/RTOS/UART-path deadlock or latched runtime state**, cleared by the ROM-backdoor transition and new application boot.
2. **ESP-to-radio UART bridge, control/reset-line or pin-multiplexer state**, initialized differently by BSL entry than an ordinary Zigbee or ESP restart.
3. **Reset/startup ordering or resource-pressure race** avoided by the BSL dwell / fresh ROM handshake; AF timeouts and F2 async-queue high-water suggest contention but **do not prove** saturation during the final hang.
4. Persistent APP/CCFG/NV corruption is **less consistent** with recovery without writes; not completely excluded by two ROM CRC reads.

**Best next discriminator (no intentional new hang):** Compare the board's actual source/logic for `CMD_ZB_BSL` versus `CMD_ZB_RST` (GPIO/reset/boot straps and UART mux); instrument independent ESP UART byte RX/TX, radio NPI receive → MT handler → SRSP enqueue/dequeue → physical TX-finished around first lost SRSP; preserve a bounded pre-hang native F2 snapshot. The October 27 F2 ring contained **1,177** valid chained records but only **76** native F2 replies, last ~13 h before failure; admission gates skipped later samples, and unsupported F2 SRSP queue counters must not be interpreted as zero. See [F2 postmortem](https://github.com/analienx/Zigbee-Coordinator/issues/144#issuecomment-6436979523).

**Bottom line:** The ROM round-trip is a **proven restoration procedure** and a **causal localization clue**, **not** proof of a particular firmware defect and **not** permission for repeated resets or blind reflashing.

## Primary references

- [Physical recovery receipt, 27-Oct #143](https://github.com/analienx/Zigbee-Coordinator/issues/143#issuecomment-6438517051); [real R4 serving #161](https://github.com/analienx/Zigbee-Coordinator/issues/161#issuecomment-6422567271).
- [SMLIGHT official CC flasher bootloader invocation](https://github.com/smlight-tech/smlight-cc-flasher/blob/main/smlight_cc_flasher/command.py) (distinct network BSL operation); [TI ROM serial bootloader specification SWRA466E](https://www.ti.com/lit/an/swra466/swra466.pdf) (independent ROM firmware and UART SYNC/ID/CRC interface).
