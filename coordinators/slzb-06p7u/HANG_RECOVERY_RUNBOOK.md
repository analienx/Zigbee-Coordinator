# SLZB-06P7U: Priority-1 hard-hang recovery — ROM/BSL round-trip

**Operational decision (verified 27–28 October 2026):** When this P7U's local ZNP command/response path hangs, **first preserve evidence and perform a guarded ROM-bootloader round-trip, returning to the unchanged firmware**. Use the qualified writer's **USB-open-before-BSL-entry** ordering. Do not first repeat radio-only or ESP restarts. A physical power cut or reflash is **not required by this verified method**.

**Scope:** the sole production SMLIGHT SLZB-06P7U, board R1.73, TI CC2652P7, SLZB-OS v3.4.3.dev1, USB mode, retained ~107-device network. Other coordinators, SLZB-OS versions and modes are *not automatically qualified*. Root-cause firmware work remains separately prioritized by [FIRMWARE_FIRST_POLICY.md](FIRMWARE_FIRST_POLICY.md).

**Proven receipt:** [2026-10-27 #143](https://github.com/analienx/Zigbee-Coordinator/issues/143#issuecomment-6438517051). **Diagnostics:** [#144](https://github.com/analienx/Zigbee-Coordinator/issues/144#issuecomment-6438518225).

## First-response decision

1. **Confirm a hard ZNP hang**, not merely an offline device or mesh NO_ROUTE. Look for locally failing SYS/AF/ZDO SRSP, frozen response counters, real device freshness loss while the MQTT broker itself is healthy, and a hung or failed Z2M initialization. Record first/last response timestamps, host Waitress/adapter queue, and last *valid* F2 snapshot. A skipped F2 is not a diagnostic response.
2. **Freeze evidence and ownership.** Privately hash/copy F2 journal, live logs, database.db, coordinator_backup.json, config and current NV/security/frame-counter baseline. Verify only one serial owner, no OTA/flash job, no Z2M/HA automation or recovery watchdog racing. Quiesce the single current production owner and show old/managed add-ons stopped/error and port holders zero. Never open ROM over a running Z2M UART.
3. **Read the firmware's own hang record BEFORE the ROM round-trip (V51 and later).** The round-trip resets the chip and erases the RAM-only record of how the collapse began. With Z2M stopped and port holders zero, run the sealed operator **once**: `p7u_pr154_ha.py hang-evidence --operation-id <installed firmware's flash operation> --plan-pin <its write plan>` (plus the usual `--package/--package-pin/--binding/--binding-pin`). See [the capture details](#v51-read-only-hang-evidence) below. Continue with step 4 whatever it reports; never retry the capture.
4. **Use ROM/BSL round-trip FIRST** among recovery actions, as detailed below. It is one bounded new incident operation, *not* an unattended watchdog action. Do not reuse consumed October 27 intent IDs/scripts.
5. **Only if ROM reentry cannot recover:** inspect fresh ROM and current APP+paired AC000 provenance for a separate, explicitly authorized guarded APP flash; protect all NV4, CCFG, network keys, TCLK and monotonic counter floors. Do not blindly flash or use stock restore as a shortcut. If ROM is inaccessible, stop and diagnose the physical bridge. No broad erase, factory reset, re-pair, new PAN, or CMD_HARD_RESET=9.

## V51 read-only hang evidence

`hang-evidence` (`host/flash/p7u_hang_evidence_once.py`) refuses to open the USB by-id unless all of the following hold:
- the installed source supports B1E3;
- the operation's verified write and `started-pending-serving` name that source;
- the HA policy shows no watchdog or automation;
- the Z2M owner is stopped;
- the inspector proves zero TTY holders;
- the board identity matches.

It then sends, in this order, each reply fsynced to a fresh private `hang-evidence-*/evidence.jsonl` before the next request:
1. B1E3, the onset record;
2. B1E6 (V52): NPI→MT→UART progress counters, OSAL timer evidence and the live in-flight Stack dispatch;
3. B1E7 (V53): NV read-cache hits, misses and invalidations, and the eight NV items with the most driver time (IDs and counts only, never NV bytes);
4. B1E2;
5. B1E5 and B1E4, the 17 x 60-minute and 17 x 5-minute trend rings;
6. B1E1;
7. B1S1;
8. B1E2, B1E6 and B1E7 again, 1 s later, for the live Stack CPU profile, pipeline progress and cache hit rate;
9. one `SYS_PING`, which goes through MT, i.e. the Stack task.

All B1Q1 queries are answered by the priority-6 NPI owner, never the Stack task. The capture never resets, enters BSL, restarts the radio, sends a startup request, touches NV or starts a host. A first timeout latches the transport and ends the capture; the partial result is still written.

`result.json` labels the state. The labels are evidence, not a recovery decision:

| Label | Meaning |
| --- | --- |
| `NPI_OWNER_UNRESPONSIVE` | No B1 reply at all |
| `STACK_DISPATCH_STUCK` | One Stack dispatch has been in progress for at least 6 s (B1E6 names its service, input events and NV time) |
| `TIMER_ALLOCATION_FAILED` | An OSAL timer entry or Clock object could not be allocated |
| `TIMER_FREE_BACKLOG` | At least 64 expired OSAL timers are still waiting to be freed |
| `UART_OR_TRANSPORT_FAULT_LATCHED` | The NPI UART first-fault record is set |
| `MT_HANDLER_NOT_PROGRESSING` | MT stayed inside a command across both samples |
| `HEAP_EXHAUSTED_OR_FRAGMENTED` | Largest free heap block below 512 bytes |
| `STACK_SATURATED` | Stack task at least 90 % busy over the 1 s interval |
| `MT_PATH_UNRESPONSIVE` | B1 queries answered, `SYS_PING` not |
| `LOCAL_QUERIES_ANSWERED` | Everything answered locally |

`result.json` keeps every applicable label, most decisive first.

What to read in the B1E3 onset record:
- the first post-READY 10 s window with the Stack at least 90 % busy: top service and its input events, NV time, MAC request/confirm-failure/indication deltas, free heap, and whether a calm window preceded it;
- the first and the worst post-READY dispatch of at least 1 s, and the worst boot dispatch, each with the NV operations and NV time inside it;
- NV time per Stack service;
- OSAL heap free, low-water and largest block;
- Stack and NPI task stack high-water.

What to read in B1E7 (V53): V52 evidence showed NWK spending ~98 % of its time in NV reads, about one 10 ms NVOCMP scan per received frame. V53 serves exact repeated reads from an 8-line RAM cache that every NV write, delete, compaction or erase clears. A healthy V53 shows a hit ratio well above 0.9 and few, short read entries in the hot list. A low hit ratio, or a write item that dominates the hot list, means the storm source has moved and the hot list names it.

The trend rings show the buildup before the hang, per bucket: Stack busy, top service, longest dispatch, NV time, heap low, MAC data requests and confirm failures. The 60-minute ring covers about 17 hours.

Publish only sanitized counters. Keep the journal private.

## The physically successful no-power-cycle procedure

**These are controlled procedure requirements, not a paste-and-run shell recipe.** Use pinned, audited Python operator modules and fresh incident-specific, immutable private journals. Failure at any guard means **STOP, not retry**.

### A. Exact-device, security and policy preflight

- Match **SLZB-06P7U**, **CC2652P7**, SMLIGHT coordinator **USB coord_mode=2**, physical MAC, expected SLZB-OS version and pinned HTTP API source. Existing USB by-id path on the qualified unit: `/dev/serial/by-id/usb-SMLIGHT_SMLIGHT_SLZB-06p7U_SLZB-06p7U115236-if00` resolving to `/dev/ttyACM0`, baud 115200, `rtscts=false`. Never switch USB ↔ Ethernet as part of this operation.
- Confirm current Zigbee2MQTT is stopped/error, no active owner of that character device, other Zigbee2MQTT add-on stopped, host boot/manual, watchdog off, recovery guard `enabled=false`/`dry_run=true`/`serial_owner_approved=false`. Require a fresh approved database/coordinator backup and retained security/counter invariants. No backup replay is part of ROM recovery.
- Source-fingerprint the vendor firmware's actual `/js/httpApi.js` against the installed release and verified model/MAC, independently recheck control-opcode mapping. On **SLZB-OS v3.4.3.dev1 only**, the reviewed JS SHA-256 was `2d50552d71bf55f8f87aeabece9f4dae01d589d9e2e88699ec0b15e8e8e600ed`, with `API_CMD=4`, `CMD_ZB_BSL=2` and `CMD_ZB_RST=1`. These are **version- and device-gated**, not universal private commands. **Never** invoke `CMD_HARD_RESET=9`.
- Acquire the existing HA lifecycle/exclusive-port lock. Allocate a **new** incident operation ID. Before each side effect, write a private fsynced `CONSUMED_BEFORE_SEND` intent and fsync its directory. On ambiguous HTTP/SSH outcomes, inspect rather than replay. Vendor API throttle ≤1 request per second.

### B. Enter and verify the TI ROM bootloader — without writing firmware

- With no existing radio serial owner, **open only the pinned USB by-id at 115200 first**, through the exact-source `SafeFastUsbRom` / `p7u_rom_lowlevel` transport from the qualified release. Keep this temporary owner open through entry and verification. On 28-Oct, opening USB after BSL entry failed to obtain ROM ACKs; the writer's open-first order succeeded. The cause of that ordering dependency is unproven.
- Write the durable entry intent, then issue exactly **one** approved SMLIGHT management **Zigbee BSL entry** using the source-verified action (on this pinned OS, `/api2?action=4&cmd=2`). After settling, use the qualified bounded stale-byte drain and send one ROM SYNC. Require chip ID **`0xF000`**, then bounded read-only CRCs for APP sector0, paired AC000 and CCFG as appropriate. Expected CRCs come from the actual current verified write/image and protected-sector receipts, never a historical firmware guess. A management `ok` ACK alone does not prove ROM entry, and three sector CRCs do not prove full-image equality.
- **Always close the ROM UART before proceeding.** No erase, download, send-data, BSL re-entry retry, DTR/RTS probing or NV write. Failure to synchronize, unexpected chip ID, unexpected boot/CCFG or unexplained UART state is a STOP.

### C. Exit BSL to the **unchanged existing** R4 application

- After closing ROM, retained R4 that requires a native readiness handoff uses the qualified startup observer: open its temporary USB transport **before** application boot, with no Z2M owner. Write a fresh one-shot app-boot intent referencing the verified ROM receipt. Issue **one** identity-bound SMLIGHT Zigbee restart/application boot (qualified `CMD_ZB_RST=1`, or the matching verified native HA button).
- Observe a fresh SYS reset indication before submitting requests. Through the source-qualified operator, verify pristine B1 checkpoints and retained coordinator IEEE/key identity, then request existing-network startup once with formation denied. Require source-bound native READY, coordinator state9 and terminal marker proof. If READY was already observed but terminal verification was incomplete, use the qualified read-only completion phase; do not reset or submit startup again.
- Close the temporary startup UART before handing ownership to Z2M. A responding startup SRSP is request admission, not readiness: on 28-Oct it was followed by total status-response loss until ROM recovery. Do not repeat that request or silently substitute stock restore.
- Resolve installed APP+AC000 provenance freshly. The 27-Oct recovery used source `4cfe317`; the 28-Oct recovery used verified source `899f179` and host `acaa002`. Neither recovery wrote firmware, NV or CCFG. Detailed [28-Oct delivery evidence](https://github.com/analienx/Zigbee-Coordinator/blob/56d022c56979990a3768373659844cfaac6de45d/docs/r4/b4/F2_V43_PAIRED_DELIVERY_20261027.md) remains source-pinned.

### D. Start exactly one host and prove **real serving**

- Reconfirm port ownership zero and all recovery automation disabled. Write and fsync a **new** single-start intent before Supervisor starts the already installed host `local_p7u_r4_native_host` (27-Oct: `0.2.1-c5d8b0ce6fdf`). A Supervisor API call can time out while the container **has actually started**: inspect state and logs before any subsequent action; **do not repeat** the start on HTTP timeout.
- Require full herdsman startup past SYS/AF registration, `Zigbee2MQTT started!`, an authenticated MQTT connection and no fatal NPI/SRSP errors. Do not run another UART diagnostic owner concurrently.
- Independently sample a **read-only authenticated MQTT v5** subscriber on `zigbee2mqtt/+` using `retainHandling=2` (RH 2), discard `packet.retain=true` and broker bridge topics. Verify **new non-retained traffic from ≥3 distinct Zigbee device topics**. Initial Z2M startup publications alone are not sufficient evidence.
- For F2 v4.3 delivery, require three genuine minor3 records with all20 progress/all18 response-stage fields, advancing native sequence/counters and verified durable journal chain/manifest. Keep failed/skipped observations distinct from native zero. Ordinary recovery of an older ABI does not require unsupported minor3 fields.
- On **27-Oct**, initial service proof was24 fresh non-retained messages from5 device topics in5.7 seconds. On **28-Oct**, it was6 fresh messages from3 devices in1.243 seconds, healthy host/zero restarts, then3 durable native F2 snapshots. These prove initial service and diagnostics; they do not prove the startup or long-running SRSP hang cured.

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

The ROM round-trip is a proven restoration procedure and a causal localization clue. The underlying startup and long-running SRSP defects remain open; repeated resets or blind reflashing are not a diagnosis.

## Primary references

- [Physical recovery receipt, 27-Oct #143](https://github.com/analienx/Zigbee-Coordinator/issues/143#issuecomment-6438517051); [real R4 serving #161](https://github.com/analienx/Zigbee-Coordinator/issues/161#issuecomment-6422567271).
- [SMLIGHT official CC flasher bootloader invocation](https://github.com/smlight-tech/smlight-cc-flasher/blob/main/smlight_cc_flasher/command.py) (distinct network BSL operation); [TI ROM serial bootloader specification SWRA466E](https://www.ti.com/lit/an/swra466/swra466.pdf) (independent ROM firmware and UART SYNC/ID/CRC interface).
