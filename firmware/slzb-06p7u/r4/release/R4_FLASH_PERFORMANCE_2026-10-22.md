# R4 flash performance — measured bottleneck and safer fast path (2026-10-22)

**Single SLZB-06P7U, CC2652P7, 107 Zigbee identities. No hardware action authorized by this document.**

## Observed result (not an estimate)

- Fresh candidate `323949a95c9a07901c4ffc3d026fca414982c148`, verified by GitHub native runs `39801711808` and `39801711598`.
- The fresh duplicate 720896-byte ROM BSL capture completed in **234.91 seconds**; duplicate pass SHA256 `754efa3713ad227c1804447535386e8a03a91b6088d29d07ae332cb307d533ba`.
- Correctly reconciled preflight checked **107 original device identities**, retained security, monotonic counter floor and the genuine prior installed `2aca9c9` full APP+AC000 hash. Earlier stale `36aa811` baseline blocked before erase, correctly.
- **Actual flash stage: 494.27 seconds (8m14s)**, including 88-sector live admission *twice*, guarded programming and final 88-sector parity. Only **three** sectors needed changes: `0x6000`, `0xA000`, `0x1c000`; AC000 was already identical. The three writes/readbacks and final 88-sector parity all passed; NV and CCFG remained untouched.
- Exactly one boot and retained startup subsequently passed: `COORDINATOR_STATE9_MARKER_PASS`, actual state 9, marker `0x60=0x55`. Zigbee2MQTT USB traffic acceptance is separate and not yet established. Do not start Z2M until board is deliberately switched back to USB; the HA USB serial by-id path is already configured and must not be changed to TCP merely to fit flashing mode.

## Why the current writer is slow

The existing `r4_stock20260311_transition.py` calls `_observe()` in `admit()`, **then again** when `execute()` calls `admit()`, and finally once more for `FINAL_ALL88_PARITY`. These are **three full 704 KiB reads** through sequential max-240-byte ROM-BSL packets. Combined with the independent two-pass capture, this is roughly **five entire flash reads (3.44 MiB, ~15,020 240-byte read commands)** even if just 24 KiB of APP payload changes. Each read requires network/ESP/UART response latency. CRC32 protected-sector guards improved earlier 25-sector flashes but cannot eliminate those full transfers.

Vendor source (older CC2652P rather than our P7): https://github.com/smlight-dev/slzb-06-manual/blob/main/docs/guide/flashing-and-updating/updating-cc2652p.md reports about **3s direct USB**, **8min raw Ethernet**, and recommends web-managed update. Figures are historical examples, **not** verified SLZB-06P7U performance.

## Important live-device discovery: local staged Zigbee firmware path

Read-only inspection of the firmware JS served by this P7U's actual SLZB-OS (`/js/functions.js`) confirms `#customZBotaForm` uploads a local firmware file with `POST /fileUpload?customName=/fw.bin`, then invokes a distinct `flashZBstartProgress` flow with `local=1` and radio-flash API `API_FLASH_ZB`. It stages the file on the ESP32 and flashes locally, instead of streaming each TI BSL command across the Ethernet bridge. **No POST or flash action was sent.**

**Crucial unknown:** the ESP32's vendor flashing *implementation* is not established from its JavaScript. Neither NV-sector preservation, CCFG pinning, APP+separate-AC000 handoff semantics, boot-vector-last commit, negative-control refusal, nor readback parity can be inferred from an HTTP 200 or a displayed 'done'. The radio firmware updater is NOT the ESP32 SLZB-OS updater. The UI conditionally offers `eraseNVM` for EFR32, not for the TI radio; this is **not proof** that TI pages are untouched. Do not upload the project R4 APP-ONLY HEX or AC000 bin using this channel until the exact actual implementation and erase/write geometry are proven. Never supply a contiguous full-flash BIN with FF-filled NV/CCFG gaps.

## Recommended fast-lane architecture, in priority order

1. **Keep one-time controls out of routine updates.** Existing original coordinator backup / factory identity / 107-device inventory, original keys and security floor remain immutable. Every operation still requires a fresh retained-security counter check and an exact source-bound sector diff against the *actual* installed firmware, not a stale handover. Avoid rebuilding on Windows or repeating a passing GitHub native build.
2. **First choice if independently qualified: ESP-local staged custom Zigbee update.** Audit or experimentally prove on a non-production fixture the vendor ESP backend's precise address range, erase policy, custom firmware format, readback method, reserved/NV/CCFG preservation and its treatment of AC000. Require immutable local upload SHA256, matching compiled APP/handoff pair, explicit changed-sector plan, and postflash verified intact NV/CCFG. Fail closed when the backend cannot express the sparse R4 APP+AC000 layout. The user-reported seconds are a reason to investigate, not license to bypass the sole-device security requirement.
3. **Fallback: narrow verified ROM-BSL delta updates.** Retain full first-time backup; for later upgrades, double-read four NV pages and read actual changed APP/boot sectors; check monotonic network counters and all retained identities; use ROM CRC32 of unchanged 88 sectors as a fast *tripwire*, but record that CRC32 is not cryptographic SHA256 proof. Do not repeat full live admission twice within the same exclusive BSL session; allow a single admission with a session-bound identity and CRC/changed-sector revalidation before erase. Keep per-written-sector SHA readback, durable journal, CCFG protection and fail-closed uncertain-write behavior. Full 88-sector SHA readback remains a higher-assurance mode; skipping it is an explicit separate security/design decision, not an invisible optimization.
4. **Instrument, don't guess.** For each stage record source SHA, transport, source sector hashes, read count/bytes, ROM command count, UART baud, wall time, and per-sector verification. Benchmark read-only paths off the live network without reset. No flash, erase, BSL re-entry or repeated startup merely to benchmark.

## Approved mode handoff after current verified flash

The sole board is **currently booted as a verified state-9 coordinator**. The user explicitly wants to return it to **USB for HA/Zigbee2MQTT**, where its physical cable is already attached; the add-on is configured with the original USB by-id path. Do not change the add-on to Ethernet TCP, change USB mode early, reset/flash again, restore NV, or re-pair. Switch the P7U to USB once deliberately, confirm the USB by-id path reappears on HA, and perform one normal Z2M start and natural-reporting acceptance.
