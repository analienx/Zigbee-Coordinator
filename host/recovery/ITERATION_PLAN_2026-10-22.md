# Recovery-only P7U iteration — 22 October 2026

**Current scope is fixed:** solve reliable **detection, automatic recovery and crash evidence** for one production SLZB-06P7U, whether it runs stock CC2652P7 Zigbee firmware or custom R4. No routing feature additions, NV tuning, random resets, generic flasher, stack migration, battery-device re-pair campaigns or broad new research project.

## Physical checkpoint

- R4 `323949a` ran on 107 retained Zigbee identities but progressively hung AF/ZDO/UTIL/SYS after ~15m. Root cause **UNDETERMINED**, stock 20260310 suffered comparable symptom after ~35m.
- SLZB Zigbee radio restart `action=4&cmd=1` at 19:49:37 + exactly one Z2M start **FAILED** at `AF register`. Do NOT declare an HTTP reset acknowledgement a recovery pass.
- One SLZB ESP restart `action=4&cmd=3` then one Z2M start succeeded at 19:56:34–38; 106 used-entry joined rows, 107 saved identities, MQTT reports flowing.
- **20:06 check:** Supervisor `started`, 1,037 post-recovery non-bridge-topic publications; last listed startup pings/errors at 19:58:54. No observed later fresh SRSP failure during that 7-minute quiet period. Long-duration acceptance **not** established.
- Independent SMLIGHT management survived the crash and HA showed no USB detach before recovery. The ESP restart re-enumerated CDC tty. No true physical power cut, NV replay or flash was necessary.

## Four steps, strict sequencing

### P0 — Physical incident recovered (COMPLETE), incident preserved

One radio restart + failed owner reconnect and one ESP reboot + successful owner reconnect are locked in private audit receipts. Keep the current Zigbee2MQTT installation and USB by-id config. No more physical recovery activity for benchmarking.

### P1 — Shared stock/custom host watcher (IN PROGRESS; #143, draft PR #146)

- Source-only completed: `policy.py` fail-closed two-sample detection and fault-type classification, `executor.py` exclusive durable one-shot shell, offline hostile tests and GitHub Actions. No live actuator yet; not installed/armed.
- Build ONE HA-hosted, restart-safe owner; preferably a minimal separate HA add-on/service that uses the **official SMLIGHT integration Zigbee Restart/Core Restart buttons**, existing Supervisor add-on state/start/stop, and per-device **non-retained** MQTT signals. No ZNP/tty opening.
- If native buttons not provisioned, a source- and SLZB-OS-version-fingerprinted local-web fallback may map only `cmd=1` radio restart and `cmd=3` ESP restart; no `cmd=9` hard reset.
- Dry-run against saved 16-Oct stock and 22-Oct R4 logs: must predict the real SRSP cascading failure while refusing resets for normal post-boot `NWK_NO_ROUTE`, broker downtime, planned HA/app stop, single device offline, OTA, flash, join activity alone or missing USB/mode evidence.
- Explicitly enable after independent code review + bounded live dry-run. Once armed: exactly-once quieting of Z2M, save sanitized F2 (when R4 has it) or host log evidence, radio restart, once Z2M startup and **real network traffic** checks, then a single ESP restart + single startup if radio stage fails. 120s stability threshold, 6h cooldown, maximum 2 radio resets/day, no response replay. If still failed, alert and HOLD; no automatic factory reset, power cycle or flash.
- **Gate P1:** independently tested physical success/failed path, complete event report and no false reset in 107-device real workload. All unsupported host assumptions = NO ACTION.

### P2 — R4 firmware instrumentation must actually be observable (NOT YET COMPLETE; #144)

- Use existing **canonical B4 F0 132-byte + F2 160-byte nonce response** in final native composite; first validate source SHA and actual binary, not only past CI green.
- Deploy the existing-once-owner Zigbee2MQTT/herdsman F2 client to the **actual** running add-on using a properly maintained versioned build (NOT ad hoc node_modules mutations, second serial client, raw UART sniffer or separate conflicting MQTT service).
- Add bounded idle-state sampling (30–60s typical; none during OTA), first-error snapshot when possible; durable fsync/atomic redacted last-good history on HA, preserved across coordinator/Z2M failure. No security or raw packet payloads.
- Physical proof BEFORE enabling automatic R4-fault reproduction: a series of real F2 snapshots under normal 107-device load, validity bits, monotonically coherent native counters, real source-bound radio boot metadata and lack of material latency regression.
- **Gate P2:** data from *before* a real SRSP failure separates NPI dispatch, SRSP queue, UART TX finished, AF confirm and heap/RTOS pressure at least as far as the firmware can observe. If F2 is itself stuck, label UNKNOWN; a last-good snapshot cannot conclusively identify a crash locus.

### P3 — Stock-only reliability experiment (BLOCKED pending P1; #145)

- Preflight exact suitable SMLIGHT stock image version (20260310/20260311 provenance), NV layout compatibility, vendor ESP build, flash geometry and current *source-bound* original network/security/counter backup. If incompatible with custom four-page NV4, do not flash in place and assume preservation; require approved offline migration.
- Switch radio to genuine stock only with separately reviewed backup, atomic security/counter and network identity guards. Shared HA recovery watcher MUST work unchanged without F0/F2; no parallel 'stock watchdog'.
- Seven-day initial stock acceptance with host-side health/SRSP window metrics and independently verified recovery; 30-day follow-up for real-world reliability. Don't call frequent auto-resets a root-cause fix or equate 'not crashed in 7 days' with robust MTBF. Keep custom R4 failure analysis in #144 independent.

## Power-cycle decision

**A third physical power-cycle escalation is not implemented or approved** because the board can be powered through USB and PoE; cutting one source may not remove power. If a genuine dual-rail-controlled power cut is ever needed, require independently powered non-Zigbee PDU/PoE/USB control and positive supply-drop telemetry, explicit fresh user authorization and cooldown. Default state is **no further action + alert** after one failed radio and one failed ESP sequence. The 22-Oct incident recovered without this tier.

## Decision after initial soak

- Shared watcher succeeds + stock stable: stock can be default; continue R4 native diagnosis separately only when explicitly scheduled. This prioritizes reliability over custom firmware features.
- Shared watcher succeeds but frequent hangs: workaround operates but reliability is still failed; use crash-time R4 counters and possibly alternate supported hardware if economically justified.
- Any network security identity/counter regression: immediately stop automation and all flash experiments; preservation outranks uptime.
- Never report 'complete' based on source CI, HTTP 200 reset response, Z2M container status or previously retained MQTT topic. Only current Zigbee2MQTT herdsman start + genuine fresh device reports + sustained operation count.

## Source references
- [#143 common watchdog](https://github.com/analienx/Zigbee-Coordinator/issues/143)
- [#144 R4 live F0/F2 diagnostics](https://github.com/analienx/Zigbee-Coordinator/issues/144)
- [#145 stock-only acceptance](https://github.com/analienx/Zigbee-Coordinator/issues/145)
- [#98 canonical B4](https://github.com/analienx/Zigbee-Coordinator/issues/98)
- [Physical log comparison](https://github.com/analienx/Zigbee-Coordinator/blob/f766f77/firmware/slzb-06p7u/r4/release/R4_FIRST_LIVE_Z2M_FAILURE_FORENSICS_2026-10-22.md)
- [SMLIGHT HA integration](https://www.home-assistant.io/integrations/smlight)
- [SMLIGHT internal API caveats](https://smlight.tech/support/manuals/books/slzb-os/page/slzb-os-api-endpoints)
- [Comparable P7 AF/ZDO failure + recovery](https://github.com/Koenkk/zigbee2mqtt/issues/32837)
