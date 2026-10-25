# P7U R4 — Firmware-first engineering priority policy

**Effective:** 2026-10-25 (Europe/Prague)  
**Applies to:** SMLIGHT SLZB-06P7U / TI CC2652P7, the retained Zigbee network, R4 firmware, the ZNP host interface, and associated issue/PR handoffs.  
**Decision:** Fix the fault; do not mistake recovery for remediation.

## Direction and precedence

**P0 engineering objective is a reliable R4 coordinator running the existing network, not repeated restoration of stock images.** This policy supersedes *priority ordering* in earlier recovery-first handoffs and work queues. It does **not** supersede any hardware mutation/safety gate, permission boundary, single-UART-owner rule, private-data restriction, or exact-image/security verification requirement.

Priority, highest first:

| Priority | Workstream | Completion criterion |
| --- | --- | --- |
| **P0 — establish failure mechanism** | Reproduce and localize loss of **local ZNP responses** (AF/ZDO/SYS SRSP, stateChangeInd, SYS_PING/startup) along host timing → USB/ESP32 → UART driver/DMA/ISR → TI NPI → MT/OSAL → stack task. Distinguish missing SRSP from Zigbee RF/NWK route failures. | A specific source-level or hardware/transport explanation supported by pre-fix evidence, with alternative hypotheses tested; unknown remains explicitly unknown. |
| **P1 — repair firmware and any proven adjacent transport defect** | Make minimal, reviewed changes to the failing source path, preserve TI routing/security behavior, add reproducing tests and negative mutants. Firmware source fixes are preferred to resets, fallback automation, new diagnostics, buffer inflation or speculative routing rewrites. | Measurable correction with regression/fault-injection evidence and no masked errors. |
| **P2 — qualify exact candidate** | GitHub-hosted genuine TI native builds, exact-source attestations, compatible APP + AC000 boot handoff, state-machine regressions, heap/RTOS/serial ownership where implicated, 106+ retained identities and independent NV/CCFG/counter safety reviews. | Exact-SHA review and test PASS, with unsupported claims explicitly excluded. |
| **P3 — one bounded, authorized hardware validation** | With the one existing coordinator and proven rescue capability, perform a separately approved trial; validate boot/state 9, local command acknowledgements under normal traffic, fresh device MQTT reports and a bounded soak before any map scan or stress. | Reliable ordinary mesh operation and fewer/no previously reproducible local ZNP failures; record baseline, new evidence, limits and failures. |
| **P4 — production safety recovery** | Restore a known-good operating state **only when needed** to preserve service/safety or unblock diagnosis, using the least disruptive admissible action. Keep previous APP/boot and recovery material ready as contingency, never as primary engineering deliverable. | Service restored *if necessary*, but firmware incident and P0/P1 remain OPEN. |

## Current facts that govern investigation

- On 2026-10-24, the earlier R4 build `2c6b23f` flashed/read back correctly yet timed out waiting for `AREQ - ZDO - stateChangeInd`; this is not a sector-write failure.
- The subsequent PR [#154](https://github.com/analienx/Zigbee-Coordinator/pull/154) candidate `2499154` has a proven source-side NPI UART-busy self-posting defect fix plus MT/OSAL error-path repairs. **Proven source defect does not establish that it caused the physical failure.** TI stack task priority 5 normally exceeds NPI priority 4; do not claim NPI alone starved that stack.
- The 2026-10-25 physical startup trial for that candidate obtained a valid source-matched diagnostic response and startup acknowledgement but subsequently had no diagnostic replies during the bounded observation. State 9 and successful network operation were not proven.
- After verified restoration of prior `3c7dd95` APP/boot, the startup observer also saw loss of responses. **Do not conclude PR #154 alone caused the failure; investigate shared startup, ESP/USB, radio state and host/driver interactions while repairing firmware defects.**
- A verified snapshot, boot ACK, green CI or successful roll-back is not equivalent to a functioning coordinator. Current live operation must be verified independently; older evidence must not be labeled current health.

## Mandatory triage / implementation rules

1. **No reflexive restore or blind retry.** First preserve logs and failure signatures, the last confirmed radio/app/host identity, UART holder state, diagnostic ingress/egress timestamps, and Z2M error sequence. Determine whether a specific non-destructive check can discriminate firmware code from ESP/USB/host failures.
2. **Prioritize active repairs, not expanding observability indefinitely.** Use existing F0/F2/host diagnostics only to answer targeted hypotheses. Do not create another forensic subsystem merely because one trial failed. Never equate absent or invalid counters with zero.
3. **Keep one serial owner.** No competing Z2M/BSL/diagnostic UART owner. No repeated stop/start loops, bootloader magic, NV replay, new pairing or radio factory reset as debugging shortcuts.
4. **Firmware mutation remains gated.** No fresh physical flash merely on policy priority change. Require a precise tested correction, pinned source/ELF/BIN/APP+AC000, fresh exact-radio current-state/security checks, immutable journal, independent image backup and explicit approved mutation scope. Preserve IEEE/PAN/extPAN/channel/keys/TCLK, live counters, NV and CCFG.
5. **Recovery only as a bounded safety fallback:** Prefer inspection and non-destructive state checks when possible. If an unusable coordinator threatens network continuity, a separately authorized least-disruptive service recovery may be performed, with matching exact-unit APP/boot evidence and zero protected-region mutation. Stop if safety prerequisites cannot be proven. Never treat restoration as task completion or close the defect issue.
6. **Acceptance is hardware-based:** true responsive local ZNP lifecycle, state 9, fresh multi-device traffic, no persistent AF/ZDO/SYS timeout and retained security across bounded observation/soak. Continue P0/P1 if ANY critical check fails. Document uncertainty instead of inventing a PASS.

## Concrete next engineering questions

- At the first failure, is UART TX completion/interrupt and RX parser responsiveness lost, is the MT request never scheduled/answered, or does the radio stack remain alive while its ZNP command path stalls?
- Does a verified ESP/USB control-plane restart change the outcome **with the same APP/NV**? This can discriminate transport/lifecycle from flash-content causes; a restart is diagnostic/contingency, not a permanent fix and still needs separate authorization.
- Do identical local command failures reproduce on both candidate and prior image under identical host/transport states? Document power/USB/Supervisor histories before claiming image-specific causation.
- Which exact source-level fix and negative regression distinguishes the failed hardware trace from a healthy one? Avoid an unbounded sequence of firmware candidate flashes.

## Issue/PR disposition

Keep the [R4 master #85](https://github.com/analienx/Zigbee-Coordinator/issues/85), [firmware reliability #95](https://github.com/analienx/Zigbee-Coordinator/issues/95), and [PR #154](https://github.com/analienx/Zigbee-Coordinator/pull/154) tied to the **firmware-first defect**. Do not describe the PR as hardware-accepted or restore as root-cause closure. Historical recovery runbooks remain available solely as contingency protocols. This policy itself authorizes **documentation/planning only**, not any physical coordinator action.
