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

## Verified production milestone — 2026-10-26 (not a stock rollback)

The **sole** SMLIGHT SLZB-06P7U / CC2652P7 is physically flashed with firmware source `4cfe317083c2a3d1b784350b0ab960e27218e618` and the matching APP/AC000. Its independently verified, single-use guarded write and boot operation is `0bd33ea656639db0e833961a6d0be4f6`; write admission covered all 88 ROM CRCs and **did not touch NV or CCFG**. The matching sealed operator/release source is `c30e29e3448ca71937272e420cba70e3884e5ae2`. Firmware CI **12/12** and operator CI **13/13** passed on the exact source SHAs.

**Production serving is physically evidenced, not inferred from a container being alive:** the sole Zigbee2MQTT owner started at 2026-10-26 **11:41:23 UTC**, with zero observed restarts after more than five hours; current-boot logs show `zigbee-herdsman started (resumed)`, coordinator identification and `Zigbee2MQTT started!` at **11:42:13 UTC**. A later read-only three-minute application-log sample contained **674 device MQTT publishes from 37 distinct devices and zero sampled application error/timeout lines**. A separate, authenticated MQTT v5 *passive* subscriber explicitly excluded retained deliveries and captured **24 non-retained messages from four devices in about two seconds**. This satisfies current-image *serving* acceptance, not a claim that all 100+ devices are healthy or that an independent simultaneous UART probe was performed. Some ZCL device ping/read errors occurred immediately after startup; handle persisting device-health failures separately.

**Causality precision:** the final source fixes a demonstrated defect that permanently latched the physical UART on recoverable outbound logical MT queue/allocation/TL errors. That code defect is established; whether it alone caused the failed `4021fff` field boot remains **unproven**. Previous `afbb7a8` and `4021fff` state-9/B1 diagnostics cannot be transferred to the current image as fresh physical measurements. Hardware acceptance derives instead from the current live application's completed protocol startup and non-retained physical-device reporting.

**Disposition:** [incident #161](https://github.com/analienx/Zigbee-Coordinator/issues/161) is closed on physical serving evidence; firmware [PR #162](https://github.com/analienx/Zigbee-Coordinator/pull/162) and source-pinned release [PR #164](https://github.com/analienx/Zigbee-Coordinator/pull/164) are ready for review. Legacy operator [#160](https://github.com/analienx/Zigbee-Coordinator/pull/160) and failed-image operator [#163](https://github.com/analienx/Zigbee-Coordinator/pull/163) were closed unmerged as superseded. **Do not merge the entire old feature stack into main without a deliberate integration review**: at acceptance, release source diverged from main by hundreds of commits/files. A merge/rebase is not itself physical serving qualification.

### Non-negotiable exact-source operator lessons

- **Running is not serving:** distinguish accepted firmware/boot receipts, Docker/Node health, completed herdsman/AF/ZDO startup, authenticated MQTT connection, and *new non-retained* device messages. Preserve UTC timestamps and measurement windows. An empty log-string filter is not evidence that traffic is absent.
- **One serial owner:** while the production Zigbee2MQTT process runs, no B1/F2/F3 serial probe, flash, BSL, DTR/RTS, second Zigbee stack, re-pair, reset or mode switch. Query current application logs and broker read-only; use a lifecycle lock before any later exclusive radio action.
- **Fresh installed-image provenance:** any future *separately justified* flash must derive its new installed baseline from the **actual most recent physically verified write operation**, not from an old stock snapshot or the already superseded `4021fff` image. Never recycle an expired/consumed flash or boot intent, copy an AC000 from another candidate, or modify immutable receipts.
- **Sealed ARM64 package:** require independently verified hashes before admission; maintain native security reader executable mode **0700**, and use `python3 -B` to avoid generating unsealed `__pycache__` under the sealed package. Keep raw ROM/NV, keys, credentials and private manifests out of GitHub issue/PR text and commits.
- **GitHub-first builds:** use exact-source GitHub Actions native builds and reviews, not local WSL by default. Do not claim a changed HEAD inherits the exact prior CI or hardware qualification; preserve pinned artifact/operation identities. Reserve recovery/stock restore for an independently justified safety fallback, never substitute it for a code fix.

---

## Historical investigation facts (2026-10-24/25; NOT the current serving state)

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
6. **Acceptance is hardware-based:** require proven current-image complete Zigbee2MQTT/herdsman protocol startup and fresh non-retained multi-device MQTT traffic, absence of fatal UART/AF/ZDO/SYS faults and preserved security. A directly queried ZDO state 9 may provide additional evidence **only when UART ownership makes it safe**; never steal the running production serial port for a second host. Do not infer servicing from container running or older-build state 9. Document limits instead of inventing a PASS.

## Questions only if a new failure is actually reproduced

- At the first failure, is UART TX completion/interrupt and RX parser responsiveness lost, is the MT request never scheduled/answered, or does the radio stack remain alive while its ZNP command path stalls?
- Does a verified ESP/USB control-plane restart change the outcome **with the same APP/NV**? This can discriminate transport/lifecycle from flash-content causes; a restart is diagnostic/contingency, not a permanent fix and still needs separate authorization.
- Do identical local command failures reproduce on both candidate and prior image under identical host/transport states? Document power/USB/Supervisor histories before claiming image-specific causation.
- Which exact source-level fix and negative regression distinguishes the failed hardware trace from a healthy one? Avoid an unbounded sequence of firmware candidate flashes.

## Issue/PR disposition

The R4 [master #85](https://github.com/analienx/Zigbee-Coordinator/issues/85) and [routing #95](https://github.com/analienx/Zigbee-Coordinator/issues/95) track broader engineering; the specific [P0 serving incident #161](https://github.com/analienx/Zigbee-Coordinator/issues/161) is **closed on current-image physical evidence**. Keep historic [PR #154](https://github.com/analienx/Zigbee-Coordinator/pull/154) and earlier failure timelines attributed to their own firmware epochs. The exact accepted firmware [#162](https://github.com/analienx/Zigbee-Coordinator/pull/162) and release [#164](https://github.com/analienx/Zigbee-Coordinator/pull/164) require a separate integration/dependency review before main. Historical recovery runbooks remain contingency protocols, not root-cause remediation. **This policy authorizes documentation/planning only, not any new physical coordinator action.**
