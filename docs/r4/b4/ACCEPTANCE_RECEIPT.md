# R4 B4 acceptance receipt — PR #100, issue #98

**Status 2026-10-17:** `B4_SOURCE_READY=BLOCKED`; `HOST_SOURCE_READY=BLOCKED`; `NATIVE_LINKED=YES (experimental SYS F0 with five queue metrics)`; `HOST_INSTALLED=FALSE`; `COMBINED_INTEGRATION=PENDING`; `PHYSICAL_VERIFIED=FALSE`; independent review `NOT AVAILABLE`.

**Evidence** (not deployment): real SDK CCS native build ×2 passed [39000883442](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39000883442); actual pinned herdsman 10.9.1 TS/Node tests passed [39001497672](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39001497672); source/hostile Python/hosted-C checks passed [39002225494](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39002225494), linked ELF delta verified there. Corrected strict parity oracle qualified on archived real CCS artifacts [39002075430](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39002075430). All 7 workflows PASSED at previous exact head `82c1ddb1e7cc948c274fc744434a97cb1c7cb9bc`, including [dual native parity 39004626220](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39004626220) and [19/19 pinned Node host tests 39004626233](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39004626233). A final host-only disconnect guard has been added on the next head (CR-14); that head requires its own concise CI receipt.

| Annex | State of evidence / blocker |
|---|---|
| D01 | HOSTED_NODE: actual Znp.request/Waitress ping SRSP + F0 owner path passed; real radio baseline unverified |
| D02 | HOSTED_PYTHON: source opcode collision mutants verified at exact source pin |
| D03 | PYTHON_ORACLE_PRESENT; native v2 reference only |
| D04 | HOSTED_NATIVE_LINKED: exact 132-byte v3 F0 and indices 0..4 native-linked in two CCS ELFs; only counter validity 0x1F/0x0C; incomplete boot/status ABI remains |
| D05 | UNIT_PRESENT; native unknown minor not representable |
| D06 | UNIT_PRESENT; no true hardware stream |
| D07 | HOSTED_PYTHON: strict event allowlist and symlink-race snapshot hardening; no installed recorder |
| D08 | REFERENCE_TEST_PRESENT; source-qualified wrap proof missing |
| D09 | BLOCKED unqualified radio epoch |
| D10 | BLOCKED trusted boot source absent |
| D11 | UNIT_REFERENCE only; native cannot qualify epoch |
| D12 | HOSTED_SYNTHETIC qualified/unqualified UART interval tests; native TX_FINISHED counter absent and no physical completion claim |
| D13 | HOSTED_SYNTHETIC accepted/finished equal still host receipt UNKNOWN; actual callback identity not proven |
| D14 | HOSTED_SYNTHETIC independent AF_CONFIRM after local SRSP timeout is not ZCL success; native AF_CONFIRM hook still missing |
| D15 | HOSTED_SYNTHETIC AF SRSP success + NWK_NO_ROUTE classified distinct from UART timeout; B2 real metric unintegrated |
| D16 | HOSTED_NODE: opt-in actual pinned Znp SYS timeout event captured; AF/ZDO in-memory source hooks, real incidents not captured |
| D17 | HOSTED_NODE: real AsyncMutex active lock AND actual Waitress pending entries block diagnostic; 200 simultaneous offers coalesce and 40 genuine in-memory pinned SYS_PING requests complete; no real UART/OTA/RF fairness proof |
| D18 | HOSTED_NODE: disabled, busy and explicit OTA suppression controls passed, real OTA pacing not tested |
| D19 | HOSTED_SYNTHETIC SIGTERM explicitly not crash; no live process evidence |
| D20 | HOSTED_SYNTHETIC USB detach disables F0 availability, prevents firmware attribution; host USB source not installed |
| D21 | HOSTED_SYNTHETIC serial-present MT nonresponse remains UNKNOWN cause, earlier last-good remains passive offline only |
| D22 | HOSTED_NODE: diagnostic timeout or sync write error removes waiter and quarantines transaction-ID-less F0; an independently queued second F0 is rechecked **inside** original ZNP AsyncMutex before writer, blocked after timeout; ordinary SYS_PING stays working; real load unverified |
| D23 | NODE_SOURCE existing owner only; second-client hostile test missing |
| D24 | SOURCE_PROVEN exact Zigbee2MQTT 2.14.0 upstream commit 62b02e2a declares herdsman 10.9.1, Extension base has no supported raw MT method; internal existing-owner patch only, installed release still UNKNOWN |
| D25 | HOSTED_PYTHON: pre-rename last-good survives; exclusive random temp files defeat predicted .pending symlink; post-rename fsync failure cannot guarantee pre-rename identity |
| D26 | HOSTED_PYTHON: I/O/fsync failure rejects; no production async worker |
| D27 | HOSTED_PYTHON + NODE: 256 event ring cap and dropped accounting |
| D28 | HOSTED_PYTHON: monotonic reversal rejected |
| D29 | HOSTED_PYTHON: duplicate waiter rejection, NODE diagnostic Waitress cleanup |
| D30 | HOSTED_PYTHON and NODE: strict raw-field rejection, metadata-only timeout ring and bounded retention; no deployment |
| D31 | HOSTED_SYNTHETIC replay verified with 64 AF/6 ZDO/69 downstream historical event counts; timeline offsets synthetic |
| D32 | HOSTED_SYNTHETIC P10 starvation replay; pre-reset F0 UNKNOWN |
| D33 | HOSTED_SYNTHETIC post-restart F0 replay; previous radio epoch UNKNOWN |
| D34 | HOSTED_SYNTHETIC detach replay, no firmware root attribution |
| D35 | HOSTED_SYNTHETIC B1 HOLD_NV/HOLD_SECURITY retains zero diagnostic RF authorization; real B1 integration BLOCKED |
| D36 | HOSTED_SYNTHETIC missing B2/B3 status stays UNKNOWN not zero; native sibling integration BLOCKED |

The `b4_inference.py` offline reference now has 15 adversarial cases ([staging run 39003058774](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39003058774)) spanning D12–D16, D19–D21, D35–D36 and privacy/counter validity. These are source-only synthetic categories, **not** native telemetry or independent peer approval.

## Five independent challenger scenarios (proposed, NOT reviewer-executed)

1. **Source collision alias:** TI defines decimal `240` instead of hex `0xF0`. The source verifier and mutant must detect the collision, not pass because of hex-only parsing. Countermeasure: revised lexical parser in `b4_verify_source.py`.
2. **Buffalo truncation:** `readBuffer(132)` on a 131-byte buffer silently returns a 131-byte slice. Countermeasure: source overlay exact-length check before read; actual pinned compiled Node negative test staged.
3. **Post-rename fsync crash:** `os.replace()` succeeds but directory fsync fails. Last-good target may have changed; never promise restoration of original after rename; report failure and require production I/O isolation.
4. **Host clock discontinuity:** `Date.now` jumps backward causing over-poll; use monotonic `performance.now()` 30s cooldown and no retries. Radio epoch remains independent.
5. **SERIAL owner leak through external cast:** plugin casts private `ZStackAdapter.znp` or constructs a second `Znp`. No external API permitted; native host overlay only on existing adapter. **Hard second-owner rejection test is still MISSING**—staged source test is not enough.

## P0/P1 blockers — do not waive

Direct in-repo review (not independent peer approval), including CR-13 queued-F0 race fixed in pinned Node run [39004432505](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39004432505): [CODE_REVIEW_2026-10-17.md](CODE_REVIEW_2026-10-17.md). P0 stale F0 SRSP alias and pre-write orphan diagnostic waiter are guarded, plus P1 occupied normal Waitress; **Prior 17 compiled pinned-source Node tests PASSED [39003959612](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39003959612)**. The original 7/7 at `82c1ddb1` passed; final CR-14 amendment requires independent exact-head verification. Remaining P0/P1 issues are explicitly enumerated there.

- The **minimal experimental native F0 handler is truly linked** and reproducible; this is only five source-qualified TX queue metrics (depth/HWM SRSP and ASYNC, plus `srsp_enqueued`). Missing native boot epoch, source digest, ABI minor/reset reason, UART accepted-versus-finished, AF confirm, B2 routing and B3 NV producer validity remain unresolved.
- **Two clean native builds:** GitHub Actions [39000883442](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39000883442), jobs `117303587721` and `117303587798`, both passed at `cf92fc07df7b25a7ad6bfbf380f6ae4b3c0dc5ca`. The *original inline* raw-XML comparison failed solely on nonsemantic `link_time`; the fixed strict comparator tested against both archived native artifacts passed on [39002075430](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39002075430), permitting **only** that one independently observed XML timestamp difference. Final integrated native Actions run remains a new gate.
- **Real linked B0→B4 allocated section delta:** +156 bytes FLASH app and +8 bytes RAM based on the same real ELF manifests, [39002225494](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39002225494). Runtime RTOS/IRQ stack high-water, NPI pressure and real AF/ZDO fairness are NOT_MEASURED.
- Upstream Zigbee2MQTT 2.14.0 source SHA `62b02e2aa1997c574223b80c196677b63a25f4a7` + its public extension boundary and herdsman 10.9.1 package dependency were independently checked in [39002832220](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39002832220). **This does not verify installed HA/Z2M versions.** Host pinned TypeScript and genuine `Znp.request`/waiter/active-mutex tests passed [39001497672](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39001497672). Opt-in in-memory AF/ZDO/SYS timeout observations are *source-tested*, not installed. There is no deployed Zigbee2MQTT 2.14.0 confirmation, disk worker integration, or independently validated USB observer.
- B1/B2/B3 combined integration and HOLD safety are still blocked by separate source-ready approval; no unauthorized cross-phase merges.
- No source-qualified radio epoch/no physical coordinator qualification. Independent four-lane reviewer sign-offs and >=5 independently reproduced blind-spot mutants remain unavailable.

**STOP / NOT READY.** Keep PR draft and unmerged. Do not flash, restart, access NV/keys or install host patches. Any later Actions should be recorded against their own exact head SHA.

**CR-14:** The already-queued experimental F0 must not issue a frame when the pinned `Znp.onPortClose()` marks its transport uninitialized before the AsyncMutex opens. Diagnostic-only `initialized` recheck inside the mutex; owner disconnect adversarial test added. Direct source evidence from pinned `znp.ts:87–90,243–249`; this does not affect normal control request admission, active Zigbee devices or any live host.

## Additional native NPI TX queue-pressure instrumentation — experimental phase continuation

Exact pinned TI SDK `npi_task.c` contains two synchronous and two async `Queue_enqueue` producer branches and one `Queue_dequeue` consumer for each. The guarded overlay adds current queue depth and peak HWM at those same pre-existing critical sections (counter indices 0–3); counter 4 remains `srsp_enqueued`. Provisional bitmap: `0x1F` with `NPI_SREQRSP`, `0x0C` without. Only emitted native bitmap bits are admitted by the patched host owner. New source and contract are not yet real ELF proof; prior native image SHA and memory delta must **not** be attributed to this amended overlay until its own real CCS links pass. Source-based queue count is not AF_CONFIRM, TX_FINISHED, boot epoch or causal evidence. This adds meaningful SRSP starvation pressure observability without changing scheduler priorities or defining a new ABI.

**Current confirmed evidence:** 2 × native CCS links + strict ELF/HEX/BIN parity PASS [39012416673](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39012416673); pinned real herdsman with two new gauge tests PASS [39012416638](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39012416638); hosted C ASan/UBSan branch PASS [39012416628](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39012416628), native pinned-source verification itself PASS but old one-field CI assertion subsequently rejected correct five-bit receipt. **Corrected old assertion** in the following commit; do not claim whole suite green until it runs again. No physical queue-pressure/stack evidence; B4_SOURCE_READY still BLOCKED.

## Remaining-issues priority decision (2026-10-17)

**Actual latest exact head:** `e1d2e488661333f64607f7dd32a7f1bb6d901fec`, 7/7 GitHub Actions green. The current native implementation source-qualifies counters 0–4 (SRSP/ASYNC queue depth and high-water plus SRSP enqueued); older counter-4-only statements in earlier sections are historical and must not be used as current acceptance evidence. No UART physical TX completion or radio reboot epoch is claimed.

**Next coding order, not another generic CI loop:** (1) Source-qualified boot identity and versioned ABI provenance using actual TI startup/reset source; fail closed if persistence/uniqueness cannot be proved. (2) Add UART2_EVENT_TX_FINISHED instrumentation only after confirming pinned SDK callback registration, ISR safety and no competing NPI transport ownership. (3) Resolve real existing-owner OTA admission from installed Z2M rather than caller-supplied boolean. (4) Bring B1/B2/B3 only through reviewed integration, then physical R4-07. Do not set absent counters to zero or treat FIFO handoff as TX-pin completion.

**Gate:** `B4_SOURCE_READY=BLOCKED`, `INDEPENDENT_REVIEW_NOT_DONE`, `PHYSICAL_UNVERIFIED`. Source/CI green is not permission to flash or merge. This section records prioritization only, not implementation of the remaining gates.

## CR-16 staged source patch — true UART2 TX_FINISHED event (not TX FIFO)

Sixth native field proposed at u32 counter index5, offset 52: `uart_tx_pin_finished_events` is the number of distinct TI `UART2_EVENT_TX_FINISHED` notifications (u32 saturates). Same pinned NPI `UART2_open` instance, no second owner. Native validity is `0x3F` when NPI_SREQRSP compiled or `0x2C` otherwise. All old status claims for index5 are superseded by this source candidate, but **native CCS linked verification is pending**, loaded-traffic and physical R4-07 still missing. The observation does NOT constitute per-command/host USB receipt nor a matched radio boot epoch. See `CODE_REVIEW_2026-10-17.md` CR-16 and TI `UART2.h` event callback source. No live device change.

## CR-17 source-level runtime OTA admission (stage: pinned integration check pending)

Pinned upstream Zigbee2MQTT **2.14.0**, source SHA \`62b02e2aa1997c574223b80c196677b63a25f4a7\`, maintains a private \`ExtensionOTAUpdate.#inProgress\` set tracking scheduled, automatic and manual OTA update/check work. B4 now supplies disposable, checksum/pin-guarded \`host/r4-b4/b4_z2m_ota_overlay.py\`, exposing **only** whether OTA work is idle. It adds a default-OFF/manual \`Controller.b4ProbeReadOnlyDiagnostics(enabled=false)\` which requires started/not-aborting Zigbee2MQTT, a connected/still-running pinned herdsman Controller, a started OTA extension, and an empty native OTA set. No public extension raw MT API is invented.

The patched internal herdsman Controller uses only its actual owned \`ZStackAdapter\`. It accepts a live read-only \`stillAllowed\` closure and passes it to the adapter; \`Znp.request\` reevaluates that closure **inside its already-existing AsyncMutex, immediately before UNPI transmission**. If OTA starts after initial admission but while SYS F0 waits behind a normal SRSP, the diagnostic is skipped with no UART write, no leaked waiter, no reset and no diagnostic poison. True ambiguous F0 transport errors retain diagnostic-only quarantine. No scheduled requests, second serial, MQTT writer, open/restart, NV or RF change.

Evidence gates: synthetic security mutations, genuine pinned herdsman TypeScript/Node and upstream Zigbee2MQTT TypeScript build are GitHub-hosted source tasks; do not report PASS until actual exact-head CI has succeeded. Installed HA/Z2M is **not** verified and remains untouched; loaded live traffic/OTA, independent review and physical proof remain BLOCKED. B1/B2/B3 remain unmerged; no radio boot epoch is invented.
