# R4 B4 acceptance receipt — PR #100, issue #98

**Status 2026-10-17:** `B4_SOURCE_READY=BLOCKED`; `HOST_SOURCE_READY=BLOCKED`; `NATIVE_LINKED=YES (minimal experimental F0 and one counter only)`; `HOST_INSTALLED=FALSE`; `COMBINED_INTEGRATION=PENDING`; `PHYSICAL_VERIFIED=FALSE`; independent review `NOT AVAILABLE`.

**Evidence** (not deployment): real SDK CCS native build ×2 passed [39000883442](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39000883442); actual pinned herdsman 10.9.1 TS/Node tests passed [39001497672](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39001497672); source/hostile Python/hosted-C checks passed [39002225494](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39002225494), linked ELF delta verified there. Corrected strict parity oracle qualified on archived real CCS artifacts [39002075430](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39002075430). All 7 workflows PASSED at previous exact head `82c1ddb1e7cc948c274fc744434a97cb1c7cb9bc`, including [dual native parity 39004626220](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39004626220) and [19/19 pinned Node host tests 39004626233](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39004626233). A final host-only disconnect guard has been added on the next head (CR-14); that head requires its own concise CI receipt.

| Annex | State of evidence / blocker |
|---|---|
| D01 | HOSTED_NODE: actual Znp.request/Waitress ping SRSP + F0 owner path passed; real radio baseline unverified |
| D02 | HOSTED_PYTHON: source opcode collision mutants verified at exact source pin |
| D03 | PYTHON_ORACLE_PRESENT; native v2 reference only |
| D04 | HOSTED_NATIVE_LINKED: exact 132-byte v3 F0 handler and counter 4 in two genuine CCS ELFs; incomplete ABI remains |
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

Direct in-repo review (not independent peer approval), including CR-13 queued-F0 race fixed in pinned Node run [39004432505](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39004432505): [CODE_REVIEW_2026-10-17.md](CODE_REVIEW_2026-10-17.md). P0 stale F0 SRSP alias and pre-write orphan diagnostic waiter are guarded, plus P1 occupied normal Waitress; **17 compiled pinned-source Node tests PASSED [39003959612](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39003959612)**. The original 7/7 at `82c1ddb1` passed; final CR-14 amendment requires independent exact-head verification. Remaining P0/P1 issues are explicitly enumerated there.

- The **minimal experimental native F0 handler is truly linked** and reproducible; this is only one counter (`srsp_enqueued`). Missing native boot epoch, source digest, ABI minor/reset reason, UART accepted-versus-finished, AF confirm, B2 routing and B3 NV producer validity remain unresolved.
- **Two clean native builds:** GitHub Actions [39000883442](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39000883442), jobs `117303587721` and `117303587798`, both passed at `cf92fc07df7b25a7ad6bfbf380f6ae4b3c0dc5ca`. The *original inline* raw-XML comparison failed solely on nonsemantic `link_time`; the fixed strict comparator tested against both archived native artifacts passed on [39002075430](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39002075430), permitting **only** that one independently observed XML timestamp difference. Final integrated native Actions run remains a new gate.
- **Real linked B0→B4 allocated section delta:** +156 bytes FLASH app and +8 bytes RAM based on the same real ELF manifests, [39002225494](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39002225494). Runtime RTOS/IRQ stack high-water, NPI pressure and real AF/ZDO fairness are NOT_MEASURED.
- Upstream Zigbee2MQTT 2.14.0 source SHA `62b02e2aa1997c574223b80c196677b63a25f4a7` + its public extension boundary and herdsman 10.9.1 package dependency were independently checked in [39002832220](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39002832220). **This does not verify installed HA/Z2M versions.** Host pinned TypeScript and genuine `Znp.request`/waiter/active-mutex tests passed [39001497672](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39001497672). Opt-in in-memory AF/ZDO/SYS timeout observations are *source-tested*, not installed. There is no deployed Zigbee2MQTT 2.14.0 confirmation, disk worker integration, or independently validated USB observer.
- B1/B2/B3 combined integration and HOLD safety are still blocked by separate source-ready approval; no unauthorized cross-phase merges.
- No source-qualified radio epoch/no physical coordinator qualification. Independent four-lane reviewer sign-offs and >=5 independently reproduced blind-spot mutants remain unavailable.

**STOP / NOT READY.** Keep PR draft and unmerged. Do not flash, restart, access NV/keys or install host patches. Any later Actions should be recorded against their own exact head SHA.

**CR-14:** The already-queued experimental F0 must not issue a frame when the pinned `Znp.onPortClose()` marks its transport uninitialized before the AsyncMutex opens. Diagnostic-only `initialized` recheck inside the mutex; owner disconnect adversarial test added. Direct source evidence from pinned `znp.ts:87–90,243–249`; this does not affect normal control request admission, active Zigbee devices or any live host.
