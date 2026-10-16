# B2 Annex A T01–T32 actual evidence matrix — fail closed

As of 2026-10-16. Normative matrix is issue #95 comment
[6222647561](https://github.com/analienx/Zigbee-Coordinator/issues/95#issuecomment-6222647561).

**DO NOT equate passing Python fixtures, authentic ELF static sizes, or hosted
CCS compiling with an actual compiled-source routing C adversarial test.**

Compiler source: TI examples `87ff5b638b632050228a7504f35cf3b95581c278`,
TI SDK `3615ad5d3f4f271258d18a2f5ce1785064ff9a58`.
Baseline: merged B0 `1baefbee8e4de2c9d28c5e1a7c339cf2025a2afe`.

Archive attribution: authentic TI linker XML maps core route APIs to
`libZStack_nwk_all.a::rtg.o` and `::nwk_util.o`; pinned public SDK 8.33
does not contain their underlying modifiable routing C implementation
bodies. TI's [exact 8.33 SDK manifest](https://software-dl.ti.com/simplelink/esd/simplelink_cc13xx_cc26xx_sdk/8.33.00.16/exports/manifest_simplelink_cc13xx_cc26xx_sdk_8_33_00_16.html)
classifies Z-Stack as binary and limited source.

| Test | Scenario | Actual disposition | Evidence/blocker |
|---|---|---|---|
| T01 | B0 linked table/byte baseline | HOSTED_NATIVE_LINKED | Six true ELF symbols with byte sizes, native CCS run 38952302280; repeated historical acceptance run 38957349766 |
| T02 | P1 192/64/128 plus 96 direct children | PARTIAL_PENDING | P1 native build and memory compare in flight; child 96 intentionally excluded as B3/NV/child-schema concern |
| T03 | P2 queue and relay peak | BLOCKED | No source-backed capacity/replay/peak or bounded queue failure yet |
| T04 | P3 actual SRAM-overbudget image | HOSTED_SYNTHETIC_ONLY | Python negative budget control exists; actual TI CCS linker overbudget proof not supplied |
| T05 | Full neighbor admission | BLOCKED_TI_INTERNAL_C | Closed NWK lib routing/neighbor behavior; no actual-source C sanitizer harness |
| T06 | Source cache saturation/in-flight eviction | BLOCKED_TI_INTERNAL_C | Closed rtg.o; no actual C bodies |
| T07 | Source-route failure stale invalidation | BLOCKED_TI_INTERNAL_C | Closed routing-body failure call path; no pre/post fix |
| T08 | NWK_NO_ROUTE return and AF status | BLOCKED_TI_INTERNAL_C | Cannot equate SRSP with on-air MAC; no compiled native hostile trace |
| T09 | RREQ retry/discovery timeout | BLOCKED_TI_INTERNAL_C | Closed rtg.o; no timer proof |
| T10 | MTO cadence and broadcast boundedness | PARTIAL_HOSTED_REAL_TI_C_ASAN | [Real pinned `zd_app.c` callback ASan/UBSan + killed source mutation](https://github.com/analienx/Zigbee-Coordinator/actions/runs/38966389472); 1/2/1000 failure callbacks produce 1/2/1000 calls to stubbed RTG boundary; *no* closed RTG, timer or actual RF proof |
| T11 | Source relay hops 0/1/max/too long | BLOCKED_TI_INTERNAL_C | Closed RTG_ValidateSrcRtg; no harness |
| T12 | Duplicate/self relay and malformed NWK16 | BLOCKED_TI_INTERNAL_C | Closed route-validation implementation |
| T13 | Cache eviction during AF enqueue | BLOCKED_TI_INTERNAL_C | Closed rtg.o ownership/lifetime |
| T14 | Late MAC callback after AF timeout | BLOCKED | No synchronized compiled-source MAC/NPI test |
| T15 | Duplicate NWK statuses and stale callbacks | BLOCKED_TI_INTERNAL_C | No compiled closed RTG/NWK replay |
| T16 | SYS_PING fairness under full queue | BLOCKED | No actual-source queue backlog harness |
| T17 | AREQ storm and AF SRSP fairness | BLOCKED | No actual-source queue backlog harness |
| T18 | Neighbor+route+source simultaneous saturation | BLOCKED_TI_INTERNAL_C | Static bytes linked only; no runtime allocator/route acceptance trace |
| T19 | Allocator NULL every source site | BLOCKED_TI_INTERNAL_C | No instrumentation into closed RTG allocation paths |
| T20 | APS fragmentation and malformed MT sizes | BLOCKED | No actual compiled MT/NPI flow harness |
| T21 | Sleepy device indirect queue fair scheduling | BLOCKED_TI_INTERNAL_C | No actual-source indirect scheduling proof |
| T22 | Parent-announcement and child aging | BLOCKED_TI_INTERNAL_C | No tested routing lifetime/children ownership |
| T23 | Rejoin short-address migration | BLOCKED_TI_INTERNAL_C | No live-source cache invalidation test |
| T24 | 106-node / 60+ routers synthetic churn | BLOCKED | No compiled-source topology test; no physical soak claimed |
| T25 | MAC7/NWK4 alternative retry comparison | NOT_IMPLEMENTED_BY_DESIGN | B0 retry policy retained; no failure reproduction justifies increase |
| T26 | Source cache 192 vs 250 comparison | PARTIAL_LINKED_SIZE_ONLY | 192 capacity expected vs 250 community donor; no cache churn/fairness evidence |
| T27 | MTO enabled vs disabled deterministic workload | BLOCKED | No comparable compiled source/radio-control workload |
| T28 | 32-bit timer wrap under retries/expiry | BLOCKED_TI_INTERNAL_C | Closed NWK route timeout internals |
| T29 | B1 HOLD_SECURITY/HOLD_NV mid-send | BLOCKED_B1_INTEGRATION | B1 PR #93 draft; must verify zero newly admitted RF after hold |
| T30 | Healthy B1 NETWORK_READY | BLOCKED_B1_INTEGRATION | Separate combined exact-source worktree/CI not built |
| T31 | OTA-like AF and route storm SRSP deadlines | BLOCKED | No compiled source host MT queue/latency trace |
| T32 | Malformed MT during route failures | BLOCKED | No compiled parser/RTG concurrent hostile harness |

## Native and synthetic controls

- P0 native compiled and ELF linked: **PASS** in runs
  [38952302280](https://github.com/analienx/Zigbee-Coordinator/actions/runs/38952302280)
  and [38957349766](https://github.com/analienx/Zigbee-Coordinator/actions/runs/38957349766).
  P0 six physical arrays' effective counts/sizeof and 144-KiB SRAM verified.
- Host Python arithmetic/ELF/overlay/profile negative oracles: hosted
  **synthetic**, not native routing behavior. 31 tests passed before the
  comparator expansion. Exact last CI run is authoritative.
- B2 T10 callback ASan/UBSan source-run and source mutation: real
  `source/ti/zstack/stack/zdo/zd_app.c` function body compiled at pinned
  SDK SHA (hosted run 38966389472), only opaque `RTG_MTORouteReq()` API
  stubbed. This proves direct repetition and absence of a local callback
  cooldown, **not** on-air MTO cadence or closed routing behavior.
- P1 new native CCS binary and two independently linked replicas:
  status governed only by the latest green linked-profile and binary
  reproducibility workflows, **do not treat this document as a PASS claim**.
- P2 deliberate deferral; P3 hosted synthetic negative only.
- No source mutation test can legitimately target proprietary TI RTG
  C body unless a lawful complete source baseline becomes available.
  Stubbing the *algorithm* would not count; a stub is allowed only at
  API-boundary radio/RTOS interfaces.
- P1 may prove memory feasibility but not MTO cache effectiveness:
  runtime `zgConcentratorEnable`, persisted NV, host coordination and RF
  all remain separately qualified.
- B1 PR #93 not merged; B1 HOLD_NV/HOLD_SECURITY MAC send gate
  and B3 TC/child capacity changes cannot be silently adopted.

**Outcome: B2_SOURCE_READY = BLOCKED.** This matrix deliberately preserves
every unmet contractual obligation instead of relabeling it N/A or PASS.
