# B2 source code review and residual risk — 2026-10-17

**Review type: single-assistant code review, with CI and independent pinned
vendor/ELF evidence. NOT an independent Muse/Wonder/human reviewer PASS.**
PR [#96](https://github.com/analienx/Zigbee-Coordinator/pull/96);
authority issue [#95](https://github.com/analienx/Zigbee-Coordinator/issues/95).

## Reviewed files and scope

- Genuine TI 8.33 SDK source pin
  `3615ad5d3f4f271258d18a2f5ce1785064ff9a58`, examples
  `87ff5b638b632050228a7504f35cf3b95581c278`.
- B2 `b2_collect_native_evidence.py`, `b2_compare_native.py`,
  `b2_verify_profile.py`, `b2_compose.py`, `b2_capacity_gate.py`,
  `b2_p3_force_link_overbudget.py`, `b2_verify_p3_link.py`,
  `b2_scope_guard.py`, `b2_compile_actual_zdo_callback.py`,
  `b2_compile_actual_mt_parser.py`, and associated workflows/tests.
- Isolation: B2 edits imported CCS `Stack/Config/znp_cnf.opts` in disposable
  GitHub-hosted builds only; the PR contains no firmware release binary,
  flash tool invocation, NV/TC-security layout patch or second NPI/UART owner.

## Corrected issues from review

| Severity | Finding | Implemented countermeasure | Result/limits |
|---|---|---|---|
| HIGH | Native comparator allowed three builds from the same **wrong SHA** because it compared them only with each other | Mandatory exact 40-hex PR HEAD and GitHub run ID, compared to all three native receipts; independent binary/artifact digests now bound to the native extraction receipts | New hostile wrong-commit/wrong-run/mismatched receipt tests; exact-head native run required |
| HIGH | Comparator reported `unattributed_below_heap_delta_bytes` but accepted any difference | Require **0 unexplained** below-heap delta and **identical P1 linker partitions**; retain measured +3,488-byte table budget | Reject synthetic +8-byte unexplained change and inconsistent replicas |
| MEDIUM | JSON-only `b2_capacity_gate.py` returned ambiguous `BUDGET_ACCEPTED` for data supplied by the test caller | Rename outcome to `SYNTHETIC_BUDGET_ARITHMETIC_ONLY` and explicit flags that ELF and runtime heap have NOT been independently verified | Native proof only via audited CCS ELF/manifest and actual compare job |
| MEDIUM | ELF report called all profiles **B0** even when analyzing P1 binary | Rename metadata and human-readable report to P0/P1 authentic native linked evidence | No change to parsed ELF table bytes |
| MEDIUM | P3 native TI `#10099-D` overflow was incorrectly rejected because normal `tiarmlnk command failed` wrapper was treated as a separate compiler error | Require exact SRAM `0x24000` diagnostic, tolerate exact linker wrapper and reject other compiler errors/FLASH-only failures | Genuine P3 linker rejection **PASS** at [run 39001340291](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39001340291) |
| MEDIUM | Acceptance docs still reported historical P3/T32 as pending | Update normative T01–T32 and acceptance receipts | Always attribute results to tested exact SHA; new review HEAD must have new CI |
| LOW | B1/B2 sibling codepaths had no mechanical same-B0 path-conflict receipt | New read-only GitHub B1 draft PR #93 file/path comparison, ancestry check, overlap rejection | **Path-only** compatibility; no B1/RF admission integration proof |

## External routing evidence and caution

- Official [Zigbee2MQTT broadcast guidance](https://www.zigbee2mqtt.io/advanced/zigbee/02_improve_network_range_and_stability.html):
  large Zigbee meshes multiply broadcast traffic, so route-recovery
  broadcasts are not a harmless response to every failure.
- Official [TI Z-Stack routing overview](https://dev.ti.com/tirex/explore/content/simplelink_cc13xx_cc26xx_sdk_5_40_00_40/docs/zigbee/html/zigbee/z-stack-overview.html):
  routing entry needs differ from total network count; source routing
  and many-to-one topology are distinct from direct children.
- Pinned TI `nwk_globals.h:271–273` establishes
  `MTO_RREQ_LIMIT_TIME=1000` milliseconds. Actual ELF constant is 1000.
  `zd_app.c` callback forwards calls, but opaque `rtg.o` may throttle
  actual emitted requests. No evidence supports asserting 1000 broadcasts
  or adding new flood-prevention timers.
- Pinned `zglobals.h` defaults concentrator and route-cache disabled;
  `zglobals.c` can read NV overrides. P1 192 routes are genuine
  allocations, **not** proven active source-route caching.
- Community ["source routing"](https://github.com/Koenkk/Z-Stack-firmware/blob/master/coordinator/README.md)
  supports scaling motivation, not copying donor settings or a
  proof of improved RF reliability in this specific SDK/network.
- Verified linker says 192 source routes, 64 neighbors, 128 ordinary routes,
  plus only 21 associated-device slots. Direct children/TC security
  persistency remain B3-owned; 106 overall nodes is not 106 direct children.

## Review lanes (single assistant, *not* independent sign-offs)

**NWK/source routing:** authentic P1 table/limit proof; no editable TI
`rtg.o` / `nwk_util.o` bodies, so invalid relay lists, cache
eviction/in-flight reuse, stale routes, timeouts and timer wraps remain
untested in required real source. [TI-source blocker #101](https://github.com/analienx/Zigbee-Coordinator/issues/101).

**MAC/MT/NPI:** actual TI `MT_ProcessIncoming` and
`ZDO_ManytoOneFailureIndicationCB` compiled ASan/UBSan; their source
mutations killed, but parser stubs intercept only documented external
interfaces. No true UART backpressure/SRSP deadline/queue scheduler tests.

**Memory/CI:** P0 vs independent P1×2 identical BIN/ELF and static
SRAM accounting. P3 genuine native rejected. C/IRQ linker stack 1024 B;
RTOS dynamic task stacks, allocator peak and fragmentation **UNKNOWN**.
Actual P1 native image audit verifies pinout and vendor CCFG; no physical RF.

**Challenger (five nontrivial findings):** (1) table allocation != enabled
MTO route cache; (2) 10-second source-route expiry could dominate rather
than capacity; (3) max source-relay list remains 12 even when table has
192 entries; (4) indirect/security/TC limits aren't changed with P1;
(5) earlier P10 issues can't establish table exhaustion in CC2652P7.

## Final review disposition

**No APPROVAL for B2_SOURCE_READY.** Current completed work is
`B2_STATIC_CAPACITY_NATIVE_PROVEN`, `P3_NATIVE_OVERBUDGET_REJECTED`,
and limited real-TI-C T10/T32 host proof, all physical-unverified.
New exact-head CI must pass the comparator changes above. B1 PR #93
is still draft; read-only path conflict evidence does not close T29/T30.
Independent NWK, MAC/NPI, memory and challenger reviews, and separate
Wonder HIGH, are **NOT ATTESTED**.

Do not merge or flash in order to move forward; await [#101](https://github.com/analienx/Zigbee-Coordinator/issues/101)
or an expressly approved narrower capacity-only acceptance contract.
