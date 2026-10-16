# B2 finalization attempt — native capacity proven, full B2 source-ready BLOCKED

Date: 2026-10-16. Normative authority: issue
[#95](https://github.com/analienx/Zigbee-Coordinator/issues/95) and
[Annex A T01–T32](https://github.com/analienx/Zigbee-Coordinator/issues/95#issuecomment-6222647561).
Scope: read-only GitHub-hosted source/build validation, not an RF pilot.

## Exact provenance and measurable P0/P1 result

- Original sealed B0 SHA: `1baefbee8e4de2c9d28c5e1a7c339cf2025a2afe`.
- TI examples: `87ff5b638b632050228a7504f35cf3b95581c278`,
  SDK: `3615ad5d3f4f271258d18a2f5ce1785064ff9a58`;
  CCS 12.8, TI ARM Clang 3.2.2.LTS, SysConfig 1.21.1.3772.
- Independently successful P0 and P1 native jobs:
  [GitHub-hosted run 38962432494](https://github.com/analienx/Zigbee-Coordinator/actions/runs/38962432494),
  build checkout `4aa94b2ff8fdffc6d4657470375e88eabd9254d6`.
- Two independent P1 CCS native builds also passed on exact **same SHA**
  `f18d962af6b3976a196faf869ebca7d1609c80a5`:
  [run 38964092055](https://github.com/analienx/Zigbee-Coordinator/actions/runs/38964092055),
  P1 replicas artifact IDs **12074639024** and **12074539365**,
  both BIN SHA-256 `105fa0a3cf35d1ed0d25f42c2a7b68ce858144c9316c19011f9b05cb9ae2762e`;
  both ELF SHA-256 identical as below. P0 artifact ID **12074104151**,
  BIN SHA-256 `6bf9def769cbbdf41a7e876ec745a067fffc862b0ba6b4adc4acda1bc224748d`.
  Reproducible evidence is retained in checked-in
  `firmware/slzb-06p7u/r4/b2/B2_CAPACITY_BUDGET.json`.
  Separate native three-build comparison workflow still requires its own
  green result before claiming complete *exact-current-HEAD* proof.
- P1 ELF SHA-256:
  `54427f7e2712ba45b9f8f9ef5122aa88e946b0d210917992273083bf0fbd780d`.
- P1 exact ELF-linked symbols:
  `rtgSrcTable[192]` 1,536 B (8 B/entry);
  `neighborTable[64]` 1,792 B (28 B/entry);
  `rtgTable[128]` 1,024 B (8 B/entry).
  Other arrays preserved: AssociatedDevList 21×36 B,
  route-discovery 8×10 B and relay-list 12×2 B.
- Compared with native P0, changed tables consume exactly **3,488 B**.
  P0 linked heap address span **121,808 B**; P1 **118,320 B**;
  same 144-KiB SRAM region; C/IRQ stack unchanged **1,024 B**.
  This validates static linker geometry, **not runtime free heap**.
- B0's native image auditor remains green for P0/P1; generated UART,
  NV/CCFG boundaries, device/TC security and NPI owner are unchanged.
  No firmware is authorized for release/production flash.

## Mandatory acceptance checklist

| Gate | Status | Reason |
|---|---|---|
| Authentic TI source pins, CPP and linked counts | PASS P0/P1 | Native CCS builds + source-file SHA references |
| P0 original unmodified project capacity | PASS | Authentic six ELF arrays |
| P1 three route/neighbor capacities | PASS | 192/64/128 linked, +3,488 B; C/IRQ stack unchanged |
| Two same-SHA P1 independent native rebuilds and reproducible BIN | PASS AT f18d962a / NEW HEAD PENDING | Two actual independent native P1 BIN + ELF SHA-256 identical in run 38964092055, reverified from ZIP manifests; latest workflow comparison job pending |
| SRAM linker address space | PASS_STATIC_ONLY | 144 KiB and heap span measured; RTOS task-stack/dynamic usage UNKNOWN |
| Dynamic heap high-water, fragmentation, concurrent route buffers | BLOCKED | Requires runtime instruments; never invent zero/headroom |
| T02 direct-child 96 and TC 192 | BLOCKED B3 | Child/schema/persisted TC keys are not owned by B2 |
| P2 queue/retry/native latency reproducible benefit | BLOCKED | No source-backed failing scenario; TI routing source closed |
| P3 TI native SRAM-overbudget failing proof | IMPLEMENTED / NATIVE RUN PENDING | Disposable pinned TI `main.c`+`nwk_globals.c` forced-144KiB-BSS injection; CI must observe real TI linker `#10099-D` or FAIL |
| Annex A compiled actual-source hostile routing tests T05–T32 | PARTIAL T10 / REST BLOCKED | Actual pinned TI `zd_app.c` callback compiled under ASan/UBSan, negative source mutation killed in run 38966389472. MT parser T32 host actual-source suite pending. Closed `rtg.o` / `nwk_util.o` remain unavailable |
| P1 actual MTO source-cache behavior/route repair | BLOCKED | Static cache can remain unused depending on NV/runtime concentrator configuration |
| B1 HOLD_NV / HOLD_SECURITY no newly admitted MAC RF | BLOCKED | Separate draft B1 PR #93, unintegrated |
| Independent NWK, MAC/NPI, memory + challenger/Wonder reviews | NOT ATTESTED | No fake independent model PASS |
| Physical 106-node / 60+ router RF qualification | PHYSICAL_UNVERIFIED | Requires separate R4-07 authorization |

## Engineering disposition

**B2_STATIC_CAPACITY_NATIVE_PROVEN for the inspected exact checkout.**

**B2_SOURCE_READY = FALSE. B1_B2_INTEGRATED_READY = FALSE.
PHYSICAL_UNVERIFIED.** This is a **partial, safe source engineering result**,
not a completed routing/queue recovery phase.

Legitimate next branches:
- **Capacity-only engineering candidate:** keep P1 without a source-route
  behavior claim; same-SHA twin native rebuilds are already bit-for-bit
  reproducible at f18d962a. Inspect newest B2 workflow independently and
  seek genuine independent review before any merge/flash.
- **Full Annex A behavior qualification:** obtain TI-authorized full
  routing source or reshape the problem into a separate firmware
  architecture/scope decision explicitly approved in #95; no pretending
  that a mock exercises the proprietary C implementation.
- Do not alter B1 NV/security state, flash stock network or merge/release
  until the separate acceptance authority permits it.

See `TEST_MATRIX.md`, `B1_INTEGRATION.md`,
`KOENKK_R2_DELTA.md` and `B2_RESEARCH_ADR.md`.
