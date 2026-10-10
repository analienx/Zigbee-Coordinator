# T832-MIN CAP192-RUNTIME — one offline candidate (2026-10-10)

Status: **OFFLINE ONLY / NOT_PRODUCTION_QUALIFIED / NO FLASH / NO NVS MIGRATION**.
Authority: [production profile #42](https://github.com/analienx/Zigbee-Coordinator/issues/42), runtime [#48](https://github.com/analienx/Zigbee-Coordinator/issues/48), and NV-loss incident [#53](https://github.com/analienx/Zigbee-Coordinator/issues/53). Based on draft PR #49 at commit `eca8e803163d29385a04cd28fe33b32f6c06180d`; preserves original firmware line and local backups.

## Distinguish capacity semantics

- **192 Trust Center device records** target potential total known Zigbee devices, not 192 simultaneous direct neighbors, 192 guaranteed live mesh nodes or proven 192-device throughput.
- **96 NWK device-list slots** are the coordinator-side device/child list, not the whole network size; provisional until observed child occupancy.
- **298 address-manager entries** are the *theoretical* TI relationship `96 + 1 + 4 bindings + 5 temporary TC + 192 TC`, not an empirically populated table.
- **13 pages × 0x800 bytes = 0x6800 bytes** in `0xF9800..0x100000`, consistent across compiler/linker/NVS. This does not prove NVOCMP free-space, compaction, or secure migration.
- **192 is upper-slot target**. No guarantee that any arbitrary composition of 192 routers/end devices will perform well, or that 64 direct neighbors can use the RF airtime simultaneously.

## Candidate changes over previous T832-MIN image

| Resource | Prior TI baseline/last explicit setting | Candidate target | How to check |
|---|---:|---:|---|
| Trust Center `ZDSECMGR_TC_DEVICE_MAX` | 192 | **192** | exact generated header |
| NWK device list | 96 | **96** | exact generated header |
| Address manager | 298 derived | **298 derived** | formula + inspect actual generated definitions |
| NVS pages | 13 | **13** | compiler + project + linker + HEX no-write audit |
| Binding table | 4 | **4** | exact generated header |
| Regular routing `MAX_RTG_ENTRIES` | 40 SysConfig default | **128** | exact generated header |
| Source route `MAX_RTG_SRC_ENTRIES` | 12 TI fallback | **128** | imported compilation options |
| Neighbor table `MAX_NEIGHBOR_ENTRIES` | 16 for router builds | **64** | imported compilation options |
| Concurrent route requests `MAX_RREQ_ENTRIES` | 8 | **16** | exact generated header |
| Maximum relays on one source route | 12 | **16** | imported compilation options |
| Conflicted-address records | 3 | **8** | imported compilation options |
| NWK waiting queue | 8 | **16** | exact patched TI source |
| NWK scheduled queue | 5 | **8** | exact patched TI source |
| NWK confirmed queue | 5 | **8** | exact patched TI source |
| NWK total buffer pool | 12 | **24** | exact patched TI source |
| OSAL heap manager | 6,144 bytes (verified on original candidate linked map) | **32,768 bytes** | linked `osal_port.o (.bss.heapmgrHeapStore)` size |
| Distinguishable ZNP SYS_VERSION | 20261010 | **2026101002** | pinned Herdsman ABI + actual 9-byte version |

Reason for change: on the *prior physical candidate* after a fresh power-up, the control plane remained responsive, while outbound messaging registered 144 status-16 SREQ rejections and 98 confirmed transport failures (38 MAC status 26, 60 NWK status 205); incoming messages were clustered among four source addresses. The new settings address candidate congestion/route-table pressure **hypotheses**. They do not establish that any single limit caused the faults.

## Implementation and proof

Single TI SDK 8.32.00.07 pinned source patcher; no new R10 SDK imports, alternate firmware family or self-hosted builder. The patch applies new `znp_cnf.opts` overrides, real `znp.syscfg` routing settings, and four `nwk_globals.c` constants. Expected SDK delta increases from 7 to 8 source files; TI example delta remains 2. CI fails if exact anchors, diff allowlists, generated macros or code revisions differ.

Hosted CI must produce actual CCS/ZNP OUT, MAP, Intel HEX and source-delta evidence, verify SRAM **unallocated** headroom >=128 KiB after allocation of the actual 32 KiB OSAL heap, and validate the imported compiler option file against the modified source. Note: SRAM unallocated according to linker is **not** free runtime heap; actual OSAL/heap usage, stack high-water and route/queue occupancy still require runtime instrumentation. Do not blindly enlarge limits again.

## Gates before any hardware use

1. Hosted CCS build and source checks green at the exact candidate SHA, with generated 192/96/4/128/16 macros, runtime overrides and NV+CCFG image protection validated.
2. Confirm compiled and linked memory budget including actual `MAX_NEIGHBOR_ENTRIES`, source-route entries and buffers; derive runtime heap and high-water (heap/stack) rather than using linker unused as proof.
3. On **isolated spare/disposable P10**, demonstrate bidirectional AF unicast and groupcast, inbound reporting, normal router join, cold start and NIB stability. Log successful `AF dataConfirm status=0` and no systematic status 16/26/205. Tests on a 2-device lab do not prove a 192-device load.
4. Separate validated 103-record security/counter and NVS preservation/rollback path per #53. **The `eraseNVM=0` flag alone is insufficient**, given documented prior NV loss. No mutation on household coordinator based solely on a green build.
5. Only after safely validated sacrificial lab operation, perform staged 60+ router and >=150-device soak/capacity tests where feasible, with measured resource occupancy and safe operator go/no-go. Never claim a production PASS from one source-level test.

No firmware packaging/deployment with new credentials, no Zigbee reset/re-pair, no HA service change, no network counter reset. Local identity/backups and real Zigbee security contents stay private.

## Critical review amendment (linked map evidence)

The first real linker image **passed**, but review of its exact `.map` found `osal_port.o (.bss.heapmgrHeapStore)` of `0x1800=6144` bytes. The unused linker SRAM was ~208 KiB, which emphatically **did not mean** the OSAL allocator could consume that unused space. This is a plausible route/AF allocation starvation mechanism and makes the first binary unsuitable as the preferred CAP192 candidate. Increase **only the pinned TI P10 project option** `-DHEAPMGR_SIZE=6144` to `-DHEAPMGR_SIZE=32768`; require real linker symbol `0x8000` and >=128 KiB unallocated SRAM. Retain `HEAPMGR_CONFIG=0`. The other 192/96/128/64/24 sizing targets and NV geometry remain unchanged. No physical heap high-water / fragmentation measurement exists; test on spare before any deployment.
