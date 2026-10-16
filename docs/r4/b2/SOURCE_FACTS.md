# B2 source facts — TI SDK 8.33 pinned line ledger

All locations are from
`TexasInstruments/simplelink-lowpower-f2-sdk@3615ad5d3f4f271258d18a2f5ce1785064ff9a58`.
Values in this document are **raw source defaults**, not compiler-effective
values and not verified linked capacities. The conditionally included
`ti_zstack_config.h` and project/SysConfig precedence must be checked.

| Source item | TI declaration | Source location |
| --- | --- | --- |
| Source-route cache | `MAX_RTG_SRC_ENTRIES=12` | `source/ti/zstack/stack/nwk/nwk_globals.h:263-265` |
| Max relays per source route | `MAX_SOURCE_ROUTE=12` | `source/ti/zstack/stack/nwk/nwk_globals.h:305-308` |
| Neighbor entries (router) | `MAX_NEIGHBOR_ENTRIES=16` | `source/ti/zstack/stack/nwk/nwk_globals.h:202-207` |
| NWK device list | `NWK_MAX_DEVICE_LIST=20` (if not defined) | `source/ti/zstack/stack/nwk/nwk_globals.h:181-187` |
| Ordinary routes | `MAX_RTG_ENTRIES=40` | `source/ti/zstack/sysconfig/ti_zstack_config.h:187-192` |
| Route requests | `MAX_RREQ_ENTRIES=8` | `source/ti/zstack/sysconfig/ti_zstack_config.h:162-165` |
| Source route expiry | `SRC_RTG_EXPIRY_TIME=10` seconds | `source/ti/zstack/stack/nwk/nwk_globals.h:267-269` |
| NWK max retransmit | `NWK_MAX_DATA_RETRIES=2` | `source/ti/zstack/sysconfig/ti_zstack_config.h:172-175` |
| APS frame retries | `APSC_MAX_FRAME_RETRIES=3` | `source/ti/zstack/sysconfig/ti_zstack_config.h:167-170` |
| NWK queues (waiting/scheduled/confirmed/total) | `8/5/5/12` | `source/ti/zstack/stack/nwk/nwk_globals.c:93-97` |
| Indirect message max per child | `3` | `source/ti/zstack/stack/nwk/nwk_globals.c:118-122` |

Physical storage declarations (same pinned SDK):
`AssociatedDevList[NWK_MAX_DEVICES]` at `nwk_globals.c:149`,
`neighborTable[MAX_NEIGHBOR_ENTRIES]` at `:162`,
`rtgTable[MAX_RTG_ENTRIES]` at `:175`,
`rtgSrcTable[MAX_RTG_SRC_ENTRIES]` at `:177`,
`rtgSrcRelayList[MAX_SOURCE_ROUTE]` at `:178`,
`rtDiscTable[MAX_RREQ_ENTRIES]` at `:182`.

The compiled linker size of `rtgSrcTable` is **not** the same as the
number of relays allowed in one source route. Also, the `AssociatedDevList`
reserve includes a parent slot via `NWK_MAX_DEVICES = NWK_MAX_DEVICE_LIST+1`.
A network with 106 devices does not imply 106 direct neighbors/children.

**B2 memory facts still unknown:** actual active `#define` override tree,
TI structure `sizeof`, generated SysConfig, linked `.bss/.data`,
C/IRQ vs task stacks, dynamic allocation peak and fragmentation. Reconcile
against `B2_BASELINE_ELF_SYMBOLS.json` once the hosted native extractor
has completed; otherwise leave the requested P1/P2 sizing BLOCKED.

Source index and generated evidence are uploaded by the pinned-source
GitHub Actions workflow; see `DATA_ACCESS.md`.
