# B2 effective MTO policy: native constant vs persisted NV

**Evidence: pinned public TI 8.33 source and actual B2 P1 ELF.** This is not live RF/NV measurement.

| Setting | Exact pinned source | Interpretation |
|---|---|---|
| `CONCENTRATOR_ENABLE` | `source/ti/zstack/stack/sys/zglobals.h:229–230` | Default `false`; runtime may override |
| `CONCENTRATOR_ROUTE_CACHE` | `zglobals.h:237–238` | Default `false`; allocation does not activate it |
| `CONCENTRATOR_DISCOVERY_TIME` | `zglobals.h:233–234` | Default `0` seconds; do not infer runtime |
| `zgConcentratorEnable`, `zgConcentratorDiscoveryTime`, `zgConcentratorRC` | `zglobals.c:159–162` | RAM initializers use defaults |
| `ZCD_NV_CONCENTRATOR_ENABLE`, `_DISCOVERY`, `_RC` | `zglobals.c:432–441` | Persisted NV can override initial settings |
| `ZDApp_ForceConcentratorChange` | `zd_app.c:1726–1740` | Reads NV and starts/stops NWK MTO timer |
| `gMTO_RREQ_LIMIT_TIME` | `nwk_globals.h:271–273`, `nwk_globals.c:208` | Genuine P1 ELF linked constant = **1000 milliseconds** |
| `ZDO_ManytoOneFailureIndicationCB` | `zd_app.c:3117–3125` | Every callback calls `RTG_MTORouteReq()`; closed RTG may enforce a limit |

Pinned SDK SHA: `3615ad5d3f4f271258d18a2f5ce1785064ff9a58`. Native linked ELF in [run 38964092055](https://github.com/analienx/Zigbee-Coordinator/actions/runs/38964092055).

**Important:** T10 real TI C host test forwarded 1,000 failure callbacks to 1,000 RTG API calls. It does **not** show 1,000 broadcasts; TI's closed RTG function may enforce the linked 1000-ms limit. TI explains that MTO route discovery is a broadcast and MTO failure recovery is an application decision in [its Z-Stack routing overview](https://dev.ti.com/tirex/explore/content/simplelink_cc13xx_cc26xx_sdk_8_32_00_07/docs/zigbee/html/zigbee/z-stack-overview.html).

## What is actually achieved

- P1 genuinely allocates 192 source routes, 64 neighbor entries and 128 ordinary routes. It leaves 12 source-route relays, 8 route-discovery entries and 21 associated-device slots.
- P1 **does not enable** concentrator routing or route caching, set discovery periods, touch the stored NV values, change network keys or alter B1 admissions.
- Therefore P1's large source-route cache may remain unused until an explicitly approved configuration phase confirms effective runtime MTO and route-cache policies; static capacity alone does not prove improved dense-mesh reliability.
- A new artificial callback cooldown is inappropriate without evidence of unbounded *actual emitted traffic*, especially when a linked 1000-ms RTG throttle constant already exists.

## Source-level routing admission hardening (draft, not in the sealed image)

The exact TI `ZDApp_ForceConcentratorChange` donor originally ignores failed
NV reads; draft B2 #114 verifies both reads before publishing concentrator
state, and stops the MTO timer on bad storage. The companion public
`ZDO_ManytoOneFailureIndicationCB` originally called `RTG_MTORouteReq()` even
with `zgConcentratorEnable == FALSE` or before the device is in an operational
coordinator/router state. The draft guard now returns without requesting MTO
in those cases, including stale errors after disable. Healthy, formed
concentrators still call TI's original RTG path immediately and retain the
SDK's own 1000-ms linked limit; no new retry, broadcast timer, NV policy,
heap allocation or queue is introduced. A source-extracted compiled-C
regression checks both negative conditions and the healthy caller, while
the unchanged donor fails the inactive-concentrator assertion. This is an
**API admission guarantee**, not proof of opaque RTG packet emission, eviction,
stale-route invalidation or reduced congestion.

An application-level 5000-ms cooldown was considered but deliberately
rejected: a host's 1000 callback invocations cannot establish 1000 RF
broadcasts, and suppressing valid network repair for extra seconds without
that evidence could make availability worse. This explicitly preserves the
previous source-evidence conclusion above.

## Safe future qualification

After B1 NV security seals, an independently authorized read-only target inspection could report current MTO enable/cache/discovery-time *without network identifiers or secrets*. B3 governs persisted TC/child tables. B2 source-only work does not authorize target access, NV writes, flashing, Zigbee changes or RF tests. Closed RTG internals remain a blocker in [issue #101](https://github.com/analienx/Zigbee-Coordinator/issues/101).

**Status: P1_STATIC_PROVEN; EFFECTIVE_MTO_NV_UNKNOWN; RF_UNVERIFIED.**
