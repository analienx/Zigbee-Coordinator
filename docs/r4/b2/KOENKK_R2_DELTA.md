# R4 B2 exact Koenkk / older-R2 comparator — memory and behavior

**Comparator only.** TI donor pinned SDK 8.33 is not byte-identical to
Koenkk/Z-Stack-firmware commit
`5e4db67e550d41ea6dc6cd86ceeb04d82ffe1bfb`,
`coordinator/Z-Stack_3.x.0/firmware.patch` blob
`e015d9a9020e08d049515664693b22a9ce0e1fdb`.
Do not cherry-pick or treat community values as validated for the P7U.

| Domain | Native TI B0 linked | R4 B2 P1 source proposal | Koenkk comparison | Decision |
|---|---:|---:|---:|---|
| Source route entries | 12 | 192 | 250 | 192 first; C-API `uint8_t` index permits at most 255 |
| Neighbor entries | 16 | 64 | 50 | 64 candidate, only a subset of 60+ routers are physical neighbors |
| Regular routing entries | 40 | 128 | 150 | 128 candidate, no route exhaustion demonstrated |
| Router children NWK list | 20 + parent | unchanged | 75 + parent | B3/TC/NV owner; 106-network total does not mean 106 direct children |
| NWK waiting/scheduled/confirmed/total | 8/5/5/12 | unchanged | 48/30/30/72 | No queue allocation/high-water proof |
| MTO enabled, route cache, timer seconds | B0 source defaults false/false/0, persisted NV unknown | unchanged | true/true/60 | Changing MTO requires bounded control-traffic proof |
| Retry policies | B0 defaults | unchanged | higher MAC/NWK variants | Do not increase blindly; SRSP latency may worsen |

## Linked memory comparison

Actual B0 output symbols and sizes:

- `rtgSrcTable[12]`: 96 bytes → **8 bytes per entry**
- `neighborTable[16]`: 448 bytes → **28 bytes per entry**
- `rtgTable[40]`: 320 bytes → **8 bytes per entry**

Counterfactual capacity *using B0 8.33 structure sizes*:

| Scenario | Source-cache delta | Neighbor delta | Route delta | Combined table delta |
|---|---:|---:|---:|---:|
| P1 target (192/64/128) vs B0 | 1,440 B | 1,344 B | 704 B | **3,488 B** |
| Koenkk target (250/50/150) vs B0 | 1,904 B | 952 B | 880 B | **3,736 B** |

These are **not** measurements of Koenkk's compiled binary or runtime
allocation; its SDK and struct layouts may differ. They are merely
apples-to-apples table-count projections with our one *measured* B0 ABI.

Source route depth `MAX_SOURCE_ROUTE=12` is a **different** array;
increasing cache entries does not increase the allowable number of relays.
MTO/source-route caching must be enabled by the actual runtime config to
use a large cache; static 192 cells alone cannot reduce network churn.

TC/key and child-list resizing, extra route discovery slots and large
queue settings would be separate changes with independent validation,
not part of minimal P1. P2 (bounded queues/retry) stays blocked until
a pre-fix failing native C trace and a static/dynamic memory delta exist.
