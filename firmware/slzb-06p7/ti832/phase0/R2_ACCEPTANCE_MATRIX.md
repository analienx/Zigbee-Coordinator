# R2 feature acceptance and remaining limits

The [36-row ledger](feature-parity.json) preserves the historical inventory. It records separate
source, native-linked, host-test and physical stages, evidence paths and a
decision for every historical F01-F17 / D01-D19 requirement. All physical
stages and release qualification remain unpassed. The original P10 numerical
and protocol targets remain visible rather than being silently rewritten to
match the P7 implementation. It is not a requirement to implement all 36 items.

## Essential scope and order

The first candidate needs recoverability, ordinary host/RF operation, existing
network functions and enough evidence to distinguish radio, transport and NV
failures. These are separate milestones:

| Milestone | Essential work |
| --- | --- |
| Before first write | Identify this unit; repeat stock/BSL entry; capture and independently copy its original state; verify a compatible stock recovery image/writer; inspect and explicitly prepare only the five NV pages. |
| Small disposable trial | ZNP/Herdsman startup, bidirectional RF, live concentrator settings, representative multihop commands, bindings/groups, battery polls/rejoin and read-only diagnostics. Then prove actual custom-to-stock rollback and original NV recovery. |
| Before household cutover | Resolve missing security relationships and counter floors, verify clean-restart persistence, then stage traffic toward the intended 60+ router/100+ device load and a stable 24-hour cohort. Watch delivery, host timeouts and free-heap trend. |
| Conditional capability | OTA testing before relying on OTA; association-slot broadcast tests before claiming 0xFFFF delivery to sleeping direct children above slot 31. Establish whether the real application requires that broadcast path. |
| Later, after recovery | Deliberate power cuts during writes/compaction. Do not make destructive injection on the only P7U a prerequisite to the first controlled trial. |

Keep the corrected source-route cache 192 and neighbor table 64. Retain the
existing 12-hop relay list, broadcast 9/queue 10, retries 2 and NWK buffers:
the historical larger numbers have no measured benefit yet. Defer heap walks,
retained previous-boot RAM, unsolicited trace streams, automatic reset loops
and full P10 diagnostic protocol parity. Add them only to answer an observed
failure which the small read-only health report cannot explain.

This is a single **unused** P7U, with the old network available from backup
only. Hardware actions need their concrete operator-controlled preflight.
Neither a source-only report nor a software package proves recoverability on
this unit. The RC1 tag and original private archives remain historical inputs.

## Firmware decisions

| Requirement | R2 decision | What remains |
| --- | --- | --- |
| F01-F02 version, extended ZNP/NV and multicast | Retain pinned TI ABI; repair reachable MT/NV/AF packet paths | Exact host startup/version, restored configuration and real group traffic |
| F03 capacity | TC 192, children 96, address-manager 298 derived, local bindings 4 | Live population, NV occupancy, real security relationships |
| F04 routing | Routes 128, source routes 192, neighbors 64, RREQ 16; retain 12 source relays | Native object/array checks, runtime NV/RAM, route-record and delivery trials; 16 relays deferred |
| F04 conflict records | Retain inherited 3, explicitly short of original 8 | Address-conflict recovery under realistic churn before changing it |
| F05 NWK buffers | Retain waiting 8 / scheduled 5 / confirmed 5 / total 12; original 16/8/8/24 is deferred | Queue saturation, held sleepy traffic and heap measurements |
| F06 heap | P7 automatic heap replaces P10 fixed 32 KiB | Current free-heap trend and observed delivery failures; deeper allocator profiling only if needed |
| F07 durable startup | NIB-before-ready plus preservation/counter guards implemented | Actual restart, restore and power interruption |
| F08-F12/F15 transport | Physical-idle distinction, ownership, bounded retries/fairness and parser recovery implemented | Actual bridge flow control, burst behavior and silent-failure recovery |
| F09 UART buffers | Keep pinned ISR 32 / TL 270 rather than copy P10 128/1080 | Measured overrun/latency/memory evidence before increasing |
| F13-F14 diagnostics | Separate P7 v1 snapshot and v2 health request; status counters and live concentrator values | Existing-owner host integration and real fault classification; P10 ABI is not emitted |
| F16-F17/D01-D06 storage/build | Strict image plans, pinned native builds, complete-driver fault/reopen tests, startup holds | Same-unit backup/rollback/NV restoration and silicon power-cut evidence |
| D07-D12 telemetry | P7 numeric recorder/strict decoder and bounded query replace legacy unsolicited DEBUG export | P10 event/site coverage is partial; closed-stack internals remain unavailable |
| D13-D16 retained AUX/A1 | Intentionally deferred; no speculative MMIO or production previous-boot retention | Proven ownership/reset/power domain before implementing retention |
| D17-D19 recovery/tooling | Separate app writer and backup-bound NV preparation/restoration, private inventory and independent software artifacts | Actual unit qualification; same-network migration is not established by inventory |

`verify_capacity.py` reads initialized bytes and allocated arrays from the ELF,
including the **12-relay constant and 24-byte relay list**. It also records
broadcast table 9 / queued broadcasts 10, local bindings 4, and linked NWK buffer
limits 8/5/12. The unused confirmed 5 constant is discarded by the linker and
is source evidence only. These are limits, not throughput measurements.

The current broadcast table 9, queue 10 and data retries 2 stay explicit. The
earlier 30/10/4 settings are a trial variant, not a presumed improvement: extra
queued messages consume dynamic memory, and retries/broadcast retransmission
can increase congestion. Test the existing values under combined traffic,
then compare a controlled variant using the same cohort, RF placement and
workload. Keep the variant only if delivery/latency improve without memory or
congestion regressions. A constant-size change cannot replace this evidence.

## Runtime concentrator verification

In the pinned SDK, `zglobals.c::zgItemInit()` restores existing NV values into
RAM. Compiler defaults 1/1/60 therefore cannot prove restored behavior. NV
items are enable 0x0032, discovery 0x0033, radius 0x0034 and route-cache 0x0036.

[`deploy/p7u_runtime_settings.py`](../../../../deploy/p7u_runtime_settings.py)
reads only these four public one-byte items through an injected callback from
the existing ZNP transport owner. It opens no connection and makes no write.
Its assessment requires both persisted values and the actual live RAM values
from the read-only health response: enable/cache/discovery/radius 1/1/60/10.
A missing RAM observation or mismatch fails the settings assessment. Matching
values still do not prove a many-to-one request, a route record, an occupied
cache or successful routed delivery. Observe those on the actual network.

## Sleepy broadcast limitation

The pinned available `nwk_globals.c` declares
`uint32_t bcastHoldAckMask[MAX_BCAST]`, while the R2 association list allows 96
children. The hold/delivery implementation is supplied in a TI library, so
expanding that array's element width in source would violate its ABI. No
binary patch or fake source reimplementation is introduced.

The inherited 32-bit limitation is a release gate for **0xFFFF broadcasts to
sleeping direct children**. A limit on the *number* of sleepy devices does not
prove their association slots fall below 32. Do not equate a join count with
the actual association index, or assume the 64-neighbor table changes the
mask's indexing. An [older TI FAQ](https://e2e.ti.com/support/wireless-connectivity/zigbee-thread-group/zigbee-and-thread/f/zigbee-thread-forum/902631/faq-cc2538-z-stack-3-0-2-known-issues-and-fixes)
documents a related closed-library defect and workarounds; it is historical
motivation, not proof of every detail in this exact SDK.

Qualify actual association slots 30/31/32/33/63/64/95 using sleepy polls and a
known 0xFFFF broadcast, including slot reuse and rejoin. Compare identical
unicast and 0xFFFC/0xFFFD controls. A failed upper-slot test prevents claiming
that sleepy broadcast capability; distribute sleepy devices across routers
and use addressed unicast where the application supports it. Such a policy
does not repair internal broadcasts or substitute for full capability proof.
If 0xFFFF delivery is required, release remains blocked until a supported TI
implementation or a validated source-level solution is available.

## Physical and end-to-end acceptance

The ledger's 18 named cases are a test catalogue, divided by the milestone
policy above. They are not all first-flash or first-release requirements.
Store raw network identity, keys, counters, captures and backup material
privately; publish only sanitized results and immutable source/artifact IDs.

| Case | Evidence for the relevant milestone/capability |
| --- | --- |
| RECOVERY/BACKUP/NV | Actual repeated BSL/stock entry, independent original-state capture, verified off-device copy, interruption/resume, deliberate five-sector preparation and original-NV restoration. Stock app rollback alone does not restore erased NV. |
| HOST/RF | Fitted board/bridge/SLZB-OS identity and actual UART/RF/clock/power compatibility; ZNP/Herdsman version/ping/AF/ZDO and AREQ behavior through one owner. Dashboard metadata is insufficient. |
| CONCENTRATOR/ROUTE | Trial: live NV/RAM and representative multihop delivery/rerouting. Later load: more than 12 active source routes and the intended 60+ router cohort. A cache size is not a hop count. |
| SLEEP32/SLEEPREJOIN | Association-slot boundary tests, sleepy polling and rejoin, RODRET and representative battery devices, parent loss and coordinator restart. |
| BIND/GROUP | RODRET-to-actuator direct bindings, coordinator bindings and Tuya router/breaker groupcast. Verify physical action, restart persistence and host-disconnected direct binding; the coordinator's four local binding entries do not limit remote binding tables. |
| OTA | Conditional: query/download/abort/resume while ordinary traffic continues, before relying on OTA. Preserve bindings and security state. |
| BURST/HEAP | Later load: combined ordinary traffic, AF errors, host latency and inexpensive free-heap trend. Largest-block scans and per-queue profiling are deferred unless failure evidence justifies them. |
| HEALTH | Read-only snapshots/counters via the owner, working traffic baseline, disconnect and still-connected nonresponsive scenarios. Require bounded detection/evidence and operator-controlled recovery; no automatic NV wipe or repeated reset loop. |
| MIGRATE | Private backup/device-DB/security relationship inventory; identify missing explicit keys/counters, preserve originals and prepare per-device re-pair fallback. A seed or device DB row is not proof of every relationship. |
| LOAD/POWER | Before cutover: representative group, then 10-20 devices, then intended cohort with at least 24 h stable traffic and rejoin. Ordinary restart persistence is essential. Deliberate write/compaction power cuts are later qualification after recovery. |

The migration inventory in `qualification/verify_z2m_backup.py` deliberately
counts coverage without certifying a same-network restore. Z-Stack may derive
some TC relationships from its seed, whereas a retained Ember backup can lack
individual security entries. Establish counter floors after the final source
transmission; copying an older counter from backup is insufficient. Re-pairing
remains the explicit fallback for relationships that cannot be reconstructed.
The existing NWK-key-change hold is not coordinated key-rotation qualification.

Hardware-specific observations cannot be completed remotely from source/CI.
The draft candidate stays unqualified for household cutover until its essential
milestones pass on this unit. Conditional/deferred features stay explicitly
unclaimed; they do not silently turn into mandatory implementation work.
