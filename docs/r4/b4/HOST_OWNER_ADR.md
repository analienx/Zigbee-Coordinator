# B4 ADR — existing-owner host and passive collector

Decision: **no sidecar, no invented Z2M extension method.** The reference recorder and parser remain offline until a reviewed in-process adapter implementation exists.

At pinned `Koenkk/zigbee-herdsman@0968f979d558874b17396c96b66382d4236bbdcd`:
- `src/adapter/z-stack/znp/znp.ts:45,47,101-112` owns the serial port and UNPI writer; `znp.ts:235-285` has a public `Znp.request()` running through its queue/waiter lifecycle.
- `src/adapter/z-stack/znp/zpiObject.ts:49-58` rejects request *names* absent from the dictionary; the pinned `definition.ts` has no F0 command. A made-up `znp.request("diagF0")` against this version will fail **before serial IO**.
- `src/adapter/z-stack/adapter/zStackAdapter.ts:43` has **private** `znp: Znp`; external Z2M plugins do not get a supported raw diagnostic request API. Never use `(adapter as any).znp`, `UnpiWriter` private access, or second `SerialPort`.

**Implementation path (experimental source overlay now implemented, still not installed):** patch pinned herdsman's own definition/parse logic and `ZStackAdapter` internals so that an explicitly authorized diagnostic request traverses **the existing** `Znp.request` mutex/Waitress/serial owner. An adapter-local scheduler must default OFF, check firmware/ABI capability, max one outstanding request, reserve low priority, suppress on OTA, startup, retry storm or any ordinary waiter, never change control SRSP retry policy. If private internals or parser constraints prevent an atomic integration, mark it BLOCKED rather than opening another serial connection.

Current branch now also contains `host/r4-b4/herdsman_overlay.py`: a guarded source patch adding an optional, **default-off** ZStackAdapter method that calls the existing private Znp owner through `requestWithReply`, explicit caller-attested idle/OTA gates, fixed 132-byte parser, and 30-second monotonic cooldown. At staged commit `503dd336` plus later host-hardening commits, pinned herdsman 10.9.1 TypeScript build and actual `Znp.request`/Waitress Node tests passed in hosted run [39001497672](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39001497672). The amended overlay now consults `AsyncMutex.isIdle()` (not only queued count), clears a timed-out **diagnostic** waiter without changing ordinary SREQ retry policy, and adds an explicit opt-in **in-memory** 256-entry, 24-hour metadata-only AF/ZDO/SYS timeout ring with no secret, packet or identity fields. These are source/hosted tests, **not deployed Z2M**. There is no host-worker persistence integration, active polling, MQTT publisher, or physical coordinator proof. Unsupported extension APIs remain explicitly BLOCKED.

## Passive forensic safety

Reuse the `r4_passive_recorder.py` ring/strict event allowlist, now with bounded 1 MiB recovery reads, chronological/unsigned history checks and POSIX parent-directory fsync. `offer()` has no disk access; `drain()` and `persist()` are future lower-priority worker operations. The in-process nonblocking callback and concurrent race-safety remain **NOT PROVEN**; no production registration is authorized. Recoverable `os.replace` errors preserve prior snapshot; a failure **after** rename but before parent fsync cannot promise the old file remains—persistence reports an error instead.

Process SIGTERM code 0 is only a shutdown observation. USB detach blocks diagnostics independently of firmware; no RF root cause can be inferred. Correlated OTA is never marked causal. No raw addresses, keys, personal identifiers, raw MT packets or secrets enter published forensic receipts.

## Zigbee2MQTT 2.14.0 release-source compatibility (not installed compatibility)

Actual upstream Zigbee2MQTT release commit `62b02e2aa1997c574223b80c196677b63a25f4a7` is package version **2.14.0** and depends on **zigbee-herdsman 10.9.1**. Its `lib/extension/extension.ts` exposes a protected Zigbee controller/EventBus, not a supported public raw SYS/MT transport request. The new `host/r4-b4/b4_verify_z2m_source.py` checks its pinned actual source, including negative version/API drift mutants; hosted source gate [39002832220](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39002832220) passed. The existing-owner herdsman 10.9.1 TypeScript/Node tests with 200 coalesced diagnostic probes plus 40 genuine in-memory stock SYS_PING requests passed [39002832223](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39002832223).

**NOT** established: which Z2M package/herdsman code is actually deployed on Home Assistant; a Z2M public extension route to the private diagnostic API; live traffic fairness; real UART ownership. No external extension or new transport is installed.

## Review-hardening 2026-10-17 — source-tested, not installed

The diagnostic-only query path is now conservatively quarantined after an ambiguous F0 timeout, synchronous UNPI writer exception or malformed/duplicate response: v3 F0 lacks a transaction ID and a stale SRSP could otherwise alias a future request. `Znp.request()` denies subsequent F0 *before* sending while ordinary SYS_PING/AF/ZDO requests remain operational. Native F0 sample sequence (static RAM) must strictly advance within one owner, but **does not certify a radio boot epoch**. All invalid native counter slots must be zero.

In addition to the active `Znp` mutex, `Waitress.b4IsIdle()` requires no normal pending/timed-out SRSP records. This prevents a diagnostic during an unresolved stock waiter even if the work mutex is temporarily free. It can suppress F0 indefinitely under adverse conditions; that is deliberate fail-closed behavior, not an automatic hardware reset. No idle/OTA attestation from deployed Z2M exists yet and no sidecar/host service has been installed. Compiled pinned-herdsman test [39003959612](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39003959612) PASS; runtime load/physical proof NOT_MEASURED.

## CR-13: the decisive F0 guard must execute INSIDE ZNP AsyncMutex

A pre-mutex poison test alone is insufficient: caller A's F0 can time out while a second F0 call, already past the early check, waits in the `AsyncMutex` queue. The pinned overlay now checks `b4DiagPoisoned` **and** normal `Waitress.b4IsIdle()` again *inside* `Znp.request()`'s existing mutex callback **before** writing any frame. This change has no stock SYS_PING/AF/ZDO scheduling or retry effect. It only prevents uncorrelatable experimental F0 retry traffic. Real Node test: `REVIEW-P0: F0 queued before first timeout cannot escape the mutex after quarantine` and direct pending-Waitress F0 denial; verified [39004432505](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39004432505). No serial device opened.

## Final admission rule: owner can close after queue admission

The pinned `Znp.request()` checks `initialized` before entering `AsyncMutex.run()`, while a genuine port-close callback sets it false. An experimental F0 queued behind an ordinary SRSP can outlive the serial-owner connection. Before transmitting optional F0, the already-existing ZNP mutex callback now requires **currently initialized** *and* not quarantined *and* Waitress idle. Otherwise it rejects that F0 with no serial write. Source-linked regression test covers this exact order. No second port, no reset, no impact on ordinary ZNP request policy.
