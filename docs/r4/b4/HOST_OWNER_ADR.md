# B4 ADR — existing-owner host and passive collector

Decision: **no sidecar, no invented Z2M extension method.** The reference recorder and parser remain offline until a reviewed in-process adapter implementation exists.

At pinned `Koenkk/zigbee-herdsman@0968f979d558874b17396c96b66382d4236bbdcd`:
- `src/adapter/z-stack/znp/znp.ts:45,47,101-112` owns the serial port and UNPI writer; `znp.ts:235-285` has a public `Znp.request()` running through its queue/waiter lifecycle.
- `src/adapter/z-stack/znp/zpiObject.ts:49-58` rejects request *names* absent from the dictionary; the pinned `definition.ts` has no F0 command. A made-up `znp.request("diagF0")` against this version will fail **before serial IO**.
- `src/adapter/z-stack/adapter/zStackAdapter.ts:43` has **private** `znp: Znp`; external Z2M plugins do not get a supported raw diagnostic request API. Never use `(adapter as any).znp`, `UnpiWriter` private access, or second `SerialPort`.

**Implementation path (future host code, not faked in this change):** patch pinned herdsman's own definition/parse logic and `ZStackAdapter` internals so that an explicitly authorized diagnostic request traverses **the existing** `Znp.request` mutex/Waitress/serial owner. An adapter-local scheduler must default OFF, check firmware/ABI capability, max one outstanding request, reserve low priority, suppress on OTA, startup, retry storm or any ordinary waiter, never change control SRSP retry policy. If private internals or parser constraints prevent an atomic integration, mark it BLOCKED rather than opening another serial connection.

Current branch provides offline frame parsing and real-source ownership/collision audits; there is **no** compiled/herdsman or Z2M plugin, no installed hooks, no live polling, no MQTT publisher and no native F0 handler. This is an explicit acceptance blocker.

## Passive forensic safety

Reuse the `r4_passive_recorder.py` ring/strict event allowlist, now with bounded 1 MiB recovery reads, chronological/unsigned history checks and POSIX parent-directory fsync. `offer()` has no disk access; `drain()` and `persist()` are future lower-priority worker operations. The in-process nonblocking callback and concurrent race-safety remain **NOT PROVEN**; no production registration is authorized. Recoverable `os.replace` errors preserve prior snapshot; a failure **after** rename but before parent fsync cannot promise the old file remains—persistence reports an error instead.

Process SIGTERM code 0 is only a shutdown observation. USB detach blocks diagnostics independently of firmware; no RF root cause can be inferred. Correlated OTA is never marked causal. No raw addresses, keys, personal identifiers, raw MT packets or secrets enter published forensic receipts.
