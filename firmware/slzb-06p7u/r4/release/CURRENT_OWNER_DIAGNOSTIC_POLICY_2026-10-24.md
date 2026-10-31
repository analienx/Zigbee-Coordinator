# P7U R4 current-owner security gate — narrowly relaxed diagnostic policy

2026-10-24. Source `2c6b23f466ce41e85ac9c767ee8ed91a307ddfd9` was independently
native-compiled on two hosted runners. This file does not grant flash rights.

## Proven on the archived USB-v4 STOCK captures (offline, never live admission)

- The genuine native TI NV4 reader successfully parses both exact 704 KiB,
  byte-equal stock captures, with zero reported erase/write attempts.
- Patched genuine TI `stock20260311_security_preflight.py` returns
  `PASS_RETAINED_SECURITY_OFFLINE_ONLY`: valid formed coordinator, retained
  NWK key/counter floor and all required TI security table conditions.
- The **strict historical forensic** `p7u_usb_security_model.reconcile`
  continues to report HOLD because it requires all 107 historical entries
  and matching every obsolete per-peer key and counter.
- The independent **current stock** model
  `p7u_usb_current_owner_gate.reconcile_current` returns
  `PASS_CURRENT_OWNER_OFFLINE_ONLY`: historical 107, current backup 106,
  captured silicon 106, current APS associations 2, reason_codes empty.
- The one dropped historical entry must be verified keyless, no counters,
  `is_child=false`, and absent on **both** captured silicon and current
  owner backup. Never fabricate, erase, rejoin or write it to NV.
- Exact current network key/sequence/seed/coordinator/PAN/extPAN/channel and
  every current IEEE inventory entry must match genuine TI native records.
  All live APS per-peer IEEE-bound keys and counters must satisfy current
  owner's lower bounds. No opaque aggregate count may replace them.
- Persisted coordinator TC=zero is compatible with TI's runtime coordinator
  TC assignment; foreign nonzero TC is not.

## Policy separation

1. **Historical disaster-recovery** remains strict v1 and HOLD. Never claim
   old 107 membership, historical per-peer keys or stale counters are back.
2. **Firmware-only controlled diagnostic** may use *new* current-stock gate
   only after a fresh paired, same-unit capture and freshly obtained current
   owner backup validate identically at the actual stop, with native TI
   security preflight, exact-source C/hardware-ID checks and protected-region
   checks. It does not restore historical data or authorize NV writes.
3. **Production-qualified persistent release** still requires observing
   state9 / retained Z2M normal traffic, absence of AF->SYS SRSP failures
   and a meaningful extended runtime window with validated F0/F2 evidence.
   A successful ROM program/readback is not network proof.

## B3 NVOCMP and boot handoff — not silent waiver

- The current two native builds *do* contain B1's authenticated NV4/
  HOLD, counter-reservation and TCLK/APS persistence work. The B3 source
  fusion independently attests three NVOCMP compaction code-path guards
  but reports `source_ready=false`, `NVOCMP_source_only=true`, other
  potential compaction failure paths, and no power-cut hardware proof.
  This is a real residual risk for a diagnostic attempt, not a PASS.
- Current native handoff hash is different from the old image. Its exact
  0xAC000 code has native compilation and Unicorn M4 execution evidence;
  hardware_boot_qualified=false is correct until first hardware exercise.
  Never change that receipt to `true` ahead of the test.
- The *only* possible relaxation is to allow a separately labeled
  one-attempt, fallback-prepared **diagnostic trial** that proves the new
  handoff in hardware. It must not promote the static build receipts,
  masquerade as production or ignore transport/flash-range/recovery failures.

## Non-negotiable stop conditions

No chip erase, no blank coordinator startup, no old NV restore, no manual
counter manipulation, no flash to 0xA0000..0xABFFF or
0xAE000..0xAFFFF, no more than one unique radio owner and no retry on
an ambiguous ROM mutation. Full-app (24 sectors) + compiled matching
0xAC000 (1 sector) only, every sector independently verified before
boot. Recovery must use same-unit stock flash bytes and preserve the
current live NV; if after flashing the boot is not established, stop
before Z2M reuses the wrong image and report the failure.

CI proves only the model; the private genuine captures, keys and backups
must never leave the owner's secured environment.
