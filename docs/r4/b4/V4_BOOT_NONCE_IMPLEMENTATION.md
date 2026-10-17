# B4 v4 candidate — nonce correlation and one-time radio boot token

**State: DRAFT / SOURCE-ONLY / NO FLASH.** This candidate composes on top of the pinned and independently green B4 v3. Existing SYS F0 stays intact. New SYS F1 (request 0x21/F1, response 0x61/F1) is a distinct opcode and version; no fallthrough to F0.

## Wire ABI v4.1

Exactly 8 bytes in F1 request (host-generated Node crypto randomBytes). Exactly 160 bytes in F1 response, excluding UNPI framing and FCS:

| Offset | Bytes | Meaning |
|---|---:|---|
| 0–3 | 4 | magic R4D4 |
| 4 | 1 | major=4 |
| 5 | 1 | flags=0 |
| 6–7 | 2 | length=160 LE |
| 8–11 | 4 | capability bit0: source-generated boot token available |
| 12–15 | 4 | counter validity 0x3F or 0x2C |
| 16–23 | 8 | cached boot token, zero when unavailable |
| 24–27 | 4 | uptime unknown=0: no counter deltas authorized |
| 28–31 | 4 | nonzero monotonic process-local sample sequence |
| 32–131 | 100 | existing 25 counters, indices 0–5 source-qualified |
| 132–139 | 8 | exact eight-byte REQUEST NONCE echo |
| 140–155 | 16 | all-zero: real binary image digest NOT CLAIMED |
| 156 | 1 | one-shot SysCtrlResetSourceGet raw cause, or FF unknown |
| 157 | 1 | minor=1 |
| 158 | 1 | reset cause valid bit0 only |
| 159 | 1 | reserved zero |

The nonce prevents a late SRSP for an older F1 request from being accepted as the response to a newer one; a mismatched nonce permanently quarantines only optional diagnostics on this ZNP owner, without affecting normal AF/ZDO/SYS traffic. The nonce is transaction correlation, not cryptographic authentication; it is not logged or persisted.

## Pinned TI source, one-time startup, fail-closed TRNG

TI 8.33 source SHA 3615ad5d3f4f271258d18a2f5ce1785064ff9a58 contains the native TRNG driver and CC13x2x7 reset API. The pinned ZNP donor SysConfig in simplelink-zstack-examples@87ff5b638b632050228a7504f35cf3b95581c278 declares TRNG.addInstance(). B4_v4_native_patch.py is a guarded overlay applied after B4 v3, in disposable /tmp only.

The only entropy call occurs ONCE from existing NPITask_inititializeTask in task context, after NPI task registration and before opening its already-owned UART. TRNG_init, TRNG_open(0) with bounded 25 RTOS-tick timeout, TRNG_getRandomBytes for 8 bytes, and TRNG_close never execute in a diagnostic request, ISR, critical section, radio path, or key/NV path. Resource-unavailable/timeout/all-zero results set no boot capability and never retry until a new boot. A successfully generated 8-byte token is cached in RAM; F1 copies it under the original brief queue-snapshot critical section. Reset reason is independent metadata, NOT entropy.

A successful TRNG call is **not** hardware-verified randomness, perfect uniqueness or evidence the target booted. Host radioEpochHardwareVerified is always false, and no cross-boot counter deltas can be inferred. The actual TI native link and hardware runtime must prove TRNG instance linkage, boot startup timing and RAM/stack budget. Failure to produce TRNG data must not prevent NPI initialization.

## Hosted existing-owner integration

The new v4_herdsman overlay applies to the pinned 10.9.1 source AFTER the original verified v3 existing-owner overlay. It adds the F1 command with exact fixed-size BUFFER8/BUFFER160 serialization, checks nonce/ABI/validity/boot representation, and extends both original AsyncMutex prewrite gates to F1. No second port, no custom scheduler, no automatic polling.

The v4 Zigbee2MQTT 2.14.0 bridge adds a manual, default-OFF method on top of the real private OTAUpdate.#inProgress source gate; it rechecks the live OTA predicate inside the original ZNP mutex just before F1 transmit. Original F0 and normal AF/ZDO/SYS_PING are unchanged.

## Remaining real gates

Hosted tests and genuine dual CCS ELF/HEX/BIN parity must succeed at the exact source SHA; source strings or simulated ELF do not qualify native completion. An independent TI/NPI/ISR/crypto/ABI review, loaded-traffic startup and stack profiling, an image digest/attestation design, actual installed HA source/version reconciliation, and a physical disposable-device pilot R4-07 all remain open. B1/B2/B3 draft branches are NOT source-ready and must be reviewed before a separate combined B5 build. No flash, restore, topology change, OTA or live HA service mutation is authorized.
