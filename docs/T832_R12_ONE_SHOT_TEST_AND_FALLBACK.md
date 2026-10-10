# R12: one-shot diagnostic test, with reflash and restore fallback

**Operator decision (2026-10-10):** do not build a complex persistent ACK/re-arm
protocol for R12. R12 is a disposable forensic build, not a lifetime
coordinator firmware. Use **a separately checked recovery image and a sealed
restore backup** to recover or to run a later diagnostic iteration.

## Existing recovery evidence (rechecked offline)

- Immutable private R11 recovery plan hash:
  `73332b6d52641083fddd1bd99678da491d9090d552835430ad2d4b0d5cb8201a`.
- Sealed original backup JSON SHA256:
  `bd95f00eb3ce1f7794f9c6406c5b4fd96a0c6aa0ef5cdbaa7a29d25d3f6083b8`.
- Independent read-only `p10_network_recovery.validate_backup(backup, 0, 2500)`
  confirms **103 devices, 103 link keys, 103 address associations** and safe
  2,500-count counter margin. The same backup was previously used for a
  recorded successful 630-NV-write restore, with a separate full 103-key
  readback and network counter floor verified before the last failure.
- Sealed R11 plan is **blocked**, terminal after prior `startupFromApp`.
  The radio is not known to have become responsive since the latest failure.
- The backup has **not been refreshed following the latest failed startup**;
  do not claim it was. Keeping or restoring the keys is not equivalent to
  guaranteeing that this problematic network will initialize successfully.

## Minimal release/test checklist

1. Freeze and hash the final R12 build; check actual native TI compile/link,
   CCFG DIO15/BSL, exact 15×2KB NVS geometry, no NV records in image, security
   backup integrity, original network identity and counter floors. Record
   local/remote firmware/backup locations and a known working reset/flash
   transport. The candidate must remain marked DIAGNOSTIC/DO-NOT-FLASH in CI.
2. One **controlled test epoch** only: deploy R12 under the user-authorized
   recovery procedure; verify healthy basic ZNP without starting the existing
   network. Do not use an automated Zigbee2MQTT watchdog that could repeatedly
   trigger startup. The R12 first-boot storage may contain unrelated AUX bytes:
   after the first verified safe access it initializes a fresh unowned
   80-byte journal. No manual changing of NVS/keys.
3. For the *A0 evidence retention check*, record a known harmless checkpoint,
   issue exactly one **radio-only reset** through SLZB (not full power-off),
   verify boot and retrieve kind54 previous-epoch evidence before another
   startup. If no previous-epoch record returns, result is **inconclusive**;
   stop this method rather than retrying startup blind.
4. **No ACK/re-arm implementation is required** for this one-shot diagnostic.
   If A0 consumes the record and a new A1 startup diagnosis is needed,
   reflashing an independently verified replacement image may reset the
   diagnostic lifecycle. This must be treated as a **new** sealed attempt,
   not a no-cost retry of R11 or R12. Reflash might clear AUX retention;
   always archive the currently emitted diagnostic evidence first.
5. In the separately admitted A1 experiment, check full 103-key/address
   counters, allow **one** restored Zigbee startup, record kind54 after a
   subsequent radio-only reset if it hangs. On failure, recover via the
   known-good radio image and restore the original network security/NV
   from the immutable backup. Confirm independently after restoration;
   no automatic re-pair or trust-center identity change.

## Risk explicitly accepted vs. risk that still needs checking

**Accepted as a pragmatic one-shot test limitation:** no ACK/re-arm API, one
image/reflash per experiment, no automatic reboot, and no need to support
future production updates of this debug firmware.

**Still mandatory before live flash:** prove the P10 is reachable through a
known BSL/recovery path (not just SLZB API success); inspect actual image
hash/layout and copied backup restore capability; be clear the proposed AUX
memory region `0x400E0FB0..0x400E0FFF` may be occupied or unclocked and an
early access could fault the CPU. This is a safety/risk disclosure rather
than a demand for new hardware or an impossible guarantee. It may be tested
using a controlled hardware A0 trial, provided the restored-network
fallback is reproducible and the operator accepts that risk.

**Recovery claim boundary:** reflashing can often recover the radio and its
NVS can be restored from an intact backup. It **cannot guarantee** that
restoring this network will eliminate the already reproduced
`startupFromApp` lockup. Report recovered ZNP, recovered keys and network
routing acceptance as **three distinct outcomes**.

**Current action:** procedural simplification/documentation only. **No
radio reset, startup, flash, NV change or Z2M start executed.** The current
CI artifact is an authenticated compile candidate, not a live-accepted build.
