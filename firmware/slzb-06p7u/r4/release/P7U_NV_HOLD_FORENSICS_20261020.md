# P7U R4 NV HOLD: exact saved-media result and next decision

Target: the single SLZB-06P7U R1.73 attached by USB to Home Assistant.
This document grants no BSL entry, transport switch, reset, write or Z2M start.

## Current evidence

R4 firmware source `828b1b5e55d24a13dccf88bffe74108bf4b56bcc`, built by
[native run 39425070812](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39425070812),
is running and answering SYS_VERSION/F1 over USB. One Z2M startup opened serial
then timed out waiting for SYS_RESET_IND. HA subsequently showed the add-on
stopped/error, watchdog disabled, and no owner of `/dev/ttyACM0`.

F1 reports stage HOLD_NV, first error/probe 4 and current error 0x21. Probe 4
is the **bridge's** HOLD_MIXED_LAYOUT, not raw observer code 4. It combines
unsafe page metadata/topology, duplicate active identities, and accepted
structure with unknown semantic markers. Main subsequently records generic
NV_INIT 0x21; this is not independent proof that TI's native initializer ran.
The observer runs before that initializer and before Zigbee tasks start.

The actual native source seal confirms the four-page observer is linked,
NVS base A4000, size 8000 and sector size 2000 (hex). The runtime reader uses
the NVS handle's region base plus relative offset. No source evidence supports
reverting to NV2, changing the address mapping, or relaxing the HOLD gate.

## Exact C observer on the preserved preflash pair

[Host-only oracle commit 7b5e438](https://github.com/analienx/Zigbee-Coordinator/commit/7b5e43870a0e6d0b902a929c0e7722520bd8ab6f)
was built and checked by [hosted run 39473865098](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39473865098).
The downloaded executable was hashed against its build receipt, and its
observer/header/bridge pins matched the actual 828b1b5 native source seal and
final TI source manifest. The private saved inputs were never uploaded.

On Zephyrus, the prebuilt executable consumed each saved full capture through
stdin, explicitly slicing A4000..ABFFF in immutable RAM. Both captures matched
their original receipt and each other. Both executions returned:

| Field | Result |
|---|---|
| Raw observer code | 8: READONLY_STRUCTURE_ACCEPTED |
| Semantic state | 2: FORMED_CANDIDATE |
| Exact compiled bridge mapping | 7: existing-network candidate |
| Expected observer-induced HOLD_NV | false |
| Records / active identities | 952 / 779 |
| Reads | 2,421 |
| Original versus traced result and read sequence | identical |
| Writes / erases | 0 / 0 |

Page rotation was FULL, ACTIVE, DESTINATION, FULL. Required BDB, coordinator
role and NIB markers were coherent. Private evidence is stored outside Git in
`p7u-r4-nv-hold-oracle-20261020/saved-oracle-result.json` on Zephyrus.

This is host execution of the exact C observer over **saved bytes**, not proof
of current live NV, target execution equivalence, native TI recovery, or a
successful coordinator/security restore. The earlier genuine-TI 892/779
initializer result used a different retained snapshot.

## Implementation decision

1. Preserve the current USB HOLD state. Do not repeat Z2M startup, reformat NV,
   replay a backup, increment counters or change admission predicates.
2. Prepare a fresh-output, bounded read-only live ROM capture using the already
   qualified adapter. A USB-to-Ethernet transition and BSL entry require fresh
   approval; the old wrapper's existing output path and stock-version
   assumption make it unsuitable for reuse unchanged. No app restart follows
   the capture automatically.
3. Compare the two live captures/ROM CRCs, identity, all sectors and specifically
   A4000..ABFFF against the preflash pair. Feed both live NV images into this
   same pinned oracle. Keep raw records and security state private.
4. If NV changed, report exact changed sectors and raw observer reason/line/
   offset, then explain the change using the pinned TI format and host startup
   sequence. Fix only a demonstrated compatibility defect. A need for genuine
   TI write-backed recovery is a separate decision, never implicit permission.
5. If live NV is identical and accepted, investigate target execution and
   integration. Preserve raw observer code, semantic state, fault offset and
   counts before their lossy bridge mapping in a narrowly scoped diagnostic
   candidate, or execute the actual linked ARM function against the captured
   bytes. Qualify any firmware change in hosted native CI before proposing a
   flash. Do not conceal the discrepancy by returning success unconditionally.

PR #136 remains draft. A successful boot handoff and working USB transport have
already been observed; operational finalization now depends on resolving this
specific admission discrepancy and then verifying retained network operation.
