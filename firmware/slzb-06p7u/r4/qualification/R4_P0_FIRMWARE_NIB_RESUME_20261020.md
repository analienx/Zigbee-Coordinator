# R4 P0 — firmware-side NIB resume (20 October 2026)

This is **firmware code in the pinned TI NVOCMP v3 path**, not a host-side
backup replay, HOLD_NV override or permission to form a new network.

## Verified incident facts

- CC2652P7U stock 20260311: four 8-KiB NVOCMP pages A4000..ABFFF.
- Surviving 116-byte original NIB is CRC-valid but inactive; no active NIB.
  Destructive host reset left startup option 0x03.
- The inactive NIB extended PAN ID matches the active OSAL extended-PAN
  ID at observed pinned nwkIB_t offset 57.
- Active NWK keys, Trust Center address and TCLK seed survive.
- 104 of the 300 TCLK records had outgoing TX frame-counter increments only;
  **never restore the older TCLK data or decrement security counters**.
- Current active page ends at offset 860; the two necessary native record
  appends total only 131 bytes and require NO compaction.
- Private network records remain only in the device's private captures.

## Exact firmware change

1. Retain independent four-page read-only NVOCMP admission before TI init.
   Only in UNKNOWN_HOLD, probe exactly one inactive 116-byte NIB, coherent
   BDB-on-network/role, startup option 0x03 or 0x00, and live active
   extended PAN ID, NWK keys, Trust Center and TCLK seed with exact lengths.
   Original NIB extended PAN must equal the active extended PAN ID.
2. On a positive probe, allow **only TI NORMAL_RESUME** native init, with
   existing B1 protection against init-time writes/compaction still active.
3. Before allowing Zigbee tasks to start, demand both updates fit the current
   active NV page with no compaction or page transition.
4. If needed, write 0x00 to startup option first using the real TI
   NVOCMP_writeItemApi and read back; rerun the read-only proof.
5. Append the original NIB with that same native TI API and compare it with
   readback; require the independent read-only observer to report a
   FORMED_CANDIDATE after writing.
6. On any failure, latch B1 HOLD_NV and deny RF/commissioning. Wipe the
   temporary NIB buffers. Never erase NV, format, form a network, flip an
   inactive flash status bit from 0 to 1, or touch TCLK counters.

The 116-byte length / 57-byte field offset are intentionally restricted to
the pinned P7U TI ABI, not a general-purpose Zigbee backup migrator.

## Remaining qualification before hardware use

- Compile the true source-linked firmware via GitHub Actions for current
  stock20260311, checking native compiler, ELF, generated NVS region and
  preserved MCUboot handoff. Source-only evidence is not a flash candidate.
- Execute the exact TI NVOCMP RAM-clone power-cut matrix for both item writes:
  payload and trailer can tear. Such a partial write must HOLD safely.
- Before physical flash, revalidate flash snapshots and ensure the host-side
  destructive herdsman restore is contained (separate draft PR #140).
- Flash only approved app/boot handoff sectors, never NV4/CCFG; observe Z2M.
- Recovery success is **not** claimed until physical Zigbee startup passes.

Primary code: TI SDK git 3615ad5, source/ti/common/nv/nvocmp.c,
source/ti/zstack/stack/sys/zcomdef.h and source/ti/zstack/stack/nwk/nwk.h.
