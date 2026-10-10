# A1 one-shot startup forensics — gates and order

## Verified baseline
- R12 8320062 remains running; post-power event54 unexpectedly still showed **old A0** attempt `0xA0120001`, seq1/site1 entry. A prior retained A0 witness showed seq2/site1 exit. These observations do not prove a clean new diagnostic epoch.
- Original backup SHA256 `bd95f00eb3ce1f7794f9c6406c5b4fd96a0c6aa0ef5cdbaa7a29d25d3f6083b8`: 103 devices, 103 keys, 103 required address associations, counter+2500 safe.
- Live read-only NV lengths: 1=8, 3=1, **33/NIB=0**, **35/address manager=0**, 85=1, 96=0. This is not a verified commissioned network.

## Mandatory correct sequence
1. **Before changing firmware**, independently qualify and restore NIB, address and security tables on current R12 using the original saved 116-byte native NIB and immutable full backup. The older two-stage `restore-native` and `restore-tables` paths have *different prerequisites*; neither may be blindly invoked against simultaneous missing NIB and address manager. Confirm actual APS/TCLK/NWK capacities, original IEEE/PAN/channel/key identity, complete 103 associations, and counter floors.
2. Allow any necessary restoration soft reset **before** arming A1. Verify 103 keys/address rows, exact NIB and updated counters **after** restoration. Do not issue `startupFromApp`.
3. Build/pin new diagnostic `8320063`, attempt `0xA0120002`, epoch `0x20261011`; flash only after restoration proof, `eraseNVM=0`. A1's code consumes **only** an archived, CRC-valid A0 journal with the exact old image/attempt/epoch and seq1/site1-entry or seq2/site1-exit. Any foreign, mixed or visibly corrupted record is preserved.
4. Before a startup, collect the **new kind55 `R12_A1_ARMED`** frame. It attests a successfully enabled recorder, *not* a restored network. If missing, STOP; no blind startup.
5. Check the entire restored security state **again after the diagnostic flash**, because `eraseNVM=0` previously did not guarantee an accessible NIB. If flash destroys the NIB, do not restore-and-reset while claiming the recorder is still armed; plan another verified epoch.
6. Then allow exactly one `startupFromApp`. If hung, issue no second startup; use a separate radio-only reset and passive kind54 capture. Keep Z2M stopped and watchdog off.
7. Recovery by flash/restore from the sealed backup remains available but successful ZNP, complete NV and operational mesh are three separate acceptance conditions.

## A1 source and review
Separate worktree `codex/t832-a1-diagnostic`, preserving original R12. New 8320063 artifact is deliberately named `T832-R12-A1-DIAG-vendor-20240716`. R12 baseline NV/security/CCFG and native TI source gates are unchanged. The one-shot transition does not touch flash/NV/UART, and event55 uses the existing bounded T832D2 export. Native C, parser and artifact tests must pass before considering a flash.

**Current stop:** missing-NIB+missing-tables recovery is not yet qualified on this R12 state; no live NV writes or A1 startup authorized by this document.
