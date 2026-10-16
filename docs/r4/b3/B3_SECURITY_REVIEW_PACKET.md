# B3-06 — independent review packet (REQUESTED, NOT COMPLETED)

Candidate branch `codex/r4-b3-nv-security-offline` / draft PR #99; source donor B0 `1baefbee8e4de2c9d28c5e1a7c339cf2025a2afe`, TI 8.33 `3615ad5d3f4f271258d18a2f5ce1785064ff9a58`. This packet names reviewer lanes but does **not** claim anyone has independently reviewed the candidate.

A. **NVOCMP/flash reviewer:** check donor blob provenance, NVS_open before attrs, exact page geometry, ignored NVS_read status, page marker state machine, mid-compaction interruption and global buffer freshness. Attack: malformed page with valid-looking CRC but invalid bounds; zero sector; repeated init; stale flash page after torn commit.

B. **Security reviewer:** validate per-key NWK TX and APS/TCLK counter domains and reservation-before-send, cross-item commit generation, lack of invented TC rows, no TRNG fallback, HOLD_SECURITY RF suppression in B1. Attack: old snapshot with higher TX; same-key wrap; changed key; two-frame burst across write failure; B2 queue bypass.

C. **Migration/privacy reviewer:** reject duplicate ZIP, symlink, traversal, tampered manifest, CRC corruption and misleading provenance. Confirm no real key/IEEE/secret printed or required, offline authority always false. Attack: unhashable layout field, malformed timestamp, stale nested backup and key-swapped snapshot with higher counter.

D. **Native/CI reviewer:** real TI CCS 12.8, SysConfig 1.21.1, tiarmclang 3.2.2, correct linked B3 patch, no B1/B2 overlay, source preimage pins, NV linker placement, CCFG, ELF/XML/HEX/BIN, full RAM and native SDK build evidence. Attack: compiled source substituted after SHA, correct C harness but unpatched native ELF, NV5 changes app sector unnoticed.

**Challenger cases (new proposed vectors, not results):** C01 malicious type for NV layout, C02 zip duplicate normalized path, C03 metadata origin flag spoof, C04 current key absent but TX floor high in earlier snapshot, C05 producer's security row count larger than native B2 TC limit, C06 rekey with old counter incorrectly accepted, C07 flash region size zero before divider, C08 B1 HOLD_SECURITY bypass by already queued AF callback.

Every real review must record reviewer identity/tool, exact head SHA, source path:line, P0–P3 severity, reproduction, Actions run ID, repair SHA and disposition. **Review verdict: NOT PERFORMED**; no Muse Wonder approval is claimed. B3_SOURCE_READY=false, B3_INTEGRATED_READY=false, FLASH_READY=false.
