# R4 isolated SLZB-06P7U — final flash-preparation packet (2026-10-17)

**Status: PREPARED OFFLINE, NOT FLASHED / BOOT-QUALIFIED.** The source and
offline tools never authorize or perform hardware modification. Only the
isolated test SLZB-06P7U R1.73 is in scope. Production MR4U, Zigbee2MQTT,
Home Assistant, network backups and pairing must remain untouched.

## Why this path

The fitted P7U CCFG \`IMAGE_VALID_CONF\` is **0x000AC000**. Its stock
first-stage firmware authenticates MCUboot-format images; the first physical
R4 pilot programmed 23 application sectors but did not boot because the R4
container was not authenticated. That R4 attempt successfully restored
stock application sectors through the SLZB-management-triggered TI ROM BSL
and returned a valid ZNP \`SYS_PING\`.

The P7U **already has a verified management/ROM-BSL recovery transport**.
No vendor signing service or SWD programmer is required to program the
application and the unprotected \`0xAC000\` sector.

Do **not** modify CCFG as in the earlier experimental direct-CCFG fallback.
Instead **keep original CCFG byte-for-byte unchanged**, and program:

1. The genuine reproducible R4 application at physical vector \`0x00000000\`,
   exactly 23 application flash sectors \`0x00000..0x2DFFF\`.
2. A separate deterministic Cortex-M4 handoff stub in **one** 8 KiB flash
   sector \`0xAC000..0xADFFF\`. The ROM continues booting at \`0xAC000\`,
   exactly as the installed CCFG requests. The stub disables IRQs,
   sets \`SCB.VTOR=0\`, synchronizes, restores the R4 MSP from vector 0,
   enables IRQs, and jumps to the R4 Thumb reset handler.

The stub bypasses the original vendor MCUboot signature enforcement.
This is an intentional change in firmware trust architecture limited to
this isolated test hardware and is not equivalent to a vendor-signed image.

## Exact address boundaries

| Physical flash region | Decision |
|---|---|
| \`0x00000..0x2DFFF\` | R4 app: 23 CRC-checked 8192-byte sectors |
| \`0x2E000..0x9FFFF\` | Preserve as stock; R4 does not write |
| \`0xA0000..0xA3FFF\` | R4 new internal NV: keep blank until R4 initializes it; no preflash erase |
| \`0xA4000..0xABFFF\` | Fitted historical NV/security: preserve |
| \`0xAC000..0xADFFF\` | Single independent handoff boot sector; original backed up |
| \`0xAE000..0xAFFFF\` | Fitted CCFG sector: never erase or program |

The native TI HEX **also contains generated CCFG records**. **Never pass
the full native HEX/BIN to a general-purpose \`-ewv\` / bank-erase flasher.**
The extracted APP-ONLY HEX contains no bytes above \`0x2DFFF\`.

## Provenance pins; never confuse an old 0x80 image with this R4

- Native TI reproducible baseline:
  [run 39056503238](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39056503238),
  branch commit \`e820946e8771831cf414a8dce5032d9798bf8df6\`.
- Native direct vector at address 0; 2 independent GitHub builds passed
  original ELF/XML/HEX/BIN/board/link checks and native reproducibility.
- Extracted 23-sector APP-ONLY HEX SHA256:
  \`38fe3b5ddf06d79d4d9cbe90900c770d1b6042c9f7f4bd0216d292d966ca11e6\`.
  Both independent native replicas produced byte-identical app HEX.
- Generated 8192-byte handoff sector SHA256:
  \`e653c929ed55df74fc586a1e272f95a7e52ee00a76096a17842494e33bc0c4cf\`.
  CRC32 \`a4efafa4\`, both replicas independently equal.
- Exact fitted, twice-read factory 704 KiB backup SHA256:
  \`ba654310cef8f1543a96c9bb6d5ef4f17411829642bcbe8249e91de6ae5b38f3\`.
- Fitted original boot sector SHA256:
  \`9d7fdad2eb0a4e134bc6e61b982a1a3b17438d72c6b49fa2a403926d58647b47\`,
  CRC32 \`448b8a3a\`.
- Original fitted CCFG top 8 KiB CRC32 \`3c032e08\`.
- Fitted \`IMAGE_VALID_CONF=0xAC000\`, ROM BSL DIO15 active-low backdoor
  remains enabled, sector \`0xAC000\` is not write-protected.
- Stock live read-only \`SYS_PING\` passed at the end of preparation.
- Both original full-flash backups stay PRIVATE on the authorized PC,
  not in repository, CI, or issue comments.

## Reproducible offline commands (trusted local executor)

From the exact branch worktree on a trusted host:

\`\`\`text
python -m unittest -v tests.test_r4_make_direct_app_only tests.test_r4_make_rom_handoff_sector tests.test_r4_boot_sector_transaction tests.test_r4_direct_ccfg_offline_plan
python firmware/slzb-06p7u/r4/release/r4_make_direct_app_only.py --artifacts <exact-native-b0out> --out-dir <private-empty-app-output>
python firmware/slzb-06p7u/r4/release/r4_make_rom_handoff_sector.py --native-app-hex <exact-app-hex> --native-app-receipt <app-receipt> --factory-pass1 <private-fullflash-pass1> --factory-pass2 <private-fullflash-pass2> --out-dir <private-empty-handoff-output>
python firmware/slzb-06p7u/r4/release/r4_final_owner_flash_preflight.py --stock-pass1 <private-fullflash-pass1> --stock-pass2 <private-fullflash-pass2> --replica1-app-hex <replica-1-app-hex> --replica2-app-hex <replica-2-app-hex> --replica1-receipt <replica-1-receipt> --replica2-receipt <replica-2-receipt> --handoff-bin <handoff-sector-bin> --handoff-receipt <handoff-receipt> --out-receipt <private-new-receipt.json>
\`\`\`

The operation does not take or publish local IEEE, NV data, keys, or raw
CCFG bytes except as locally compared reads.

## BSL operator sequencing (NOT executed in this preparation)

All device operations must target the isolated P7U alone through SLZB-OS
management's BSL entry and the pinned ROM transport on data port 6638.
Do not use a different radio index or the production MR4U endpoint.
The existing application writer is 23-sector restricted; the distinct
\`r4_boot_sector_transaction.py\` is an independently tested generic
**single-sector** writer core, not a live programmer or operator permit.

1. Read-only live target MAC, model, silicon ID, firmware identity, full
   same-board backup SHA, 23 stock app CRCs, \`0xAC000\` stock boot CRC and
   \`0xAE000\` unchanged fitted CCFG CRC. Reject differences.
2. Enter BSL through the known management transport; maintain exclusive
   radio ownership. No other firmware/OTA/HA/Z2M action.
3. With stock loader still installed, program exactly 23 application
   sectors using the previously physically tested sector-only protocol,
   erase sector 0 **last**, verify each sector CRC, with no intermediate
   radio reset.
4. Verify all 23 R4 application CRCs and fitted CCFG CRC; only then use a
   narrowly scoped adapter accepting erase/download of **0xAC000 only**
   to program the complete 8 KiB handoff sector **last**. Verify its CRC.
   **Never** erase/program \`0xAE000\` or NV.
5. Exit BSL, management radio restart, require valid \`SYS_PING\`,
   expected \`SYS_VERSION\`, boot diagnostics and NV fail-closed behavior.
6. On any failure, management/ROM BSL rollback uses exact-stock **boot
   sector 0xAC000 first**, then original application sectors (sector 0
   last). Verify original application, boot and untouched CCFG CRCs,
   exit BSL and verify original \`SYS_PING\`. Do not infer success from
   reset alone.

The boot-sector writer core fails closed on changed CCFG/ROM backdoor,
unexpected existing boot CRC, changed application CRC, stale approval token,
and programming/CRC failures. The **live** transport adapter that extends
the original ROM command allowlist to the sole \`0xAC000\` sector must be
independently reviewed and tested before its first hardware write. A
simulated writer pass is NOT proof of a physical erase/rewrite.

### Current gate status

- [x] Two manufacturer-independent, pinned native source builds are
      reproducible.
- [x] Genuine native application safely isolated from CCFG/NV/boot sectors.
- [x] Both private original same-device fullflash backups compared.
- [x] Handoff Thumb machine code independently decoded; R4 SP/reset bound.
- [x] Two replicas of app-only and handoff binaries byte-identical.
- [x] Fitted ROM boot vector, backdoor, sector protection and 8 KiB stock
      sector CRCs verified offline.
- [x] Final stock/application/handoff/rollback offline receipt generated.
- [x] Read-only real stock ZNP \`SYS_PING\` confirmed.
- [x] Single-sector generic writer tested against synthetic ROM failures.
- [ ] Hardware-specific boot-sector adapter/rollback path integration and
      separate live read-only final preflight.
- [ ] Physical R4 flashing, boot test and stock rollback rehearsal
      (intentionally not executed during flash preparation).

This is an isolated test candidate, **not** production firmware release.
