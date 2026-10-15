# SLZB-06P7U TI 8.32 — v0.1.0-rc1 (software release candidate)

**Release scope: firmware sources, reproducible P7U build artifacts, sector-only recovery tooling.**
**Status: software qualification only — NOT approved to flash a physical device; NOT a stable production release.**

## Included and verified

- TI SimpleLink SDK 8.32, CCS 12.8, TIARMClang 3.2.2, SysConfig 1.21.1; real ARM ELF/HEX/map linked with exact manufacturer SMLIGHT P7U 88-byte CCFG and `enableDCDC=false`.
- G7 UART/DMA Zigbee NPI transport hardening, source and linked tests.
- F07 NIB commit-before-ready, restoration fails closed, coordinator NWK frame-counter escrow and guarded periodic NWK checkpoint; host hostile faults and linked native call-edge evidence. APS/TCLK and powercut remain unqualified.
- **R1 `p7u-f07-stock`:** P7U manufacturer CCFG + NV2 + G7/F07. Preferred **first isolated hardware qualification image**, with fewer variables changed.
- **R2 `p7u-cap192-f07`:** P7U manufacturer CCFG + CAP192/NV5 + G7/F07. Source/build qualified; NOT evidence of 192 stable real Zigbee devices. Test only after R1 safe recovery.
- An explicit two-phase protected-sector TI ROM BSL read/flash tool (`p7u_flash_spare.py`), real vendor stock firmware extraction and sector-only stock rollback, with interrupted-write/resume tests. No upstream SMLIGHT CLI `BANK_ERASE`, CCFG, IEEE or ESP updater.
- For **network** BSL, SMLIGHT API `get_info()` must report exact SLZB-06P7U model and the operator's full physical ESP management MAC **before** any `CMD_ZB_BSL` radio reset. Reject MR4U/P10, absent model/MAC, auth-required API. USB must already be in ROM BSL; do not assume DTR/RTS resets the TI radio.
- Exact official SMLIGHT `20240710` SHA-256 `1e257bc066e7a8db9c12e0b826791cc81d8744b9453355af0f4efce194060d6b` (179,688 APP + 88 CCFG); stock rollback covers 23 application sectors with **0x2C000 entirely FF-cleaned** to eliminate custom-only tail, no NV or CCFG writes.
- Python 3.12 Windows isolated venv (pysmlight 0.5.3, pyserial-asyncio 0.6) tested on Zephyrus; no incompatible `gpiod` or official high-level segmented-HEX bank-erase CLI.

## Reproducible release kit

Use `p7u_rc1_package.py` with an **actual** `DIAG-NOT-FLASHABLE.hex` from the pinned native CI and its matching `BASE-VS-DIAG-EVIDENCE` directory. Its strict cross-check binds: native `candidate-sha.txt`; native ELF/HEX SHA; exact vendor 88-byte CCFG and P7 ROM BSL; linked F07/G7 call edges; original 23-sector plan; source ZIP/HEX identity; and independently verified official stock SHA/CRCs. The code rejects mismatches, missing evidence, altered bytes, missing FF rollback tail, unexpected profile, absent or moved sectors.

```sh
python firmware/slzb-06p7u/qualification/p7u_rc1_package.py \
  --native-full-hex /private/native/DIAG-NOT-FLASHABLE.hex \
  --native-evidence-dir /private/BASE-VS-DIAG-EVIDENCE \
  --official-stock-bin /private/CC1352P7_coordinator_20240710.bin \
  --profile p7u-f07-stock \
  --git-commit <EXACT_NATIVE_CCS_COMMIT_SHA> \
  --output-dir /private/new-v0.1.0-rc1-R1
```

Re-run with profile `p7u-cap192-f07` and its exact native artifacts for R2. Per profile, the kit has 7 artifacts plus `RC1-MANIFEST.json` and `SHA256SUMS`: custom CCFG-free APP HEX + source/plan, manufacturer stock CCFG-free rollback APP HEX + source/plan/receipt. `verify_directory()` hashes every file, rejects extras/missing files, and confirms software-only status. Vendor original BIN is **never committed**. CI uploads **manifest only**, not stock-derived binary. Artifacts remain private; `flash_authorized=false`.

See `firmware/slzb-06p7u/qualification/STRICT_SPARE_P7U_FLASH_ROLLBACK.md` for two-phase read-only inspection and separately operator-authorized write/rollback.

Post-RC1 review hardening also requires the fixed seven-file kit, re-derives both sector plans, pins the deterministic stock rollback HEX, and cross-checks the profile, image hashes and native provenance fields. Missing files and inconsistent or unsupported hardware claims are rejected. These are integrity/consistency checks; compare the manifest with independent native CI evidence for source authenticity. The original source tag and archived private kits remain unchanged.

## Remaining hardware/release gates (cannot be closed by source tests)

1. Identify **actual spare** P7U fitted board, SLZB-OS bridge, model and management MAC; obtain stock `SYS_PING/SYS_VERSION`, 88B installed CCFG and private IEEE/NV snapshot, original firmware and backup. Confirm this is NOT active MR4U/P10.
2. Enter ROM BSL read-only, verify CC26x2x7 wafer ID, 704KiB flash, CCFG DIO15 backdoor and stock sector CRC; return to stock Zigbee app; **repeat ROM BSL entry**. This is not proven on our hardware.
3. Physical separately approved R1 app-sector flash, per-sector CRC and CCFG integrity validation, then re-enter BSL and **physically restore stock image** from the exact recovery kit. Confirm stock ZNP and BSL works afterward.
4. Only then try R2 CAP192/NV5, radio UART/RF/PA/clock, persistent security counter behavior, abrupt power-loss, large (>100) device soak and production migration/re-pair.
5. Restore/rebuild Zigbee network from a verified usable backup is **acceptable user fallback**, but not a substitute for recovering the TI radio if the application fails.

**Physical flash NOT performed. Source release ≠ production hardware certification. Parent PR #61 stays DRAFT, `main` untouched, active P10 and Z2M untouched.** Historical successful P10 recovery is encouraging but P7U CCFG shares the final main-flash sector unlike P10.

Sources: [parent PR #61](https://github.com/analienx/Zigbee-Coordinator/pull/61), [recovery tooling #78](https://github.com/analienx/Zigbee-Coordinator/pull/78), official SMLIGHT 20240710 URL `https://updates.smlight.tech/firmware/slzb06x/zigbee/slzb06p7v2/CC1352P7_coordinator_20240710.bin`.
