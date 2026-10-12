# SLZB-06P7 — G2 code-review remediation and G3 preparation (2026-10-12)

**Disposition:** pristine TI SDK 8.32 / LP_CC1352P7_4 compiler baseline is validated; isolated NPI UART warning candidate rebuilt natively with *identical programmed HEX*; real SMLIGHT CC2652P7 board and CAP192 runtime remain unqualified. No flashing or network change authorized.

## Audited source and CI

- Draft PR: https://github.com/analienx/Zigbee-Coordinator/pull/61
- Fully passing real native TI CCS12.8 reference + UART candidate: https://github.com/analienx/Zigbee-Coordinator/actions/runs/38261234833
- Pristine G2 artifact: https://github.com/analienx/Zigbee-Coordinator/actions/runs/38261234833/artifacts/11752787235
- Separately compiled type-fix candidate: https://github.com/analienx/Zigbee-Coordinator/actions/runs/38261234833/artifacts/11752966919
- Pristine G2 ELF SHA256: 90b44e59af383d79dd90ae63a8d00013a07017343611a34afb52dcb587c04d24
- Pristine and type-candidate HEX SHA256 (identical): 5b19e5a3cac13349b30188bc1e5dcf78f544019516b43181f4cf126aeb47de13
- Candidate ELF SHA256: 9f1f8ed1da9af0b5fe7cc1d5bfc7b95a9ce346b2c296bce2e6b4b8633588dd0b
- Reference zip SHA256: bd31f11447f521c4132b717f665c524d7b9d5e870c0d7ca48a95823fedccbc03 (all 18 manifest entries independently verified)
- Candidate zip SHA256: 8bfd4a7f88d46b990af069c343cf2f68e21647b2a1f5d3029204215c336f2bb7

## Review remediation

1. **ELF-to-HEX:** exact checksummed program-address-and-byte equality with native ARM ELF loadable segments and corruption tests. An altered but otherwise valid HEX can no longer pass.
2. **Artifact publishing:** reference image is uploaded only after full native compiler, linker, CCFG/NVS, ELF/HEX and manifest checks. Failed jobs retain troubleshooting logs only.
3. **Linker and NV:** app bytes in HEX match linked FLASH allocation; CCFG bytes match FLASH_LAST; 16,384 B reserved NVS is genuinely uninitialized, with zero HEX payload bytes.
4. **Generated configs and reproducibility:** pinned CCS/SysConfig/SDK project, required generated Z-Stack macros, pristine TI source hashes, baseline ELF/HEX SHA256 and independent reproducibility.
5. **Two source warnings:** reversible isolated two-declaration correction of npiRxBuf and npiTxBuf from TI Char to uint8_t in source/ti/zstack/npi/npi_tl.c. Native CCS recompilation explicitly recorded in candidate log. Zero pointer-sign warnings and **identical firmware HEX**. The pristine G2 project was never patched.

## Installer-integrity lock — exact downloaded bytes

The source-test and real-build gate enforce SHA256 on TI vendor HTTPS archives before extracting/executing them:

- CCS12.8.0.00012_web_linux-x64.tar.gz: 3b56d5d07a47132408a116f01cc01587c88e78de7372e9623754f035e1c9d550
- sysconfig-1.21.1_3772-setup.run: 0c1674f82a53b187f60e376de3da2b719f003187c7437998c2ce3f975504d1d5

Recorded from TI-hosted HTTPS downloads in native CI on 2026-10-12. This is a **pinned observed digest**, NOT proof of an independently checked TI-published signature. CCS 12.8 is a web bootstrap downloading additional packages; recursive toolchain provenance remains a future supply-chain gate. Byte-identical compiled ELF/HEX golden hashes protect against unexpected emitted binary drift.

## Measured P7 reference memory and CAP192 uncertainty

- App flash 176,396 / 696,320 bytes linked, 519,924 bytes unused. SRAM 18,848 / 147,456 bytes linked.
- heapStart 0x20006030, heapEnd 0x20023C00: **121,808 bytes linker address span**, not measured runtime allocation or guaranteed free heap.
- Stack reserved: 1,024 bytes; runtime high-water unknown.
- NV: two 8KiB erase sectors, 16KiB total, with no initialized HEX records. CCFG: final 8KiB flash sector contains 88 bytes.
- Conditional capacity illustration: at an *assumed* 80% utilization of one 8KiB page, 192 serialized entries only fit if each total record is approximately 34 bytes or less; 48-byte records would fit only 136. This does not prove actual NVOCMP record sizes, compaction strategy, available keys, security counters or power-failure recovery.

Real CAP192 requirements (192 TC keys, NWK list 96, addresses 298 derived, route/source-route 128/128, neighbors 64) remain **unimplemented for P7**. Subsequent genuine runtime tests must measure heap/task/ISR stacks, NV fill and interrupted compaction, live routing, recovery and security-counter continuity. No simulated estimate is a hardware PASS.

## SMLIGHT physical safety constraints

The authentic original SLZB-06P7 fitted PCB revision, original CCFG/BSL enable/backdoor control, ESP↔radio UART/reset nets, RF frontend/EIRP, original NV layout and tested restore path remain unproven. The TI-documented CC2652P7 default ROM bootloader UART RX DIO12 / TX DIO13 does not prove the SMLIGHT radio PCB routing. TI LaunchPad CCFG and other SMLIGHT models are not acceptable substitutes.

G3 hardware evidence ledger and 12 negative tests fail closed. No coordinator, Home Assistant, Zigbee2MQTT, radio, keys, network, UART, BSL, flash or erase operations were used. The PR must remain draft and not flashable.

## CI efficiency

The expensive CI stage now has a fail-safe PR synchronize *before/after commit-delta* gate rather than trusting GitHub PR path filters, which evaluate the accumulated PR file list. A documentation-only synchronization may skip the native build only when the commit delta is available and verified. Missing/ambiguous deltas rebuild. The cancellation lock is on the native job, so docs-only events cannot terminate an active genuine compiler build. Cheap source tests always run; manual dispatch forces a native build.

Source/path-gate workflow changes are verified separately by GitHub Actions; see the latest PR checks. **Document-only updates must not be described as new native binary attestations.**

**Final boundary:** G2 native compiler/link reference PASS, G3 isolated UART correction compiled PASS, physical SMLIGHT/RF/BSL/NV migration BLOCKED, CAP192 runtime qualification BLOCKED, flash_authorized false.
