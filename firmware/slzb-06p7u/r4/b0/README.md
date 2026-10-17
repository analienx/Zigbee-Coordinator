# R4-B0 native P7U ZNP: thin overlay + hosted build orchestration (issue #90)

Status: SOURCE-ONLY staged source. No binary is claimed until the
hosted `r4-b0-native-build` job turns READY with real ELF/map/HEX
artifacts. Compile success, when it happens, proves only that the
donor composition builds -- never board RF, NV equivalence with
vendor 20260310, SYS_PING reachability, or mesh reliability.

## 1. Donor composition (exact, verified upstream)

Donor pair at release `lpf2-8.33.00.16` (see `B0_DONOR_INVENTORY.json`
for the machine-checked file list; every name below was re-derived
with `git ls-tree -r` at the pinned SHAs, never invented):

- `TexasInstruments/simplelink-zstack-examples@87ff5b63`
  ZNP project `examples/rtos/LP_CC1352P7_4/zstack/znp/`
  - CCS projectspec
    `tirtos7/ticlang/znp_LP_CC1352P7_4_tirtos7_ticlang.projectspec`
    (device `Cortex M.CC1352P7`, TICLANG cgt `3.2.2`,
    `NVOCMP_NVPAGES=2`, stock NPI defines
    `-DNPI -DNPI_USE_UART -DZNP_NPI`, stock startup order,
    SysConfig-driven linker `ti_utils_build_linker.cmd.genlibs`
    plus ROM `timac_rom_PG2_0_rom_api_linker.cmd` and
    `driverlib.lib`, post-build `tiarmobjcopy` HEX emission).
  - SysConfig `tirtos7/znp.syscfg`
    (`--board /ti/boards/LP_CC1352P7_4 --rtos tirtos7`;
    NVS internal `CONFIG_NVSINTERNAL` base `0xAA000` size `0x4000`;
    CCFG from `lprf_ccfg_settings.js`; **no NPI UART pin override**
    -- the stock file leaves UART board-defined).
  - Submodule gitlink `cc13xx_cc26xx_sdk` mode `160000` equals the
    SDK pin below (coherent 8.33 pair, both commit messages name
    `lpf2-8.33.00.16`).
  - Upstream `README.md` section "Build SDK Libraries": SDK
    libraries must be built **before** the project build.
- `TexasInstruments/simplelink-lowpower-f2-sdk@3615ad5d`
  app main `source/ti/zstack/startup/main.c`, NPI group
  (`npi_task.c`, `npi_tl_uart.c`, ...), MT group (`mt_sys.c`, ...),
  board linker `source/ti/zstack/boards/cc13x2x7_cc26x2x7/cc13x2x7_cc26x2x7_tirtos7_ticlang.cmd`
  (the exact .cmd the pinned projectspec links: SDK blob
  `1e5777c2`; FLASH app `0x00000..0xA9FFF`, FLASH_NV
  `0xAA000..0xADFFF`, FLASH_LAST `0xAE000..0xAFFFF` with `.ccfg`
  at HIGH, `.resetVecs`, `--stack_size=1024`),
  startup `startup_files/startup_ticlang.c` + `ccfg.c`.
- `Koenkk/zigbee-herdsman@0968f97` (v10.9.1, ABI reference only).
- `Koenkk/Z-Stack-firmware@5e4db67` comparison-only patch donor
  (blobs `e015d9a9` / `25f8bb3f`); the 4096 C/IRQ stack figure comes
  from this donor and stays OPEN until native map proof exists.
  The donor default enforced by the audit is **1024**.

## 2. B0 overlay scope (narrow by design)

`B0_BOARD_CONTRACT.json` distinguishes a **historically measured fitted
P7U board** from the unqualified new R4 image. Issue #90 correction
[6215896717](https://github.com/analienx/Zigbee-Coordinator/issues/90#issuecomment-6215896717)
recovers earlier physical facts: rev 1.73 ESP32-S3 / CC2652P7, stock 20240316
SYS_PING/SYS_VERSION/IEEE on USB, confirmed 704 KiB two-pass ROM recovery,
actual R2 ELF + vendor 20240710 UART0 RX DIO12 / TX DIO13,
115200 baud, hardware flow OFF; SMLIGHT manufacturer board reference
pins ESP TX GPIO17 to radio RX DIO12 and radio TX DIO13 to ESP RX GPIO18.
The established physical pinout must **not** be repeatedly requalified.

The genuine older-vendor 20240710 CCFG differs from the pinned TI
LaunchPad CCFG in DCDC_RECHARGE and DCDC_ACTIVE, both disabled on P7U;
historical `p7u_stock_ccfg.py` already implemented
`device.enableDCDC = false;`. R4's `tools/b0_p7u_board_overlay.py`
reuses this known vendor-specific adjustment and replaces the donor
XDS110UART selection with an explicit UART0 DIO12/DIO13 assignment,
only in the disposable CCS project copy. It emits a source SHA receipt.
TI 8.33 generated UART pinmux, linked CCFG and RF/PA remain
**R4_IMAGE_UNVERIFIED** until independently verified from real native
artifacts. None of these historical facts establishes equivalence with
later vendor 20260311/20260310 CCFG, routing or security/NV.

The machine-checked contract keeps the target CC2652P7 and
donor NV geometry (`NVOCMP_NVPAGES=2`, NVS
`0xAA000`/`0x4000`); stock NPI ownership (no extra serial owner);
MT SYS_PING/SYS_VERSION retained with `startupFromApp`.

Deliberately absent from B0: custom scheduler, custom UART/NV
drivers, diagnostics endpoint, G7 port, routing tweaks, NV
page-count changes. Board/RF/driver claims that cannot be derived
from source stay `PHYSICAL_UNVERIFIED` or `OPEN` in the contract,
with the donor default preserved. Production-stock-NV boot is
PROHIBITED until a read-only compatibility proof plus an
authorized disposable-device trial both exist.

## 2a. Reviewed B0 status and protected-NV flash boundary (17 October 2026)

**Source/native build PASS, physical boot NOT PROVEN.** Actual source
PR [#91](https://github.com/analienx/Zigbee-Coordinator/pull/91)
merged by squash commit `512e620f1901bf83c6453410d7e411126b7853a3`
into `review/p7u-r4-issue87-independent-fixes` (**PR #89 HEAD,
NOT `main`**). Integration to `main` remains staged behind open
R4 provenance/diagnostic PRs #86 and #89. Genuine exact-PR-head native
build [38923787459](https://github.com/analienx/Zigbee-Coordinator/actions/runs/38923787459)
was green with actual ELF/XML/HEX/BIN, verified generated UART/CCFG,
strict reset-vector audit, and toolchain receipts.

**Do NOT flash the native 704 KiB `.bin` directly.** TI
`tiarmobjcopy -O binary` spans `0x00000..0xAFFFF`, including 16 KiB
of artificial padding across reserved **FLASH_NV
`0xAA000..0xADFFF`**. A flasher writing all `.bin` bytes would write
that padding into NV and can destroy Zigbee identity, counters or
keys. The Intel HEX has NO actual NV DATA records, but this does not
establish safety of a particular programmer, OTA method or hardware.

`tools/b0_flash_boundary.py` verifies hashed collected HEX/BIN
contents, absence of HEX NV writes, the exact flat BIN span and
its uniform synthetic NV padding, then emits
`DO_NOT_FLASH_NV_BOUNDARY.json` with **flash/release/migration all
FALSE**. This is a denial/traceability certificate, **never an
authorization to flash either HEX or BIN**. Standalone hostile tests
also fail on manifest digest mismatch, mixed NV padding, inserted NV
records, altered app payload and out-of-range HEX writes.

Separate future approval still requires a dedicated offline-protected
**address-aware writer** specification, verifiable NV-safe flash
range/erase operations, backed-up security identity and monotonic
counters, independent review, physical cold boots / SYS_PING / RF
validation on an isolated board. No source CI success changes those
requirements. See [#90](https://github.com/analienx/Zigbee-Coordinator/issues/90).

## 3. Hosted native build path (staged, fail-closed)

Toolchain: CCS `12.8.0.00012`, TI-ARM-CLANG `3.2.2.LTS`, SysConfig
`1.21.1.3772` installed explicitly standalone on `ubuntu-22.04`
(CCS 12.8 officially validates Ubuntu 22.04; it bundles only
SysConfig `1.21.0.3721`, never relied on for the `1.21.1.3772`
pin). Exact Linux installer SHA-256 digests were recovered from
TI's official versioned download pages (2026-10-16) and are enforced
in `tools/b0_fetch_ti.py`, `B0_DONOR_INVENTORY.json` and the
provisioning receipt. Download archives are persisted only after a
successful publisher-hash check, before the potentially failing native
build. The CCS 12.8 bundled SysConfig 1.21.0 launcher is dispatched,
with a reversible hosted-only binding receipt, to verified standalone
SysConfig 1.21.1+3772; it is NEVER used as the old 1.21.0 binary.

The native SDK + ZNP CCS compile/link and genuine ELF/XML/HEX/BIN
checks have passed on the pinned B0 source SHA. The enhanced offline
flash boundary remains separate from the native ELF acceptance. The
physical behavior of the NEW R4 image, PA/RF/clock and later vendor
NV/security compatibility remain UNVERIFIED. Source success never
authorizes hardware flash or production deployment.

Publisher SHA-256 evidence:
- CCS 12.8 Linux: `fa807c9ea3bc8a558c4c9bef64c37261c1146d0b9da96ae7867e1b5e3046e06d`
- SysConfig 1.21.1 Linux: `0c1674f82a53b187f60e376de3da2b719f003187c7437998c2ce3f975504d1d5`
- TI ARM Clang 3.2.2 Linux: `2864bb1013ec60b1290f92ff723a4fc222653db1278c08ad81af6063f698dec9`

When provisioned, the exact build sequence is:

```bash
git submodule update --init cc13xx_cc26xx_sdk
# 1. SDK libraries first (upstream README requirement)
#    (SDK-specific library build per SDK README at the pinned SHA)
# 2. Headless CCS import + build (TI documented CLI)
eclipse -noSplash -data /tmp/b0ws \
  -application com.ti.ccstudio.apps.projectImport \
  -ccs.location <repo-root>/examples/rtos/LP_CC1352P7_4/zstack/znp/tirtos7/ticlang/znp_LP_CC1352P7_4_tirtos7_ticlang.projectspec
eclipse -noSplash -data /tmp/b0ws \
  -application com.ti.ccstudio.apps.projectBuild \
  -ccs.projects znp_LP_CC1352P7_4_tirtos7_ticlang
# 3. Audit the real artifacts (fails on hash/link/CCFG/NV/stack)
python firmware/slzb-06p7u/r4/b0/tools/b0_image_audit.py audit \
  firmware/slzb-06p7u/r4/b0 --artifacts <build-out>
```

Reference: TI CCS command-line projects
(`https://software-dl.ti.com/ccs/esd/documents/ccs_projects-command-line.html`).

## 4. Stageable validation without the toolchain

- `tools/b0_overlay_validate.py validate <b0-dir>` -- offline
  overlay consistency (pins, verified path set, UART values,
  NV pages, forbidden claims).
- `tools/b0_image_audit.py audit <b0-dir> --artifacts <dir>` --
  artifact binding, real linker-invocation evidence (CCS
  projectBuild + `tiarmclang --xml_link_info` + objcopy + syscfg),
  genuine TI `--xml_link_info` XML geometry (FLASH_NV `0xAA000` /
  `0x4000`, `.ccfg` in FLASH_LAST at HIGH, `.resetVecs`) plus an
  independent ELF cross-check (ARM magic, entry agreement) plus
  HEX/BIN cross-binding (genuine Intel HEX records, data inside
  XML regions and outside FLASH_NV, `.resetVecs`/`.ccfg`/entry
  coverage, native 704KiB BIN address-preserving with uniform\n  padding through protected NV (NEVER flash raw BIN)); exit 2
  `B0-AUDIT-BLOCKED` when no artifacts exist (never a pass). The
  legacy REGION/CSTACK/VECTORS text format is rejected as
  synthetic.
- `tools/b0_provision.py provision` -- toolchain presence probe
  with `READY`/`BLOCKED` receipt (exit 1 when blocked).
- `fixtures/` -- valid + hostile artifact sets (including a
  HEX/BIN-tampered pair with recomputed digests that must fail
  at the HEX/BIN cross-binding) with `SHA256_RECEIPTS.txt`;
  `tests/test_r4_b0_*.py` fail if the overlay/audit logic is
  removed.
