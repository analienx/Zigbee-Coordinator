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

`B0_BOARD_CONTRACT.json` is the machine-checked overlay: UART RX
DIO12 / TX DIO13, 115200 baud, hardware flow OFF; target part
CC1352P7; donor NV geometry preserved (`NVOCMP_NVPAGES=2`, NVS
`0xAA000`/`0x4000`); stock NPI ownership (no extra serial owner);
MT SYS_PING/SYS_VERSION retained with `startupFromApp`.

Deliberately absent from B0: custom scheduler, custom UART/NV
drivers, diagnostics endpoint, G7 port, routing tweaks, NV
page-count changes. Board/RF/driver claims that cannot be derived
from source stay `PHYSICAL_UNVERIFIED` or `OPEN` in the contract,
with the donor default preserved. Production-stock-NV boot is
PROHIBITED until a read-only compatibility proof plus an
authorized disposable-device trial both exist.

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

The hosted pipeline has already compiled the pinned SDK libraries and
imported the ZNP projectspec. Native ZNP compile/link and genuine
ELF/XML/HEX/BIN audit remain independent acceptance gates: until those
all pass, no firmware is claimed. Regardless of native build outcome,
P7U UART, PA/RF, CCFG and vendor NV/security compatibility remain
PHYSICAL_UNVERIFIED and production flashing is prohibited.

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
  -ccs.location <examples>/LP_CC1352P7_4/zstack/znp/tirtos7/ticlang/znp_LP_CC1352P7_4_tirtos7_ticlang.projectspec
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
  coverage, BIN equal to the HEX payload); exit 2
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
