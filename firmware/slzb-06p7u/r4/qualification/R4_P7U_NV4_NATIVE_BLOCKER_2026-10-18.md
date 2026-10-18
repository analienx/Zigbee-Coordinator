# P7U stock NVOCMP v3 / four-page admission — 2026-10-18

## Outcome

The fitted stock P7U reserves four 8192-byte internal-flash NVOCMP v3 pages at
`0xA6000..0xADFFF` (exclusive end `0xAE000`). The earlier two-page TI donor
configuration (`0xAA000..0xADFFF`) cannot safely replace that reservation.
The last CCFG sector remains `0xAE000..0xAFFFF`.

**Read-only native NV initialization is now verified, but physical flash is NOT
authorized.** Genuine, unmodified TI 8.33.00.16 `NVOCMP_initNvApi`,
`NVOCMP_initNv`, `NVOCMP_scanPage`, regular `NVOCMP_findItem`, actual item
reads, and the pinned TI CRC implementation were compiled for a four-page
in-memory NVS backend. Its write, erase, and compaction functions always fail
closed; no radio or debug probe is opened.

**B1 integration (same day):** After applying the exact-pinned B1 source
overlay, `nv4_b1_bridge.py` replaces its two-page-only admission with the
four-page bounded CRC reader and preserves the B1 existing-network security
signal, sticky HOLD and init-time write denial. A second native-host simulator
compiled the *actual post-B1 and post-bridge TI `nvocmp.c`*, including its
`NVOCMP_initNvApi`, against both private captures. Both returned success and
normal resume with **366 active items**, and **zero attempted writes, erases,
or compactions**; earlier/later scan totals were 667/714 records and
3936/4124 NVS reads. Synthetic bad-CRC and unsettled-compaction inputs HOLD.
All device bytes stayed private. Public CI for this post-B1 test has passed.

### Private captures, aggregate-only results

| Test | Earlier fitted P7U capture | Later fitted P7U capture |
|---|---:|---:|
| TI init return | `NVINTF_SUCCESS` (0) | `NVINTF_SUCCESS` (0) |
| TI init action | `NORMAL_RESUME` (1) | `NORMAL_RESUME` (1) |
| Page states in address order | `78,78,7C,FE` | `7C,FE,78,78` |
| Records read with genuine TI logic | 667 | 714 |
| Active items read/CRC-checked | 366 | 366 |
| NVS read calls | 2086 | 2180 |
| Write/erase/compaction attempts | 0 / 0 / 0 | 0 / 0 / 0 |
| Result | **PASS**, read-only | **PASS**, read-only |

The independent bounded C parser, using its own implementation of CRC8 and
physical page traversal, also passed both captures with the same record and
active counts. No item IDs, security material, payloads, or real NV bytes are
included in the repository or in the published receipts.

### Corrected false alarm

The first generated TI RAM clone reported two attempted one-byte writes and
one compaction for each real capture. Those reports were **harness artifacts**:
the extractor accidentally selected TI's conditional
`#if NVOCMP_FASTITEM` code. The pinned SDK sets
`#define NVOCMP_FASTITEM 0`, so production actually uses the **second**,
regular `NVOCMP_findItem` implementation. The optional fast branch has a
different page-buffer strategy and misinterpreted a cross-page item search.
Fixing the extractor to select the code that the stock TI compiler selects
produced clean, zero-write initialization for both captures. No device
modification or NV recovery was performed.

### Reproducing without private data

The following repository files and CI workflow provide safe, public tests:

- `nv4_source_overlay.py`: exact-pinned SysConfig, linker, compiler/linker
  `NVOCMP_NVPAGES=4` edits, only on disposable public TI source copies.
- `nv4_readonly_admission.[ch]`, `nv4_readonly_cli.c`: independent, bounded,
  explicitly read-only four-page scanner.
- `nv4_ti_host_clone.py`: selected genuine TI 8.33 init/read/CRC bodies,
  pinned by original git blob SHA, backed by read-only RAM NVS.
- `tests/test_r4_nv4_source_overlay.py`,
  `tests/test_r4_nv4_readonly_admission.py`,
  `tests/test_r4_nv4_ti_host_clone.py`: synthetic cases, negative tests,
  and native C compilation of exact upstream sources.
- `.github/workflows/test-r4-stock-nv4-source.yml`: fetches the required
  public TI sources at immutable revisions, validates pins, and exercises
  the above tests. It **never** flashes or accesses private NV.
- `nv4_b1_bridge.py`, `nv4_b1_ti_host_clone.py` and their two tests:
  post-B1 four-page exact-source integration, real TI init bodies, HALT
  controls and the two private-capture aggregate-only host results.
- `nv4_native_gate.py`, its negative tests and
  `.github/workflows/test-r4-stock-nv4-native.yml`: newly submitted real CCS
  full-stack ZNP build with stock `NVOCMP_NVPAGES=4`, current stock 20240716
  power/CCFG, B1 NV4 admission, generated SysConfig verification, and strict
  real linked HEX address audit. **Until that job succeeds its native proof is
  pending; this workflow never flashes.**

Public TI guidance backs up the required matching configuration in
compiler defines, linker preprocessing, SysConfig NVS region, and linker
allocation:

- [TI Z-Stack NV flash configuration guide](https://software-dl.ti.com/simplelink/esd/simplelink_cc13xx_cc26xx_sdk/8.30.00.121/exports/docs/zigbee/html/zigbee/flash_memory-cc13xx_cc26xx.html)
- [TI E2E: four NV pages, three storage + one compaction, and base-address mistakes](https://e2e.ti.com/support/wireless-connectivity/zigbee-thread-group/zigbee-and-thread/f/zigbee-thread-forum/951826/ccs-cc2652p-znp-crash-with-130-devices)
- [TI E2E: compiler project defines must change, not just `nvocmp.c`](https://e2e.ti.com/support/wireless-connectivity/zigbee-thread-group/zigbee-and-thread/f/zigbee-thread-forum/1020733/cc1352p-what-is-the-correct-way-to-allow-more-devices-to-join-the-network-created-by-the-znp)

## Remaining full-stack gate (not NV4 parser corruption)

1. **B1 admission adaptation — PASS in real TI host clone, not yet linked ARM.**
   Pre-init page geometry and the existing-network signal are now tested with
   both captures. Physical RF, security semantics and whole-image boot are
   NOT implied by a host result.
2. **Native executable/link audit — running in public CI.** Build pinned TI 8.33 ZNP for the
   fitted board with four-page NVS, confirm the entire linked application
   stops below `0xA6000`, compiled and generated NVS attributes exactly match
   `0xA6000/0x8000`, and direct-boot CCFG + sector protection match the live
   board. A host clone cannot prove those build outputs.
3. **Network/security state.** Before live RF, prove the old on-network state,
   Trust Center keys and monotonic frame-counter behavior survive Zigbee
   stack initialization, and that the fail-closed B1 gate prevents unwanted
   joining/factory resets/transmission when that proof fails. CRC-valid
   storage does not itself prove semantic compatibility.
4. **Transport readiness.** Poll genuine post-reset readiness; the immediate
   first probe has timed out before later queries succeeded. This is separate
   from NV4 and must be included in physical acceptance.

No restore action is scheduled: the intended flash transaction will leave
`0xA6000..0xADFFF` untouched. The working transport-only diagnostic remains
the last physically proven device state until the above gates close.

The current physical 18-Oct return-to-stock readbacks (as opposed to older
17-Oct R4/handoff incident documents) confirm `IMAGE_VALID_CONF=0` and the
official `20240716` power profile. The native candidate therefore retains
current stock direct-boot and power settings rather than applying the obsolete
20240710 or resident-handoff source overlay.

**Verdict: `NV4_B1_TI_READONLY_INIT_PASS`; `NV4_FULL_ZNP_NATIVE_CI_RUNNING`;
`FULL_STACK_FLASH_HOLD`.**
