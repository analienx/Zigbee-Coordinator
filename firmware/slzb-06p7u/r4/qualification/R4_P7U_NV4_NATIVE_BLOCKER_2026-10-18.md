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

**Factory-new security state found with an independent read-only inventory:**
Both same-board captures have `bdbNodeIsOnANetwork=0` and coordinator logical
type 0. The live NIB is absent. This is *not* a formed network requiring
restoration. Network-key/active-key, Trust Center seed/address, and the
coordinator-role and formed-state markers are structurally present, with
300 preallocated TCLK rows, three APS key-data rows and five NWK material
rows. These counts are aggregate only: no key contents, identities, full
item IDs or payload bytes left the private device. The pinned B1 security
precheck expressly accepts absent NIB when the on-network flag is zero, but
its actual post-boot formation and ZDO-ready diagnostic still require a
full-stack runtime test. Never treat the populated NV4 header as proof that
the Zigbee network was formed.

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
  `.github/workflows/test-r4-stock-nv4-native.yml`: successful real CCS
  full-stack ZNP build with stock `NVOCMP_NVPAGES=4`, current stock 20240716
  power/CCFG, B1 NV4 admission, generated SysConfig verification, and strict
  real linked HEX address audit. [Native CI run 39155330607](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39155330607)
  **passed** at exact head `6128dc25e94f1e5ba058e8f9cfda046d8a22803e`.
  The genuine ZNP APP ends before `0x2CA34`, with reset vector `0x25D3C`,
  stack `0x20023C00`, and matching complete stock CCFG SHA-256
  `fa750d46003f4cc059140ac75a83282ec61543b0d898c50cd2add61988c08b47`.
  It occupies 23 erasable 8KiB APP sectors below the conservative
  physical-image ceiling `0xA0000`. **No physical flash was performed.**
- `nv4_current_app_package.py` and its negative tests: offline-only bridge
  from exact digest-pinned native artifacts to private, current-board,
  APP-sector-only payloads; requires a separately SHA-pinned current full
  physical capture/profile, rejects any erase sector at or above `0xA0000`,
  and cannot initiate a flash. The native workflow now retains a short-lived
  **AUDIT ONLY — NOT FLASHABLE** build artifact for that private bridge;
  the full linked HEX and BIN must never be programmed directly.

Public TI guidance backs up the required matching configuration in
compiler defines, linker preprocessing, SysConfig NVS region, and linker
allocation:

- [TI Z-Stack NV flash configuration guide](https://software-dl.ti.com/simplelink/esd/simplelink_cc13xx_cc26xx_sdk/8.30.00.121/exports/docs/zigbee/html/zigbee/flash_memory-cc13xx_cc26xx.html)
- [TI E2E: four NV pages, three storage + one compaction, and base-address mistakes](https://e2e.ti.com/support/wireless-connectivity/zigbee-thread-group/zigbee-and-thread/f/zigbee-thread-forum/951826/ccs-cc2652p-znp-crash-with-130-devices)
- [TI E2E: compiler project defines must change, not just `nvocmp.c`](https://e2e.ti.com/support/wireless-connectivity/zigbee-thread-group/zigbee-and-thread/f/zigbee-thread-forum/1020733/cc1352p-what-is-the-correct-way-to-allow-more-devices-to-join-the-network-created-by-the-znp)

## Remaining full-stack gate (not NV4 parser corruption)

1. **B1 admission adaptation — PASS in real TI host clone and linked ARM.**
   Pre-init page geometry and the existing-network signal are now tested with
   both captures. Physical RF, security semantics and whole-image boot are
   NOT implied by a host result.
2. **Native executable/link audit — PASS; physical image transfer pending.**
   The first run's unrelated `find | grep -q` / `pipefail` SIGPIPE check was
   fixed. The pinned full ZNP genuine TI compiler and linker produced the
   expected NV4, stock CCFG and 23 low APP sectors. A successful native link
   does not prove board-side startup; current SHA-pinned private capture and
   protected APP-only ROM programming must be validated separately.
3. **Network/security state.** Current live stock is factory-new (`onNetwork=0`),
   not an existing formed network. Verify B1's genuine factory-new ZDO and
   Zigbee commissioning path without undesired record deletion, state HOLD,
   unrequested joining or premature RF. When a network is formed, Trust Center
   key and frame-counter persistence must then remain monotonic. CRC-valid
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

**Verdict: `NV4_B1_TI_READONLY_INIT_PASS`; `NV4_FULL_ZNP_NATIVE_CI_PASS`;
`FULL_STACK_PHYSICAL_STARTUP_UNTESTED`.**

## 19 October source-only admission hardening (partial T3)

The NV4 pre-init reader now rejects the two reserved values of TI's page
`allActive` indicator (only `ALLACTIVE=3` and `SOMEINACTIVE=0` are legal in
the pinned donor). It also refuses to classify a CRC-valid store containing
only active records outside the fitted P7U's Z-Stack system-ID namespace (1)
as an existing-network structural candidate. Such a store returns the new
`R4_NV4_NO_ZSTACK_RECORDS` status, mapped to B1's sticky unknown-layout
HOLD. The synthetic harness includes reserved-bit, blank, inactive-only,
foreign-only and mixed-namespace controls.

**This remains a structural preflight, not a formed-network classifier.**
Presence of a Z-Stack record does not prove a BDB on-network flag, NIB,
network identity, Trust Center contents, APS/NWK key material or counter
monotonicity. In particular, factory-new P7U captures with 366 live NV
records must not be reported as formed. The B1 later security precheck is a
separate fail-closed gate, and full pinned-source T3/physical behavior remain
open. These additions neither use private NV bytes nor authorize flash.

## 19 October pinned-Z-Stack marker classification (partial T3 follow-up)

The independent NV4 reader now distinguishes **structural validity** from
**semantic candidacy**. A CRC-valid item store still returns structural code
`R4_NV4_READONLY_STRUCTURE_ACCEPTED` (8), but the native B1 bridge does not
advance to its security precheck unless the separate `semantic_state` is
`UNCOMMISSIONED_CANDIDATE` (1) or `FORMED_CANDIDATE` (2). Every other semantic
state is an explicit sticky HOLD, even with otherwise valid pages and CRCs.

The classifier uses the immutable TI 8.33 source at SDK revision
`3615ad5d3f4f271258d18a2f5ce1785064ff9a58`: `osal_nv.c` encodes OSAL
legacy data in Z-Stack system namespace 1, legacy extended item 0, sub-ID
equal to the original OSAL NV ID. The pinned `zcomdef.h` defines coordinator
`logicalType` as sub-ID `0x87`, `bdbNodeIsOnANetwork` as `0x55`, and NIB as
`0x21`; `zglobals.h` defines coordinator role as 0. CRC validation streams
stored payloads through an existing bounded 64-byte transient buffer; only
the one-byte BDB and role values are separately retained in *semantic marker*
scratch. The NIB is checked for *presence only*: its contents, address, keys
and counters are not decoded into markers or emitted in diagnostics/logs.
Marker bytes are taken from the same read validated by CRC, not re-read
afterwards; an adversarial callback test enforces this TOCTOU boundary.

| Candidate | Role marker | BDB marker | Live NIB |
|---|---|---|---|
| Uncommissioned | present, coordinator 0 | present, false 0 | absent |
| Formed | present, coordinator 0 | present, true 1 | present |
| **HOLD** | missing, malformed or noncoordinator | missing, invalid or contradictory | any |

The previously observed stock P7U pair fits the *uncommissioned* marker
combination. An arbitrary CRC-valid record, an absent marker, BDB=1 without
NIB, BDB=0 with NIB, noncoordinator role or a malformed one-byte value
cannot substitute for it. Public tests exercise all such cases with purely
synthetic records, plus a post-B1 genuine TI host-clone HOLD-before-init
assertion. The prior source-only test runs pass locally; the native cloned
tests require the exact pinned TI/overlay inputs in hosted CI.

**Limit:** these are candidates, not security or physical-release proofs.
Neither candidate validates network identity, NV key material, TC counter
monotonicity, ABI compatibility, ZDO-ready boot, or actual RF operation.
Both still traverse B1's separate native security gate. The main T3 finding
and device-side validation therefore remain open; no NV write, compaction,
flash, merge or commissioning is authorized by this classifier.

## 19 October exact-TI four-page NOR power-cut matrix (partial T4)

The earlier two-page N24 power-cut test did not cover the multipage TI
`NVOCMP_compactPage()` implementation selected when `NVOCMP_NVPAGES=4`.
`nv4_powercut_ti_host_clone.py` now extracts the **unchanged** four-page
`NVOCMP_compactPage()`, `NVOCMP_compact()` and `NVOCMP_findSignature()` from
the SHA-pinned TI 8.33.00.16 vendor source. Its host-only NVS simulator
implements NOR one-way programming and sector erase in disposable RAM.
It replays a public synthetic, uncommissioned coordinator layout and cuts
power at **every committed-byte boundary of every NVS_write and NVS_erase**
performed by genuine TI compaction (including zero/all bytes). No actual
flash, device, RF, key material or private capture participates.

The test first exposed a missed *settled* TI page geometry: following
`NVOCMP_cleanPage()`, TI fully erases source sectors and then **reformats**
them with a signed `PGNACT=0xff` page header and blank item region. A normal
complete compaction can thus have `1 PGACT + 1 PGXDST + 2 PGNACT`, whereas
the independent preflight previously recognized only `1 PGACT + 1 PGXDST +
2 PGFULL`. The preflight now permits a formatted `PGNACT` only if all
signatures and bounded header fields are sound, its compaction state is
normal, its logical end is erased, and **every byte** of its data region
is blank. A physically raw/unformatted page, partially damaged page header,
stale payload or in-progress `PGXSRC`/`PGCDST` still HOLDS.

Pinned-source local result for this **one synthetic compacting workload**:

| Genuine TI NV4 compaction | Result |
|---|---:|
| Program/erase operations in uninterrupted pass | 26 |
| Distinct interrupted-byte-boundary media images | 24,703 |
| Independent preflight HOLD | 24,701 |
| Settled semantic candidates | 2 |
| Candidate cases verified by TI `NORMAL_RESUME` with no write/erase | 2 |
| Device flash authorized | **No** |

The independent scanner never invokes a write or erasure; its candidate
cases reproduce TI native initialization in read-only mode with the same
three CRC-authenticated live synthetic items. The test is reproducible by
`tests/test_r4_nv4_powercut_ti_host_clone.py` and the pinned-source
`.github/workflows/test-r4-stock-nv4-source.yml` workflow. The post-B1
exact-source clone also exercises the newly admitted formatted-inactive
geometry.

**Limits:** byte-boundary enumeration over one source-backed synthetic
workload is not a proof for all ring layouts, item populations, scheduler
interleavings, controller reset physics or NV transaction histories.
In particular it says **nothing about APS/NWK/Trust Center frame-counter
monotonicity** across successful commits and reset/rejoin, and does not
establish an existing formed-network migration. R4-R03/T4 and T5 remain
open pending wider invariants and counter-durability verification. The
physical/RF/release gates remain unchanged.
