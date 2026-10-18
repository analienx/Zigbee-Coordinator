# P7U staged qualification

This is the replacement qualification path for the SLZB-06P7U r1.73 /
CC2652P7. The physical board is now running stock 20240716, verified after
the approved duplicate ROM capture on 18 October. Older documents describing
a spare board running silent R4 are superseded. This is the only available
coordinator.

No module here grants hardware authorization. There is no live-radio CLI.
Current-board captures, IEEE/security material and restore images stay private.

## Implemented stages

| Stage | Implementation | Meaning |
|---|---|---|
| Current capture | `capture_pair.py`, injected read adapter only | Two complete bounded reads, ROM CRC and identity checks; no entry/reset/write API |
| Current profile | `../release/r4_current_board_profile.py` | Externally hash-bound boot/power/protection observations; NV semantics remain unknown |
| Transport diagnostic | `transport_profile.py`, existing TI NPI/MT owner | Only zero-length SYS_PING / SYS_VERSION; no NV initialization or Zigbee/RF stack startup; physically silent twice |
| UART startup smoke | `uart_smoke_profile.py`, `uart_smoke_native_audit.py` | Independent SYS/BIOS task writes a repeatable UART2 marker, without NPI/MT, NV, Zigbee or RF; offline only |
| Board generation | `board_profile.py` | Source-level SysConfig power/UART selection and generated GPIO/CCFG audit |
| NV clone probe | `nv_compatibility.py` | Actual pinned TI init/item/CRC readers, with all writes/erases/compactions refused; structural evidence only |
| NV sector inventory | `nv_sector_inventory.py` | Sanitized page-header hints across reserved sectors; never selects active stock NV or authorizes startup |
| Native proof | `build_native.py`, `native_profile_audit.py`, `compare_replicas.py` | Genuine pinned TI compiler artifacts and independent firmware-byte comparison |
| Application packaging | `../release/r4_current_app_package.py` | Dynamic ELF/HEX sectors bound to a current direct-boot capture; no NV/CCFG payload |
| Transaction | `../release/r4_app_sector_transaction.py`, injected adapter only | Original capture-receipt and live management identity pins, current application rollback, sector allowlist, vector sector last, status/CRC/readback gates |

Public vendor and historical power references exercise the compiler. They are
**not** evidence of current-board settings. Earlier app-only experiments preserved
physical CCFG, so their unused compiled power words do not prove the cause
of ZNP silence.

## Native build

The `P7U qualification transport dual native (NO FLASH)` workflow builds the
verified public 20240716 power reference twice on separate Ubuntu runners.
Historical references remain available for offline comparison. The workflow uses the
existing checksum-pinned CCS 12.8 / TI ARM Clang 3.2.2.LTS / standalone
SysConfig 1.21.1.3772 bootstrap and TI SDK/examples 8.33 pins.

Each build runs a host harness extracted from the actual transformed TI code,
then compiles real ARM ELF/XML/HEX/BIN. Acceptance requires the transport
identity and functions in the ELF, and rejects linked NV/stack/RF mutation
functions. The generated board audit independently checks active UART0
DIO12/13, flow-off, VDDR/DC/DC words and absence of unrelated configured GPIO
or external-flash initialization. Matching HEX/BIN across replicas establishes
repeatability, not physical boot or a healthy network.

The diagnostic still starts TI SYS/BIOS, OsalPort support and the original NPI
task. The post-trial v2 profile adds one delayed diagnostic-only `0x41/0xF7`
AREQ frame (`0xA7` payload) using the **existing** NPI MT TX owner after
successful UART/NPI initialization. Seeing the beacon proves this initialization
path executed and the TX path is observable; not seeing it is inconclusive.
The ordinary solicited `SYS_PING` and `SYS_VERSION` remain unchanged. It is
purpose-built qualification firmware, not an unmodified ZNP image.
Normal B0 and cumulative B1-B4 are not released by this diagnostic workflow.

The official 20240716 P7U catalog artifact is now verified offline by
`vendor_stock.py` (SHA256, bounded SLZB segment layout and both segment CRCs).
Its application has vectors at zero and its 88-byte CCFG sets IMAGE_VALID to
zero, MODE_CONF_1 to `0xFFC00010` and MODE_CONF to `0xF1B9C1FF`. It contains no
resident-loader segment. The sanitized receipt is
`vendor-stock-20240716.json`. This supports the unchanged-CCFG direct boot path
**if fresh physical capture confirms those installed settings**; updater write
policy must not be inferred from the download alone.

## Completed physical read-only evidence (18 October 2026)

Two private full 704-KiB ROM captures matched byte-for-byte. The approved
return to stock produced valid `SYS_PING` and `SYS_VERSION=20240716` after the
initial delayed response; no second restart was needed. Installed CCFG matches
official stock `20240716` and selects vector address zero, with DIO15-low
ROM-BSL backdoor configuration retained. Thus the current **boot layout**
permits a native application without changing CCFG. It does **not** prove
that a custom binary actually boots.

A read-only reserved-sector inventory identifies four possible NVOCMP v3
page headers at `0xA6000`, `0xA8000`, `0xAA000` and `0xAC000`. The third
header byte differs (`0x0C` vs `0x0F`) only in the low two `allActive` bits;
both encode version 3 according to TI's pinned NVOCMP bitfield definition.
The sectors `0xA0000..0xA5FFF` appear erased. No active stock NV page pair
has been identified; no key, counter, or downgrade
compatibility follows from these structural hints. No flash programming or
erasure occurred during the capture. Raw captures, identifiers, secrets and
restoration bytes stay private on Zephyrus.

The ROM capture receipt's **live management identity SHA-256** and the
current profile's **canonical private board identity SHA-256** are distinct
digest domains. A later admission/erase must validate an externally pinned
original capture receipt, bind both matching readbacks to the current profile,
and re-read the live management identity against the receipt's pin. It must
never substitute the profile digest as a fabricated live identity response.

## First owner-approved flash trial and focused isolation (18 October 2026)

On the isolated P7U R1.73, the exactly three application sectors at
`0x02000`, `0x04000`, `0x00000` were programmed vector-last and independently
ROM CRC-verified. The first candidate did **not** respond to bounded
post-reset UART SYS probes. The operator immediately restored those exact
three stock sectors, reverified their CRCs and unchanged CCFG, and passed
stock SYS_PING and SYS_VERSION=20240716. The device is on original stock.
This is **not** successful R4 boot qualification, and no retry is authorized.

After this trial, the *actual captured stock* UART2 hardware attributes were
compared against the exact-head native ELF: 20 of 22 32-bit fields match; only
application-dependent SRAM buffer pointers differ. This independently confirms
UART0 (`0x40001000`), RX DIO12, TX DIO13 and DMA/IRQ fields on the P7U. The
entire native 88-byte CCFG matches installed stock byte-for-byte (SHA-256
`fa750d46003f4cc059140ac75a83282ec61543b0d898c50cd2add61988c08b47`).
The native loadable application ends below `0x6000`, within the three written
sectors. These observations exclude three immediate failure hypotheses but do
not locate a runtime startup failure. Raw stock bytes remain private.

The second isolated, approved trial used the NPI-startup beacon but again
received **zero UART bytes** (no beacon and no SYS_PING); SYS_VERSION was not
reached. The same three original sectors were restored and CRC-verified; stock
SYS_PING and SYS_VERSION=20240716 passed after the rollback. This repeats the
transport failure without proving that modified `main()` or the NPI task ran.
The new UART2 smoke profile is the next **offline** diagnostic image; it has
not been flashed. No further reset, flash, NV, network or RF operation is
authorized by this text. See issue #103 and draft PR #135.

## UART2 startup smoke (independent of NPI)

`build_native.py --profile uart-smoke` changes only the exact pinned TI
`source/ti/zstack/startup/main.c` in a disposable 8.33 SDK tree. It preserves
genuine TI C runtime, SysConfig, board Power/GPIO initialization and the
direct-ROM linker, but skips stack, NV, RF and NPI services. One newly
constructed SYS/BIOS task opens the generated `CONFIG_DISPLAY_UART` at 115200
8N1 and writes `FE 01 41 F7 A8 1F` once per second. The `A8` byte is different
from the previous post-NPI `A7` beacon. An optional debugger-only volatile
stage variable marks early main/Board/Task/UART/write steps. It does not
cause any flash or GPIO activity beyond TI board/UART setup.

The separate one-run native workflow checks source pins, linker symbol graph,
the real ELF/HEX/BIN binding, unchanged stock power/CCFG words, and that all
non-CCFG linked bytes remain in the first three 8 KiB APP sectors. It does
**not** grant a flash; it cannot establish physical boot or Ethernet bridge
delivery. A future trial requires a separately authorized, capture-bound
three-sector private package and rollback. If the repeated marker appears,
return to NPI initialization for the fault. If not, investigate early boot,
Task/UART2 initialization and bridge startup **without assuming a result**.

## Previous owner-approved capture procedure (completed)

The approved capture window used this bounded procedure:

1. Confirm the private management identity and arrange exclusive ownership of
   TCP 6638. Do not change Zigbee2MQTT/HA settings during boot diagnosis.
2. After specific approval, enter ROM BSL using the existing SMLIGHT management
   transport. Capture two 704 KiB passes with `capture_pair()`; its total deadline
   defaults to ten minutes and each request to six seconds. It cannot retry,
   erase, program, reset or enter BSL itself.
3. Leave BSL through the separately approved management restart; verify stock
   SYS_PING and SYS_VERSION. The capture receipt intentionally cannot claim
   that return to stock was verified.
4. Pin the private capture/identity hashes and run the current-profile analyzer.
   Never substitute the October 16 captures for the new installed stock state.

The selected boot configuration determined the next gate:

- `DIRECT_NATIVE_CCFG_UNCHANGED`: direct-native application packaging may be
  prepared, subject to board/profile/sector checks and another specific trial
  approval. CCFG remains untouched.
- `AC000_RECOVERY_REQUIRED`: native deployment remains blocked. Do not repeat
  the old trampoline or use the only board for a first risky top-sector erase.
- `UNKNOWN_BOOT_BLOCKED`: reconcile the selected vector/backdoor/layout first.

The observed boot configuration is `DIRECT_NATIVE_CCFG_UNCHANGED`. The first
transport trial has already failed and been restored, as detailed above.
Any revised-image trial requires a **new**, explicitly identified image,
capture-bound restoration package and separate owner authorization.

CCFG restoration must account for the entire final 8 KiB sector, including any
resident-loader tail. TI top-sector erase restores TI defaults after erasure;
this is not documented as power-fail atomic. The generic SMLIGHT bank-erase
workflow and ROM DOWNLOAD_CRC are not the bounded deployment method.

## Network-capable release gates

Before normal B0 startup, establish the **current** NV geometry and semantics
using a private clone and actual candidate NV code. Preserving flash sectors
does not stop firmware NV initialization from modifying them. No automatic
migration, blank-NV relocation, network formation or re-pairing is permitted.

The existing full composite still records incomplete B3 compaction coverage
and unreviewed seed-status callers. Those flags must not be changed to true
because a build links. Complete the fault paths with real-source tests before
network qualification. Retain the existing B2 P1 capacities (source routes 192,
neighbors 64, routes 128) and existing B4 ABI; audit generated RF/PA settings
against actual board evidence before RF startup.

The later progression is transport diagnostic, B0, B1, B2, B3, B4. For the
current shortest-path diagnostic, require just one trustworthy beacon/probe
observation and immediately restore stock if it fails; this does **not** waive
the eventual network/persistence gates needed for a production coordinator.
Full R4 requires an integrated 24-hour network soak, stable transport and
representative established router/end-device communication. Firmware rollback
after encrypted traffic must preserve current keys/epochs and monotonic
counters; stale full-flash/NV replay is prohibited.

Until those gates close, the precise deliverable is an audited diagnostic or
application candidate. It is not a boot-qualified or network-qualified R4.
