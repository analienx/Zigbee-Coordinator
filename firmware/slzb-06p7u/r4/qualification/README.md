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
| Transport diagnostic | `transport_profile.py`, existing TI NPI/MT owner | Only zero-length SYS_PING / SYS_VERSION; no NV initialization or Zigbee/RF stack startup |
| Board generation | `board_profile.py` | Source-level SysConfig power/UART selection and generated GPIO/CCFG audit |
| NV clone probe | `nv_compatibility.py` | Actual pinned TI init/item/CRC readers, with all writes/erases/compactions refused; structural evidence only |
| NV sector inventory | `nv_sector_inventory.py` | Sanitized page-header hints across reserved sectors; never selects active stock NV or authorizes startup |
| Native proof | `build_native.py`, `native_profile_audit.py`, `compare_replicas.py` | Genuine pinned TI compiler artifacts and independent firmware-byte comparison |
| Application packaging | `../release/r4_current_app_package.py` | Dynamic ELF/HEX sectors bound to a current direct-boot capture; no NV/CCFG payload |
| Transaction | `../release/r4_app_sector_transaction.py`, injected adapter only | Current application rollback, sector allowlist, vector sector last, status/CRC/readback gates |

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
task. It is purpose-built qualification firmware, not an unmodified ZNP image.
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

The observed outcome is `DIRECT_NATIVE_CCFG_UNCHANGED`. The next hardware
step would be a separately approved transport-only diagnostic trial with a
board-bound application-sector recovery package, independent native-artifact
parity and a bounded recovery window. The earlier capture approval does **not**
authorize that flash or another restart.

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

The later progression is transport diagnostic, B0, B1, B2, B3, B4. Require
100 diagnostic ping/version exchanges and three authorized restarts for the
transport stage, then relevant physical and persistence checks at every stage.
Full R4 requires an integrated 24-hour network soak, stable transport and
representative established router/end-device communication. Firmware rollback
after encrypted traffic must preserve current keys/epochs and monotonic
counters; stale full-flash/NV replay is prohibited.

Until those gates close, the precise deliverable is an audited diagnostic or
application candidate. It is not a boot-qualified or network-qualified R4.
