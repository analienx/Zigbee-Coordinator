# P7U stock NV4 compaction and NPI startup forensics — 18 October 2026

**Correction to the first NV5 hypothesis:** the five-page *conservative
inspection envelope* includes one erased sector outside the current stock
NVS. The stock firmware's binary NVSCC26XX base/size attributes support
**NV4 at `0xA6000/0x8000`**, not NV5 at `0xA4000/0xA000`. An independent
native/symbolic cross-check is still useful before enabling a Zigbee stack.

This is a **private-capture-derived, sanitized** conclusion for one
SLZB-06P7U, CC2652P7, HW 1.73. Raw snapshots and network secrets remain
on Zephyrus under `C:\Workspace\.analienx\zigbee-private`.
No hardware flash, BSL entry, Zigbee stack/NV initialization, restoration,
or network operation was performed during this investigation.

## 1. Reserved-sector differences: record-preserving NVOCMP rotation

Validated read-only captures (each has an independent identical second pass):

| Capture | Whole-flash SHA256 |
|---|---|
| Earlier/current stock | `632b1ce58a0e256ec4d4c2c720ccfe6355460e47d9b04b8c5ac00234c3fcfd46` |
| After UART diagnostic | `78e04c50459682439963c39ed00d089ae052daf2326948fbeced19aba4409fc4` |
| After later diagnostic | `7e2a98beccee74e3e3f32a4e4bbd74b7ce194b412dc52157e0fe8905176772ae` |

The conservative inspection envelope is `0xA4000..0xADFFF`, five 8KiB
sectors. The **four occupied/rotating pages** are `0xA6000..0xADFFF`.
We compared its exact TI-style compressed item headers and
CRC8 (poly 0x97) with `qualification/nv_five_page_forensics.py` on the
private machine. It exports **aggregate counts only**.

| Sector | Earlier state/cycle | Later state/cycle | Changed bytes |
|---|---|---|---:|
| `0xA4000` | erased | erased | 0 |
| `0xA6000` | FULL/1 | ACTIVE/3 | 7,181 |
| `0xA8000` | FULL/1 | COMPACTION DESTINATION/3 | 7,876 |
| `0xAA000` | ACTIVE/1 | FULL/2 | 7,688 |
| `0xAC000` | COMPACTION DESTINATION/1 | FULL/2 | 7,883 |

**Logical-item comparison (earlier -> later):**

- Exactly **366 unique active NV items** in each image.
- **366/366** active item identifiers and payload hashes agree exactly.
- **0 missing, 0 new, 0 changed** active payloads.
- **0 active duplicate IDs**; **0 CRC failures** across all **667** earlier
  and **714** later scanned records (including inactive history).
- Every active record's `systemID` is **1** in both captures (366/366).
  TI defines `NVINTF_SYSID_ZSTACK=1`, providing direct Z-Stack identity
  evidence without publishing individual NV identifiers.
- The next capture's high reserved pages match the prior capture byte-for-byte;
  CCFG was unchanged too. The later true TI NPI flash wrote only low APP
  sectors and did not run the Zigbee/NV stack; no newer full readback is claimed.

TI `nvocmp.c` defines page states `0x78=FULL`, `0x7C=ACTIVE`,
`0xFE=COMPACT_DESTINATION`, per-page cycle counters, format version 3 and
signature `0x96`. The observed page transitions and complete logical-item
parity constitute strong evidence of **normal lossless NVOCMP compaction**.
The specific command/boot that triggered the two cycle advances was not
observed, so causation is not assigned to a particular firmware action.

### Independent stock binary configuration cross-check

The earlier stock capture contains exactly one candidate for the TI
`NVSCC26XX_HWAttrs` adjacent `regionBase`/`regionSize` words ending before
CCFG/NV boundary: at APP offset **`0x2A0F4`** the 32-bit words are
**`0x000A6000`** and **`0x00008000`**. Their values map to **four** 8KiB
pages covering exactly the four occupied sectors. Neither `0xA4000` nor
`0xAA000` appears as an aligned NVS base value in the stock application.
TI's [NVSCC26XX hardware attributes](https://dev.ti.com/tirex/content/simplelink_cc13xx_cc26xx_sdk_8_32_00_07/docs/drivers/doxygen/html/struct_n_v_s_c_c26_x_x___h_w_attrs.html)
define precisely this adjacent base/size structure. The match is strong
binary evidence, though a symbol-linked call-site proof has not been made.

## 2. Crucial difference: native R4 ZNP's *configured* NV2 is incompatible

**Do not equate lossless existing NV pages with a safe new Zigbee stack.**

Our current TI donor B0/B1 configuration is based on `NVOCMP_NVPAGES=2`,
NVS `0xAA000` size `0x4000` (see `b0/README.md`, `b0/B0_BOARD_CONTRACT.json`
and `b1/tools/apply_b1.py`). It is not a correct physical NV mapping for
the observed **four-page** current network store at `0xA6000..0xADFFF`.
The prior `qualification/nv_compatibility.py` intentionally supports only
donor NV2 and cannot qualify these real snapshots by a two-page probe.

**Required work before any full Zigbee/NV-enabled firmware runs:**

1. Produce an image-specific **four-page** board profile: linker APP ends
   before `0xA6000` (conservatively `0xA4000` is fine), NVS
   `regionBase=0xA6000`, `regionSize=0x8000`, sector size `0x2000`, and
   `NVOCMP_NVPAGES=4`. Update native assertions, B1
   storage admission and CI provenance together; no overlapping linker map.
2. Build a **pinned genuine TI NV4 clone parser** with all writes, erases and
   recovery/compaction requests failing closed; compare its active items
   with the 366 record reference before relying on a normal NV init. This
   Python observer establishes record integrity but not all TI runtime
   lookup/counter/recovery semantics.
3. Verify Z-Stack logical item version/layout migration on a clone, with
   read-only identity/Trust Center/key-table/counter semantics and counter
   monotonicity; never print keys or IDs. Avoid migration defaults that erase
   or reset a live coordinator's existing network.
4. Only then evaluate Zigbee-enabled candidate boot/RF behavior. Transport-
   only APP diagnostic iterations may continue without changing these pages.

Relevant vendor guidance:

- TI [Z-Stack flash/NV layout and migration notes](https://software-dl.ti.com/simplelink/esd/simplelink_cc13xx_cc26xx_sdk/8.30.00.121/exports/docs/zigbee/html/zigbee/flash_memory-cc13xx_cc26xx.html)
- TI [NVOCMP multi-page compaction and power-cut recovery](https://software-dl.ti.com/simplelink/esd/simplelink_cc13x2_26x2_sdk/4.40.00.44/exports/docs/ble5stack/ble_user_guide/html/ble-stack-common/flash_memory-cc13x2_26x2.html)

## 3. Startup timing: measured warm reset and bounded polling

On the installed genuine TI NPI/MT transport-only image at commit
`1e803856fe841c9588b24f77cdf4a9c8cb7a1661`, package SHA256
`4a6bb28d982c74c0592f9fcee57a69d246dced3e7b4f6466675eece3fa614c70`,
we requested **three management radio resets** (no BSL, program, restore,
RF stack or NV) and polled only framed `SYS_PING` and `SYS_VERSION`:

| Reset | HTTP reset ACK | Full NPI readiness | Early failures |
|---|---:|---:|---|
| 1 | 0.297s | 2.468s | first socket/response timeout |
| 2 | 0.328s | 2.500s | first socket/response timeout |
| 3 | 0.312s | 2.515s | first socket/response timeout |

The first immediate probe timed out on **every** reset; the next probe
returned both valid TI responses. Earlier immediate-probe failures thus
have a practical explanation in **radio/bridge readiness after reset**, not
an established UART protocol defect. The exact delay's hardware/ESP/RTOS
origin remains unknown; the current measurement was after managed *resets*,
not independent cold power interruptions.

The original `SYS_VERSION` test expectation of 9 bytes was wrong: current
TI NPI returns **10 payload bytes**, FCS-valid. This validation error must
not cause a false rollback or report a bad firmware image.

For all future pilots, use `qualification/npi_startup_poll.py`: bounded
retry of both authenticated MT response shapes, ideally a 40-second ceiling,
instead of an arbitrary 22-second sleep or a one-shot immediate probe.
FCS verification rejects garbage/bridge noise and unexpected MT frames.
Operator invocation after a *separately managed* reset (replace the host):

```sh
python firmware/slzb-06p7u/r4/qualification/npi_startup_poll.py \
  --host P7U_BRIDGE_ADDRESS --port 6638 --max-seconds 40
```

The command sends **no reset, flash, NV, or network command**. It prints a
bounded JSON readiness receipt with retry counts and exits 0 only on
verified `SYS_PING` plus `SYS_VERSION`; exit 1 means the deadline expired.
Its timer starts at invocation, so a separately measured reset-to-ready
duration must also account for any delay before launching it.

## Disposition

- Reserved-sector **data-loss/corruption suspicion**: not supported by the
  complete per-record, CRC-checked comparison; record-preserving compaction
  is the strongly evidenced explanation. **Root trigger still unknown.**
- **NV4-to-current-R4-NV2 geometry/configuration mismatch: HIGH / blocking**
  full Zigbee NV initialization until source, native linker and a private
  read-only clone match four-page and semantic requirements.
- **Startup: operational workaround verified 3/3**; readiness-based retry
  implemented and unit tested. Cold-power robustness remains unmeasured.
- Installed diagnostic is left in place. No restoration performed.
