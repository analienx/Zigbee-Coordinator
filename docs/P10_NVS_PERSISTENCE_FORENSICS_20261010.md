# CC2674P10 / MR4U forensic investigation — NVS lost after firmware updates

**2026-10-10; read-only/source-only investigation of issue #53.** No P10
reset, flash, NV write, Z2M start, or network mutation was executed
during this investigation. Original and newly sealed 103-association
backup files remain private. This document separates **observations**
from **hypotheses**.

## 1. Incident facts (already captured and hashed)

- Hardware SLZB-MR4U, radio index1, TI CC2674P10,
  Ethernet management. The **read-only current `/ha_info`** identifies
  the bridge as **SLZB-OS `v3.4.1.dev1`**, firmware channel **dev**,
  hardware version `174`. This is the management OS, not the TI ZNP
  revision. Public release notes:
  https://smlight.tech/support/manuals/books/slzb-os/page/changelog-slzb-os
- The first post-R11/R12 failure could have been confounded by a prior
  `startupFromApp` hang. The **second recurrence isolates the change
  better**: while rev8320062 was running, a bounded 630-write NV restore
  completed, followed by a soft reset and full **103/103 link-key /
  103/103 address-association / original NIB / counter** verification.
  A newly sealed postrestore backup exists on Zephyrus.
- Then one A1 rev8320063 firmware update returned management
  `ZB_FW_done`; SYS_VERSION 8320063 / SYS_PING 3/3. Yet ZNP
  `osalNvLength(33)=0` (NIB) and `osalNvLength(35)=0` (address manager).
  No Zigbee startup was sent between restoration and image change.
- The successful update only establishes that the **P10 code image
  boots**, not that NVS regions were preserved. The updater call carried
  `eraseNVM=0`; no ROM BSL erase-range trace was captured.
- No event55 `A1_ARMED` was received in the postflash listener. Because
  its implementation emitted only once, possibly before TCP attachment,
  this is **not** proof that A1's one-shot transition failed. This is a
  separate observability issue; avoid using it as NVS evidence.

## 2. Proven source and build relationships

Downloaded, built and independently hash-checked exact artifacts:

| Property | R12 A0 | R12 A1 |
|---|---|---|
| TI ZNP firmware | rev8320062 | rev8320063 |
| Source commit | `70a5643f8ffe37262e73ee75ed3a687ec3c6722d` | `e601143594192c42bd9ecaeba9be5b0d71d3caaa` |
| SDK commit | `6499c3f53fc5fb5806213be695450a7b43fbaf3d` | **same** |
| `provenance/nv-contract.json` | **identical** | **identical** |
| `provenance/nv-lab-report.json` | **identical** | **identical** |
| CCFG contract | identical except relocated reset vector | identical except relocated reset vector |
| Reserved NVS | **0x000F8800–0x000FFFFF** | **same** |
| Region size | **30,720 bytes = 15 × 2,048** | **same** |
| Image contains NVS data records | no | no |

These facts strongly disfavor **an intentional NVS geometry or NVOCMP
driver-version change between the two builds**. They do *not* establish
that the web uploader avoided bank erase, or that boot-time code did
not initialize or compact flash.

The exact TI SDK source at
`source/ti/common/nv/nvocmp.c` is SHA256
`b4b12fefaa6db77a4fd902094636248e728a9c09194db058b6b4d064c52a432a`
in the pinned checkout.

**Important destructive behavior in TI NVOCMP, proven by source:** in
`NVOCMP_scanPage()` (roughly line 2,080), any invalid page state,
version or signature enters a path calling
`NVOCMP_erase(pNvHandle, pg)`; NVOCMP initialization also selects
compaction/erase/recovery paths on inconsistent page states. Thus
`osalNvLength(33)=0` is *not sufficient* to infer whether the updater
cleared physical NVS or whether firmware initialization erased
invalid/corrupted page headers. Both can lead to an empty logical NIB.
This page-erase path exists in the **same SDK** used by both images;
no new A1-specific NV code is required for this failure mechanism.

## 3. Management updater audit — concrete protocol mismatch to resolve

The maintained, previously executed
`home-assistant-stack/tools/p10_debug_flash.py`:

1. Uploads image using HTTP **POST**
   `/fileUpload?customName=/fw.bin`.
2. Starts the Zigbee-radio flash using a separate **GET**:
   `/api2?action=6&zbChipIdx=1&local=1&fwVer=-1&fwType=0&baud=0&fwCh=2&eraseNVM=0`.
3. Observes `ZB_FW_done` (no protocol-layer capture of ROM BSL commands
   or sector-erase ranges).

The **actual bridge OS** is `v3.4.1.dev1`. SMLIGHT's release notes say:
“Zigbee OTA API has been switched to the POST method.” This is a
**protocol compatibility warning**, not proven causation: “Zigbee OTA
API” might mean end-device OTA rather than the exact coordinator-module
`/api2?action=6` endpoint, and the GET operation demonstrably did
flash. We must get the manufacturer-confirmed method and `eraseNVM`
semantics for **MR4U P10 on v3.4.1.dev1**. Do not automatically change
the call to POST without an exact contract.

The **public, separate** `smlight-tech/smlight-cc-flasher` Python CLI
implements `erase_bank() -> cmdBankErase()`, clearing **all main bank
flash sectors**, and for M33 its explicit `erase()` also calls
`erase_ccfg()`. The same utility offers `device.read()` through
ROM BSL `cmdMemRead()` (four-byte reads). Source:
https://github.com/smlight-tech/smlight-cc-flasher/blob/main/smlight_cc_flasher/device.py
and
https://github.com/smlight-tech/smlight-cc-flasher/blob/main/smlight_cc_flasher/command.py .
**This is NOT proven to be the embedded SLZB-OS flashing implementation.**
It only establishes that a destructive main-bank erase operation
exists and is easily exposed by related tooling.

## 4. Competing root causes and discriminating evidence

| Hypothesis | Current supporting evidence | Missing definitive evidence |
|---|---|---|
| **H1** uploader erases part/all NVS despite `eraseNVM=0` | twice missing NIB after firmware changes; matched NVS contract; full bank erase is supported by TI ROM BSL | actual updater firmware/BSL erase commands, or NVS bytes read **immediately after programming, before ZNP boots** |
| **H2** NVS page headers corrupted, ZNP NVOCMP erases on boot | proven `NVOCMP_scanPage` erase-on-bad-header path | raw preflash+post-program/preboot headers, precise NVOCMP init action and page error reason |
| **H3** valid NVS preserved but wrong driver/index setup | `osalNvLength` alone cannot exclude indexing failure | raw postboot 30 KiB showing valid signatures, 103 key records physically intact and matching addresses |
| **H4** wrong NVS layout/revision/CCFG | no positive evidence | only if future raw evidence conflicts with the identical linked contracts |

**Working prioritization:** H1/H2 first, H3 next, H4 lowest on
available evidence. Not a quantified probability or final diagnosis.

## 5. Minimal read-only physical-flash acquisition plan — NOT RUN

We must not repeat `restore -> flash -> NIB disappears`. First establish
an independently verified **ROM BSL read-only** path:

- Authenticate identity of physical MR4U and **P10 radio index1**; ensure
  Z2M and watchdog stopped and that no recovery worker owns the radio.
- Verify ROM BSL command sequence **never sends bank/sector erase,
  DOWNLOAD, writeMemory, image flashing or CCFG modification**. Note:
  entering BSL itself ordinarily requires a P10 reset, which is a
  **hardware operation** and has not been authorized/executed by this
  research pass; a raw read may also be restricted by device policy.
- Read exactly 0x7800 bytes of P10 flash at
  **0x000F8800–0x000FFFFF** into a restricted private folder.
  Retain full bytes privately (they can include the live Zigbee network
  key, link keys, device identities and counter state); never upload raw
  dump or print secrets to logs, GitHub, Slack or model context.
- Report **SHA256**, size, per-page all-0xFF flags, count of non-0xFF
  bytes, and only page-header state/signature/version comparisons.
  Avoid identifying values or raw item contents. BSL read can
  establish whether physical records survive **now**, but a postboot
  dump showing erased pages cannot distinguish H1 from H2 by itself.
- The **decisive future** experiment requires a spare P10 or an
  independently authorized/fully backed up one-shot test: capture
  NVS before flashing, program a known candidate, **read NVS immediately
  after programming while still in BSL, before allowing ZNP/NVOCMP to
  boot**, and then capture after first boot. This separates uploader
  erase from application initialization erase. Protect original
  network security and TX counter floors throughout.

No BSL mode entry, power cycle, radio reset, flash operation, ZNP
startup command, or NV restoration is approved by this document.

## 6. Non-destructive engineering next steps

1. Obtain SMLIGHT's **exact v3.4.1.dev1** P10 updater code/trace or
   written confirmation whether its `api2?action=6` implementation
   issues `BANK_ERASE`, which addresses are erased, and whether
   `eraseNVM=0` is parsed for **GET** requests on MR4U.
   Confirm if the release-note POST migration applies to this endpoint.
2. Build a **standalone read-only BSL extraction recipe** with exact
   command allowlist, timeout, device pin and secret-safe output;
   test it on a spare device/synthetic transcript before using the
   production coordinator.
3. Add a static CI gate that compares `nv-contract.json`, NVS base,
   image bounds and SDK/CCFG across every candidate migration; this
   confirms image geometry only and is not a substitute for raw reads.
4. After solving the physical NVS question, fix event55 to be
   host-observable/repeatable without unbounded traffic. No use for
   another startup until exact 103 keys and NIB reverify after flash.

**Live state at this writing:** A1 rev8320063 ZNP responsive, NIB33
and address-manager35 absent, Zigbee2MQTT stopped. Original and
postrestore 103-association backups sealed; **no live changes in
this investigation.**

## 7. Actual publicly distributed SLZB-OS `v3.4.1.dev1` binaries (offline strings)

Forensic acquisition used only the public vendor download server,
`https://updates.smlight.tech/firmware/slzb06x/core/`. Two distinct
versions of the same announced release were downloaded into a separate
**local scratch** folder on Zephyrus; they were **not flashed, uploaded to
GitHub, or applied to the device**:

| Public image | Bytes | SHA256 |
|---|---:|---|
| `slzb-os-v3.4.1.dev1-ota.bin` | 2,849,440 | `2967e91cdc7f0a8e21814757adfed0f71ce4e53585753ee193fab4e8c4894334` |
| `slzb-os-u-v3.4.1.dev1-ota.bin` | 4,274,640 | `63a40e962ec3ef5851e848c40e4522b9dc7b97336ea68e1a57bd583fba81a508` |

**Both** independently contain one instance each of these exact ASCII
marker strings: `eraseNVM`, `ZB_FW_done`, `Flash erase error!`,
`CCFG erase error!`, plus `/api2` and `/fileUpload` HTTP route
identifiers. In the **plain** binary, the `eraseNVM` marker at file
offset 92,808 is adjacent to `fwVer`, `fwType`, `fwCh`, and
`zbChipIdx`; the `ZB_FW_done` marker is next to flash/CCFG erase error
strings. The U variant contains the same markers. This confirms the
distributed bridge firmware *includes* flash-erase-handling and the
exact `eraseNVM` parameter **but not how it branches on zero/one**.
The `ha_info` OS version is known, but the actual OTA image variant for
this MR4U was not established from an on-chip binary hash; these
findings apply to both candidate vendor images, without claiming
byte-for-byte equivalence to the currently installed ESP image.

**Explicit negative conclusion:** static strings *do not* prove
`BANK_ERASE` was issued, which pages were cleared, or whether GET
versus POST changed the flag semantics. Those must be established by
actual updater source, BSL transcript or preboot raw flash acquisition.

## 8. Raw page analyzer prepared offline (zero hardware operations)

New tool `firmware/t832/r12/nvs_raw_forensics.py` handles **exactly
30,720-byte** private raw dumps from P10 `0x000F8800..0x000FFFFF`.
It identifies 15 × 2048-byte TI NVOCMP flash pages. The exact pinned
SDK `nvocmp.c` defines header state in byte0, cycle byte1,
format version (`byte2 >> 2`), signature byte3
(`NVOCMP_SIGNATURE=0x96`, version `0x03`). Valid states:
0xFF (inactive), 0xFE (transfer destination), 0x7E (ready),
0x7C (active), 0x78 (full), 0x70 (transfer source).

Command modes (offline only):

```
python firmware/t832/r12/nvs_raw_forensics.py --snapshot PRIVATE_CURRENT_NV.bin

python firmware/t832/r12/nvs_raw_forensics.py \
  --before PRIVATE_BEFORE.bin \
  --post-program-preboot PRIVATE_AFTER_PROGRAM_BEFORE_APP_BOOT.bin \
  --after-boot PRIVATE_AFTER_FIRST_APP_BOOT.bin
```

The tool loads files **only**; it has no network/serial/BSL interface
and never writes data. It rejects incorrect file sizes or symlinks.
Output is per-page validity/counts, overall SHA256 and changed-page
status — never raw keys, item IDs or device identities. All full binary
snapshots must stay in the restricted local private directory and must
never be committed or pasted into issue comments. A first-boot header
erase is only attributed to the *stage* in which bytes changed; it is
not proof of an individual erase opcode. A single postboot snapshot
cannot attribute the source of loss.

**Automated synthetic tests:** nine passed for correct page format,
signature/version corruption, precise length, full erase before app,
erase only after boot, unchanged snapshot, partial write, and redaction
of a deliberately embedded fake secret. Six earlier static-image
contract tests also pass. Host-only CI automatically runs tests through
the existing `test_*.py` glob.

**Still outstanding:** the ROM-BSL *read-only* acquisition transport
and first-boot hold have **not** been proven on the production MR4U.
The production module has **not** been put in BSL mode or reset during
this investigation. The public `smlight-cc-flasher` read command uses
4-byte memory requests, but entering BSL via its host controls
**can reset the radio**. Never invoke it against production as a
casual read without an explicit, separately approved reset/forensic
ownership gate and a verified no-erase/no-download command transcript.
