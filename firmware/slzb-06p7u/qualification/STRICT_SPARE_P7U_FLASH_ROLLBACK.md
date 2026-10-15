# Isolated SLZB-06P7U restricted ROM BSL first flash + stock rollback

**Only-one-unit correction (15 Oct 2026):** For issue #80 there is no spare.
Follow [R2_FIRST_SINGLE_UNIT.md](R2_FIRST_SINGLE_UNIT.md) before this tool procedure.
R2 may be the first custom image, but requires proven blank NV5, private original
state backups and a separately reviewed NV preparation/recovery operation if NV
is nonblank. The historical `spare` filenames/flags acknowledge isolation; they
do not establish that replacement hardware exists. No physical action is authorized.

**Current contract:** The original 23-sector application/stock-cleanup boundary remains unchanged. See [NV5_RECOVERY.md](NV5_RECOVERY.md) for the separate five-sector NV tool. Use [R2_FIRST_SINGLE_UNIT.md](R2_FIRST_SINGLE_UNIT.md) for the current one-unit sequence and a freshly matched kit; the R1-first assumption below is historical.

**Status:** Implementation complete in source with simulated ROM tests; actual physical P7U BSL/flash/rollback is NOT yet qualified. This code must **never** target the active SMLIGHT MR4U/P10, and does not touch ESP32-S3/SLZB-OS firmware, Home Assistant or Zigbee2MQTT. P7U flash is **not already authorized**.

## Why NOT `smlight-cc-flasher -w` or `-ewv`

Pinned upstream `smlight_cc_flasher/cli.py` unconditionally promotes a segmented-HEX `--write` to `--erase`; `CC26xx.erase()` calls `cmdBankErase()`, not `cmdEraseSector()`. It can also rewrite secondary IEEE in CCFG. The generic CLI is unsafe for CCFG/NV-preserving flashing, even when the supplied HEX is application-only. Never invoke the upstream CLI to flash our custom P7U HEX. This project imports **only the pinned low-level command transport** and hard rejects an unknown installed copy by exact source SHA-256.

## Source images and offline rollback (fully implemented)

The **official SMLIGHT 20240710 vendor image**:
`https://updates.smlight.tech/firmware/slzb06x/zigbee/slzb06p7v2/CC1352P7_coordinator_20240710.bin`
must have SHA-256 `1e257bc066e7a8db9c12e0b826791cc81d8744b9453355af0f4efce194060d6b`, 179804 bytes. It contains only two CRC-validated segments: APP `0x00000`, 179688 bytes; CCFG `0xAFFA8`, 88 bytes. No NV segment. The manufacturer exact CCFG SHA-256 is `1defedbd2f474ee8b7385476801a63de95f55c3dd51115e29f97c69196049af7`.

`p7u_stock_rollback.py` independently validates container SHA, segment offsets, sizes, CRCs, CCFG SHA, vector plausibility and protected layout, then produces:
- `stock.app-only-NOT-FLASHABLE.hex` (NO CCFG, NV, ESP binary).
- `stock.source.json`, `stock.plan.json`, and `stock.receipt.json`.
- Stock APP occupies 22 sectors; custom P7U currently occupies 23. The derived stock rollback deliberately adds a single FF byte at 0x2C000 to force a **23rd sector erased entirely to FF**, removing custom code left outside the original stock image. Its verified manufacturer bytes remain untouched. The CLI refuses any future custom image whose last sector exceeds the stock cleanup plan; no binary redistribution.

Commands (Python 3.12+, from repo root; use private local paths):

```sh
python firmware/slzb-06p7u/qualification/p7u_stock_rollback.py \
  --official-vendor-bin /private/CC1352P7_coordinator_20240710.bin \
  --profile p7u-cap192-f07 --output-prefix /private/stock
python firmware/slzb-06p7u/qualification/p7u_flash_spare.py --phase offline \
  --app-only-hex /private/custom.app-only.hex \
  --full-image-evidence /private/custom.source.json \
  --sector-plan /private/custom.plan.json \
  --official-stock-bin /private/CC1352P7_coordinator_20240710.bin \
  --rollback-app-hex /private/stock.app-only-NOT-FLASHABLE.hex \
  --rollback-receipt /private/stock.receipt.json \
  --out /private/offline-check.json
```

Use `p7u-f07-stock` for the R1 NV2 build. All four files must share the profile. The full-image source manifest must originate from the native linked P7U HEX source audit. `--phase offline` never opens serial ports.

## Physical BSL inspection (requires isolated target, not P10)

The radio target must be an **explicitly identified SLZB-06P7U isolated from its operational network**. The installed manufacturer's ESP SLZB-OS remains untouched. The fitted PCB and real P7 radio were not connected to Zephyrus when this was authored. Source defines ESP flash/BSL GPIO16 active-low, reset GPIO21 active-low, USB/host bridge; TI's ROM UART uses TI DIO12/DIO13, not ESP GPIO17/18. Verify actual wired bootloader access on this board.

The restricted `p7u_rom_lowlevel.py` implements ONLY a small allowlist of TI ROM UART commands with framing matched to SMLIGHT source commit `9a1d33571c1cdaedc9dfcdcf2df5b5a5fece0b1c` (`command.py` SHA-256 `9fb42418ffa2301be52bfa2fe1208fb465138c2cc4cf432a767df2f6860ee25a`). This **does not import** the high-level SMLIGHT flasher, its unsafe implicit BANK_ERASE, or its non-installable Windows `gpiod>=2.4.0` dependency. Protocol tests check actual ACK/NACK, checksums, command bytes, big-endian addresses and CRC responses against the pinned implementation. Runtime dependencies are only `pyserial-asyncio==0.6` and `pysmlight==0.5.3`, in `requirements-p7u-spare-serial.txt`.

```sh
python -m venv .venv-p7u
.venv-p7u/bin/python -m pip install -r firmware/slzb-06p7u/qualification/requirements-p7u-spare-serial.txt
```

On Windows, use `.venv-p7u/Scripts/python.exe`. Native Windows virtualenv installation and import tests are checked on Zephyrus; an actual P7U serial port and radio handshake are still required. No GPIO or external bootloader-reset assumptions are introduced.

**Inspect mode** requires `--isolated-spare-only`. For Ethernet/Wi-Fi, specify `--device socket://SPARE-P7U:6638 --expected-spare-mac AA:BB:CC:DD:EE:FF` with the full physical **ESP management** MAC read independently from the spare P7U label/console. Before any `CMD_ZB_BSL` radio reset, the tool makes a read-only manufacturer API `get_info()`, rejects anything but **SLZB-06P7U**, compares full management MAC byte-for-byte, rejects unauthenticated/unsupported access and stops before reset on mismatch. Never substitute the Zigbee/IEEE radio address or the active MR4U/P10 address. On USB specify a *known, explicitly identified* `COMn` or `/dev/ttyACMn` already placed in ROM BSL using the manufacturer's mechanism. **DTR/RTS on ESP USB is NOT assumed to reset the radio.** No CLI mode forces ESP32 firmware update. Network entry is a radio mode change, so do not run on the production network.

Run the exact same command as `--phase offline`, but set:
```
--phase inspect --device socket://SPARE-P7U:6638 \
--expected-spare-mac AA:BB:CC:DD:EE:FF --isolated-spare-only \
--out /private/inspect-1.json
```
This does not erase/program anything; it does enter ROM BSL on the isolated radio. It checks actual ROM `GET_CHIP_ID`, TI FCFG wafer `0xBB77`, 704 KiB internal flash, private primary-IEEE digest and **installed** 88-byte CCFG (enabled ROM BSL, TI DIO15 low backdoor, vector 0), and records per-sector existing and expected CRC32. It never prints IEEE or security-key bytes.

To qualify repeatable BSL entry: restore stock-app mode using the manufacturer-controlled radio reset, confirm stock `SYS_PING`/`SYS_VERSION`, and run `inspect` a second time after a fresh ROM BSL entry. Compare identity/CCFG fingerprints and initial stock CRC counts. Record this separately. **The `--rom-bsl-reentry-twice-confirmed` flag is a human declaration, not an automatically proven observation.**

## One-shot restricted write (only after physical BSL proof)

For `--phase flash --target-image candidate`, supply all the original image/stock paths and the approved `inspect-2.json`, plus **the exact `approval_digest` field from it**:
```
--approval-file /private/inspect-2.json --approve-digest HEX_DIGEST \
--execute-radio-write --isolated-spare-only \
--expected-spare-mac AA:BB:CC:DD:EE:FF \
--rom-bsl-reentry-twice-confirmed --stock-rollback-available \
--out /private/result.json
```
No write runs unless all those gates pass. Before any sector erase the code rechecks the same target IEEE fingerprint, wafer, CCFG digest, image, sector plan, USB/LAN endpoint, and full approval data. It compares live CRCs to the approved prior-or-desired CRC for every sector. It programs sectors **excluding sector 0 first**, then the vector sector last. Each address is allowed only below `0xA4000`, aligned to 8KiB, and explicitly present in the 23-sector source plan. Each `CMD_SECTOR_ERASE`, `CMD_DOWNLOAD`, every ≤252-byte `CMD_SEND_DATA`, postsector CRC and CCFG re-read must succeed; on failure the tool stops and **never resets the radio**. No call to `CMD_BANK_ERASE`, `ERASE_CCFG`, IEEE writes or ESP update is possible via the exported wrapper.

Use a **new, unused `--out` path for every invocation**. The tool rejects existing paths and aliases of recovery inputs before contacting the device; it never replaces an earlier receipt or stock backup. A flash approval's digest, endpoint, image, profile, sector list and prior CRC syntax are also checked offline before a network BSL-entry reset, then checked again with live identity/CCFG/CRC before erasing.

The physical RC1 CLI requires the exact 23 reviewed application sectors `0x00000..0x2C000`. The transport independently refuses other erase/download addresses and downloads that do not start at an 8KiB sector boundary. SEND_DATA is accepted only within an acknowledged 8KiB download and is disabled after an uncertain/failed packet until a new download is acknowledged.

On successful verification **the radio is deliberately left in ROM BSL**. Only then use the known manufacturer's reset path to start the custom ZNP app and test UART/RF. Confirm you can re-enter BSL even if ZNP crashes. Keep the rollback files isolated from the repo.

### Interrupted write

If a sector is partially written, the original approval snapshot CRC no longer matches. A new independent `--phase inspect` is preferable. Explicit `--resume --accept-interrupted-sector-reerase` with the original approval token skips sectors whose full 8KiB CRC already matches, and **re-erases** the partial/mismatching application sector. All identity, CCFG and address guards remain. Never power-cycle the radio merely to work around an active failing write; if connection dropped, reconnect to BSL first.

### Return to stock

Use **the same** `p7u_flash_spare.py`, but set `--target-image stock` and run a fresh `--phase inspect` against the target radio in BSL to obtain a *new* approval digest, then `--phase flash` with that new authorization. The stock bytes are regenerated on every run from the SHA-pinned original manufacturer's 20240710 BIN; a fabricated receipt or modified stock HEX is rejected. CCFG/NV are never erased. After verification reset into stock and check vendor `SYS_VERSION` and BSL reentry. This restoration procedure is implemented and passed fake-ROM end-to-end, but has **not yet been physically proven**.

## Still unverified without hardware

True ROM BSL entry on fitted P7U, USB CDC/SLZB-OS bridge behavior, stock ROM CRC parity with installed application, oscillator/RF/PA wiring, actual end-to-end successful flash + rollback, abrupt power-loss behavior and active Zigbee security/Trust Center migration. The network can be rebuilt/restored separately; **none of these source tests guarantees no brick** if the fitted bridge or ROM backdoor is unusable. An external TI debug probe remains last-resort recovery.

CI deliberately tests hostile fake-ROM faults and downloads/checks the exact official vendor source, but never connects a radio.
