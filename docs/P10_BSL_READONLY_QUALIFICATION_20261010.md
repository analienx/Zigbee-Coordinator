# P10 raw NVS acquisition — BSL read-only qualification (NOT DEPLOYED)

## Decision and current boundary

- Device: **SLZB-MR4U**, TI **CC2674P10**, **radio index 1**, mapped to
  Ethernet serial `192.168.50.200:7638` in this installation. Radio index
  **0 / port 6638 is the other SoC**. Do not use default single-radio
  bootloader commands or the `--host` path of unmodified
  `smlight-cc-flasher` against the production MR4U.
- Currently running A1 rev **8320063**, ZNP responsive, **NIB33 and address
  manager35 missing/uncommissioned**, Zigbee2MQTT stopped, watchdog off.
  Original and fresh post-restoration backups contain 103 devices/keys
  and counters in restricted private storage.
- Goal: read physically stored **15 x 2048-byte pages** at
  `0x000F8800..0x000FFFFF` and analyze them using the previously
  committed `nvs_raw_forensics.py`.
- **NO production bootloader invocation, radio reset, firmware flash,
  NV restore, ZNP start, or raw NVS read has been authorized/performed
  as part of this qualification.** The code is staged and tested offline
  against synthetic BSL responses. A live read is an independently gated
  later experiment.

## Verified command/index mapping

The public source from SMLIGHT/PySMLIGHT explicitly defines:

- `Actions.API_CMD=4`, `Commands.CMD_ZB_BSL=2`.
- `CmdWrapper.zb_bootloader(idx=0)` passes
  `set_cmd(Commands.CMD_ZB_BSL, f"idx:{idx}")`.
- `Api2.set_cmd()` inserts `idx=1` into an API request **only when
  explicitly passed**. For the desired P10 the **candidate** action
  would be `GET /api2?action=4&cmd=2&idx=1` (DO NOT EXECUTE).
  Exact behavior of this endpoint on **MR4U / SLZB-OS v3.4.1.dev1**
  and whether it accepts authenticated, physical index1 switching
  **remain untested**. Confirm by vendor or controlled spare-radio test.
- `smlight-cc-flasher`'s `Bootloader.invoke_smlight_net()` calls
  `set_cmd(CMD_ZB_BSL)` **without the index**. Therefore it defaults
  to radio0 on MR4U; not safe to invoke against production.
- The public CC flasher defaults to `--bootloader-reset generic` and
  its CLI calls ROM `cmdReset()` on exit unless `--keep-open` is set.
  It also exposes `--erase` and `--write`. We will NOT use that
  default invocation as our read-only production procedure.

Sources:
https://github.com/smlight-tech/pysmlight/blob/main/pysmlight/web.py
https://github.com/smlight-tech/pysmlight/blob/main/pysmlight/const.py
https://github.com/smlight-tech/smlight-cc-flasher/blob/main/smlight_cc_flasher/command.py
https://github.com/smlight-tech/smlight-cc-flasher/blob/main/smlight_cc_flasher/cli.py

## Implemented protocol guard

`firmware/t832/r12/p10_bsl_readonly.py` does **not** implement or
invoke the SLZB management API, BSL entry, GPIO, DTR/RTS, flash write,
NVS restore or reboot. It only supports the following TI ROM BSL
commands through an **already-active** serial-over-TCP BSL transport
at the pinned `7638` port:

| BSL opcode | Allowed purpose |
|---|---|
| 0x55 SYNC | establish ROM framing |
| 0x20 PING | check ROM response |
| 0x23 GET_STATUS | check previous read request succeeded |
| 0x28 GET_CHIP_ID | bounded identification (optional) |
| 0x2A MEMORY_READ | 4-byte reads **only** at a fixed factory chip-ID register or the NVS region |

Every other opcode is refused *before* any socket write. In particular
`DOWNLOAD`/0x21, `SEND_DATA`/0x24, `RESET`/0x25,
`SECTOR_ERASE`/0x26, `MEMORY_WRITE`/0x2B,
`BANK_ERASE`/0x2C, `SET_CCFG`/0x2D and
`DOWNLOAD_CRC`/0x2F are not permitted.

The first BSL memory read checks factory ICEPICK device ID
`0x50000800+0x318` and rejects wafer IDs other than **0xBB78**
(CC2674/CC27x4 family as recognized by the vendor's own `device.py`).
This is an independent defense against connecting to EFR32 radio0 or
the wrong serial port. It does not authenticate the hardware instance
cryptographically; the IP/port/USB target must still be independently
verified and exclusively owned.

The NVS read is exact `0x7800=30720` bytes as 7680 four-byte requests.
A transport/CRC/chip-ID/length error aborts with **no partial dump
written**, no retry, and **no end-of-operation BSL RESET**. Only once
a complete dump exists is it written exclusively as `.bin` inside
`C:\Workspace\.analienx\sonoff-private\recovery\`; the file must
inherit the restricted ACL, be hashed, and must never be attached to
GitHub/ChatGPT or printed to stdout. The only output includes size,
hash and command counts.

## How to verify offline (SAFE; no network)

```cmd
cd /d C:\Workspace\worktrees\zigbee-p10-bsl-readonly
python firmware\t832\r12\p10_bsl_readonly.py
python -m unittest discover -s firmware\t832\r12 -p test_p10_bsl_readonly.py -v
```

The default command **only prints a plan**. Both commands were run
on Zephyrus without opening a socket. The synthetic ROM fixture covers
valid partial TCP frames, chip-ID verification, 4-byte reads, CRC failure,
short replies, wrong port, incomplete authorization, non-NVS address,
forbidden erases and resets.

## Future hardware gates — STOP until qualified separately

1. Obtain an authoritative, MR4U-specific **idx1 BSL transition** contract
   for the actual bridge OS v3.4.1.dev1 or verify it on a spare MR4U/P10.
   Do not execute unmodified `smlight-cc-flasher --read`; its reset/
   BSL defaults are not radio-index safe.
2. Confirm exclusive serial access to the intended P10, correct `ha_info`
   chip mapping, Z2M/watchdog stopped and unheld recovery journal,
   original + post-restoration backups all hash-valid and private.
3. In a **newly authorized physical operation**, enter BSL for radio index1
   once. This switches the operating radio mode and often requires a
   radio reset, even if the subsequent memory reads are nonmutating.
   Before any BSL switch, decide and explicitly document how the
   P10 will return to the known-good app; do not silently send RESET.
4. When BSL is already active, a separately approved live read may be
   invoked with explicit `--read --already-in-bsl` and the remaining
   authorization gates, plus a new restricted private path. **Do not
   execute this as part of the offline qualification.**
5. Feed the private snapshot into `nvs_raw_forensics.py`, share only
   per-page header status / all-FF information / SHA256. A single
   **postboot** dump cannot distinguish updater-erase from NVOCMP
   boot-time erase. The conclusive three-stage experiment remains
   before flash, after programming before ZNP boot, and after boot,
   preferably on a spare test radio.

**Status of this deliverable:** offline source and guarded protocol are
ready. **MR4U-specific index1 BSL entry + BSL TCP bridge in that mode
remain unverified hardware prerequisites. No hardware access has
occurred.**
