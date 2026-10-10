# R12 investigation gate: independent, non-resetting capture of the R11 startup POD

**Status (9 October 2026): Offline artifact + decoder implemented and locally tested.
Live CPU/RAM capture BLOCKED by unverified debug wiring, access and probe.**
**This is NOT an R12 firmware image, not a flash authorization, and not a
replacement for the sealed HA recovery controller.**

Owner: `analienx/Zigbee-Coordinator` branch `codex/t832-r12-forensics`,
based on exact shipped R11 source `156fe563ba5e6eb3d15c56b21ec9aabfda882096`.
Cross-system incident: `analienx/home-assistant-stack#73`.

## 2026-10-10 postboot NVS investigation (separate from non-resetting R11 POD capture)

A later, separately authorized **ROM BSL read-only** session on A1 rev
**8320063** successfully acquired the entire physical 30 KiB NVOCMP
region. The radio was subsequently returned to ZNP; this BSL procedure
**did involve an intentional radio mode transition and reset**, and is
**NOT** evidence of any qualifying cJTAG/SWD access described below.

See [P10_NVOCMP_POSTBOOT_CRC_20261010.md](P10_NVOCMP_POSTBOOT_CRC_20261010.md)
for the complete snapshot hash, verified **867/867** TI CRC-8 records,
exact SDK legacy item-ID/subID mapping and an occupancy-safe inventory.
All 15 page headers are valid, but the A1 postboot state has **no legacy
NIB item, no address-manager entries and no populated TCLK device slots**.
The R12 rev **8320062** pre-A1-flash restoration receipt independently
verified **103 trust-center associations and 103 address rows** immediately
before the A1 firmware transition, at which the uploader requested
`eraseNVM=0`. Data loss can be bounded to the intervening
flash/boot/postflash interval, but **whether programming or first boot
modified the originally populated entries is NOT established**.

The original R11 rev 8320052 startup hang remains unsolved.
The cJTAG/SWD hardware access qualification is **still BLOCKED**.
This investigation performed **no new BSL, flash, reset, NV mutation,
ZDO startup, Z2M restart or secret extraction**; it only analyzed the
previously sealed postboot snapshot offline.

## 1. Observation vs. hypotheses

The exact deployed R11 diagnostic firmware, rev 8320052, SHA256
`13d69fb126b0cad0e5f362d01b8fcb4d78d7a417c75eb36d6dbbaa38266ed36e`,
is reproducibly responsive before original-network startup. Its
`verify-after-cold-power` receipt confirms original network identity, key,
103 trust-center link-key associations, 103 address records and the protected
counter floors. One `ZDO startupFromApp(startdelay=100)` at
2026-10-09T20:05:53.589Z produced **zero** more RX bytes; it timed out at
20:06:33.591Z. The subsequent passive 15-second capture also received zero
bytes. Seven valid R11 diagnostic frames were received *before*, not after,
this startup request.

After an operator-issued SLZB **radio-only reset**, ZNP recovered (SYS ping
3/3, version 1/1; direct `UTIL getDeviceInfo` state 0; revision 8320052).
The original Zigbee network was **not** restarted; Z2M remains down with
watchdog disabled. The reset proves radio-only recovery is sometimes possible,
not the cause of the earlier restored-network startup failure.

This does NOT prove a CPU hard fault, deadlock, RAM exhaustion, malformed
NV, UART peripheral failure or bridge fault; every one remains a hypothesis.
Seven pre-start MT DEBUG exports are not post-request proof. In particular,
the R11 exporter uses the same ZNP path that stops responding.

## 2. Exact hosted firmware and symbol provenance

GitHub Actions successful hosted R11 build:
- Repository: `analienx/Zigbee-Coordinator`; workflow run `37967989446`.
- DIAG artifact `t832-r11-DIAG-vendor-20240716`, ID `11635590360`.
- Source SHA `156fe563ba5e6eb3d15c56b21ec9aabfda882096`.
- Manifest `T832-BUILD-MANIFEST.json`, DIAG revision 8320052.
- Image SHA256 as above, `.map` SHA256
  `8d2620cae646a29dd6f15fd17282182ec626d41886c7385998a3f678df5d9e5a`,
  `.out` SHA256
  `e11a340b38d1230d1ed937d04f2d48dd63661195adf7d3bd7f1c63d770dff74a`.
- Local copy: `C:\Workspace\.analienx\sonoff-private\recovery\p10-r11-debug-20261009\forensics\r11-matched-symbols`.
  No network keys or private NV backups go into Git.

Linker map independently confirms *section placement and symbol table*:

| Symbol | Physical RAM | Linked bytes | Risk |
|---|---:|---:|---|
| `t832R11Startup` | `0x20001220` | 20 (`0x14`) | preferred minimal read; fields only |
| `t832R11Ext` | `0x2000103C` | 44 (`0x2C`) | read only if specifically justified |
| `t832R6Nv` | `0x200086DC` | 116 (`0x74`) | sensitive NV metadata; avoid by default |
| `t832DiagFatal` | `0x20008330` | 172 (`0xAC`) | potential task detail; avoid by default |

These symbol addresses are valid ONLY for the exact image above, not vendor
`20240716`, a rebuilt R11, R12 or a different image. The R11 firmware
manifest names a generic CC2674P10 reference board, **not an independently
verified MR4U cJTAG testpad pinout**. The live management/API confirms MR4U
radio index1 is the P10, but does not prove a debug connector exists.

## 3. Stage A: current OFFLINE gate (implemented)

Tool: `firmware/t832/r12/r12_swd_offline.py` — Python stdlib, FILE INPUT
ONLY. It cannot connect to hardware, read the network, change radio flags or
invoke a debugger. Exact manifest, BIN, ELF and MAP SHA/size are mandatory;
symbol section and map symbols must agree before an address is reported.

```cmd
cd /d C:\Workspace\worktrees\zigbee-t832-r12-forensics
python firmware\t832\r12\r12_swd_offline.py symbols --artifact-dir "C:\Workspace\.analienx\sonoff-private\recovery\p10-r11-debug-20261009\forensics\r11-matched-symbols" --out "C:\Workspace\.analienx\sonoff-private\recovery\p10-r11-debug-20261009\forensics\r12-exact-symbols.json"
```

Status `SYMBOLS_VERIFIED_NO_HARDWARE_PROOF` is intentional.
The private manifest already exists from the authenticated hosted artifact.
The parser does not execute an SWD command. Tested against real hosted artifact
and synthetic negative controls. All offline tests must also pass in hosted CI.

## 4. Stage B: hardware access qualifications — NOT YET PASSED

Before **any** debugger attachment to the production P10, independently
establish and record:
1. **Exact MR4U PCB revision and radio1/2 mapping.** Obtain the manufacturer's
   PCB schematic / labeled pads, or directly inspect trace continuity. Don't
   infer JTAG/cJTAG pads from older single-radio SLZB-06P10 pinouts.
2. **Actual cJTAG/JTAG and voltage wiring.** Confirm TCK/TMS or TDI/TDO
   as appropriate, target reference voltage, common ground, probe isolation,
   orientation, and *non-connection* of RESET/BOOT/P10 power or BSL pins.
   Don't power the radio via the probe. PoE/USB coexistence requires care.
3. **Probe and tool availability.** XDS110 (or TI-supported cJTAG debugger)
   visibly enumerated on the host; CCS debugger configured to **connect to a
   running target without reset or program load**. A generic USB UART link is
   not SWD/cJTAG. Unverified installation/driver state = BLOCKED.
4. **Debug authorization and non-erasing behavior.** Verify read access without
   unlock/mass erase and confirm that the default CCS GEL/project scripts do
   not reset the board on connect. Some standard debug configurations reset
   automatically. If locked: **STOP**. NEVER invoke unlock, mass erase,
   ROM BSL, `Load Program`, `Load Symbols and Program`, or flash programming.
   Pure `Load Symbols Only` is acceptable after matching image SHA.
5. **Physical bench qualification on a spare or sacrificial P10 first.**
   Demonstrate two sequential 20-byte reads from the same linked symbol,
   prove no reset, flash/NV modification, UART ownership conflict or
   unexpected target state transition. Record first/second digests, reset
   reason, probe/driver version, board ID (not public IEEE), and timestamps.
   A halted core is *intrusive*: it pauses task scheduling. Do not claim
   non-invasive timing, and do not blindly resume into a test.
6. **Independent live preflight before a future hang trial**: original Zigbee
   security-state verification, Z2M actually stopped, watchdog off, no competing
   recovery process, appropriate backups, and a brand-new sealed single-shot
   incident. The earlier R11 startup-stage receipt is **consumed and blocked**.
   Never rerun it by clearing flags or by invoking raw ZDO.

Offline tool passing does **not** imply any of these hardware gates passed.
Until physical access is validated, **no new startup or flash is justified.**

References: TI SimpleLink CC13xx/CC26xx debug guide
`https://dev.ti.com/tirex/content/simplelink_cc13xx_cc26xx_sdk_8_32_00_07/docs/proprietary-rf/proprietary-rf-users-guide/proprietary-rf-guide/debugging-index.html`;
TI CC13x4/CC26x4 TRM
`https://www.ti.com/lit/pdf/swcu194`;
TI Zigbee guide warns some CCS GEL connection scripts issue board reset by
default: `https://dev.ti.com/tirex/explore/content/simplelink_cc13xx_cc26xx_sdk_5_40_00_40/docs/zigbee/html/zigbee-guide/debugging-index.html`.

## 5. Stage C: after an INDEPENDENT debugger capture (not performed)

The R11 `t832R11Startup` structure is 20 bytes, little endian:

`uint32 generation; uint32 sequence; uint16 entry_mask; uint16 exit_mask;
uint16 last_status; uint8 last_site; uint8 last_phase; uint8 dev_state;
uint8 nwk_state; uint8 valid; uint8 reserved`.

Sequence odd -> writer may be in progress (torn); abort conclusions.
Read the **same 20 bytes twice**, independently, within the halted SAME
CPU boot epoch. Different reads -> refuse classification. Never ingest a
whole 296-KiB RAM dump into public tools. Raw RAM may contain AES/network
keys even if the 20-byte startup POD itself does not.

Source-defined observed sites:
1. main / initNV
2. BDB restored-network handling
3. ReadNetworkRestoreState
4. RestoreNetworkState / NLME
5. SecInit
6. NetworkInit
7. formation confirm
8. NetworkStartEvt

The decoder reconstructs entry/exit masks, last site/phase,
bit-valid status/state and NLME flags. **An unmatched entry bit is NOT proof
the CPU got stuck in that function**. A missing exit may be a lost recorder
update, re-entrant task, later exception or an unrelated starvation; combine
with PC/LR/SP, xPSR, CFSR/HFSR and task state (separately captured after
debugger/ELF provenance has been established). Reset reason, image/build
identity and boot epoch are needed to guard against post-hang automatic reset.

After an authorized debugger has saved two dedicated 20-byte files
`startup-read1.bin` and `startup-read2.bin` (no debug tool commands
are provided here because MR4U wiring is unverified):

```cmd
python firmware\t832\r12\r12_swd_offline.py decode --manifest "C:\Workspace\.analienx\sonoff-private\recovery\p10-r11-debug-20261009\forensics\r12-exact-symbols.json" --read1 "C:\PRIVATE\startup-read1.bin" --read2 "C:\PRIVATE\startup-read2.bin" --out "C:\PRIVATE\r12-startup-review.json"
```

Expected result without hardware proof: `COHERENT_20B_READS_ORIGIN_UNPROVEN`,
**never** "CPU root cause found". A synthetic file is not hardware evidence.

## 6. Next experiment and decision

**Preferred**: preserve currently alive R11 radio (state 0) and arrange
verified non-resetting hardware debugger access. Acquire a benign pre-start
20-byte baseline **after** proving correct hardware, then capture the same
20 bytes and core-fault/task context upon any later single sealed startup hang.

If the MR4U has no accessible cJTAG/SWD pads or debug access is locked,
**do not attempt erasure or guess a GPIO**. Investigate a separate, physically
verified observer channel (spare GPIO/isolated logic analyzer **only after**
pin-mux and board schematic proof), or instrument a *new and distinctly
reviewed* firmware build that can export crash reason to an independently
operational subsystem. On-radio extra flash writes, backup restores, vendor
rollbacks and forcing network startup do not satisfy this diagnostic gate.

Decision table:

| Observed evidence | Interpretation | Next action |
|---|---|---|
| No probe/wiring proof | CPU cause unknown | stop; acquire pinout/probe |
| Debug locked | CPU state inaccessible | stop; **no** erase/unlock |
| Two POD reads disagree | torn/moving record | retain both; no classification |
| Same stable POD, only site1 | no post-boot site recorded | inspect PC/tasks; no causal leap |
| Later entry without exit | location hint ONLY | correlate PC/RTOS/fault registers |
| CFSR/HFSR exception proof | CPU fault possibility supported | decode PC/LR with exact ELF |
| CPU runs, Zigbee task blocked | possible scheduler/deadlock | map task owners/queues |
| CPU/RTOS healthy, MT/UART silent | transport/NPI hypothesis strengthened | inspect NPI/GPIO with independent witness |

**Release/finish criteria**: signed source/ELF/image match; debug-access
proven; two stable POD reads; independent core/task/reset evidence; no
flash/NV/reset side effect; new incident owner and one-shot startup; critical
security backup retained; no raw keys logged. Until these exist:
`HARDWARE_BLOCKED` and Zigbee original network still OFFLINE.
