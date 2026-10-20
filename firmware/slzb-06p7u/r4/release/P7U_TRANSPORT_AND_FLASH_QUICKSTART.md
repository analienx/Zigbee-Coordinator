# P7U transport choice and R4 flash quickstart

Applies only to the **single production SMLIGHT SLZB-06P7U R1.73 / CC2652P7**. Do not substitute the historical 06P7, MR4U, P10, or a hypothetical spare.

## Physical wiring is not the selected transport

The P7U USB cable is physically connected to **Home Assistant (Raspberry Pi)**, **not** to the Zephyrus Windows computer. The coordinator's ESP/SLZB-OS switches which *logical* Zigbee data path is active; switching modes does not move that physical cable. No COM port on Zephyrus in Ethernet mode is expected.

| Situation | Radio mode | Operator/data path | What to do |
|---|---|---|---|
| **Current state: R4 flashed, USB live, NV HOLD** | **USB** | SMLIGHT radio -> Home Assistant /dev/ttyACM0; ESP management still via LAN | **Do not restart Z2M or power-cycle the radio.** Z2M startup failed at 19:29 CEST 2026-10-20; read-only F1 reports NV HOLD. Preserve this state pending retained-NV forensic decision. |
| R4 flash with validated Ethernet BSL support | **Ethernet** | Native Windows operator -> TCP/6638 in ROM BSL; management control enters BSL separately | Preferred when the exact host, stable link, readback, silicon ID and safety admission work. No WSL or device-mode toggle. Never use a generic mass-erase flasher. |
| Ethernet BSL admission fails, or network path is unstable | Stop, unchanged unless explicitly directed | Assess HA-attached USB path or move physical cable to Windows under a *new explicit plan* | Do not pretend USB mode creates a Zephyrus COM port. Do not flash via an unreviewed TCP bridge. |
| Post-flash verification while still in BSL | **Keep Ethernet/BSL** | Pinned APP+AC000 readback, all unchanged NV/CCFG sectors checked | Do not start Z2M or change mode until the write has been positively verified and the controlled boot action is authorized. |
| Restore normal 107-device Z2M operation | **USB**, *only after verified boot* | P7U USB -> Home Assistant `/dev/serial/by-id/...` -> Z2M configured for USB | User switches mode deliberately, then starts Z2M only after correct firmware/identity/security checks. Do not silently change Z2M settings. |
| Day-to-day HA operation | **USB** | HA owns radio | Leave Ethernet management web UI reachable if its firmware supports `Keep network & web server`. Only one Zigbee host owns serial. |

**Never confuse** (1) physical USB cable to HA, (2) ESP Zigbee-to-USB/Ethernet mode, (3) TI ROM BSL, and (4) the Windows host where artifacts reside.

## Explicit mode decision and current failure state (2026-10-20)

**Never ask for another mode switch as a routine prerequisite.** Use the current mode unless the *specific next operation* cannot use it:

- **USB** means the radio's Zigbee ZNP serial is attached to **Home Assistant** (the USB cable was already physically connected). Use it for read-only ZNP F1 status and, **only after network readiness is proven**, running Zigbee2MQTT. Changing the SMLIGHT mode to USB does not attach the radio to a Windows COM port.
- **Ethernet** means the Zephyrus can reach the radio through the wired management/BSL TCP path. Use it for controlled **ROM BSL live-flash backup/read/sector write/verify** using the audited Windows writer. Keep Z2M stopped. Ethernet management UI can be reachable even while ZNP operates in USB mode; management reachability **does not** imply Zigbee serial-over-Ethernet is selected.
- **No mode switch** is needed to read the already-preserved 2026-10-20 704-KiB private captures or run GitHub-hosted candidate tests. Those are the first response to an R4 initialization failure.
- **Only when a NEW live ROM-sector capture or flash transaction is necessary** do we request a single deliberate switch to Ethernet, confirm no serial owner, and use the pinned ROM BSL adapter. The radio entry/reset is a separately risk-assessed action; never treat SMLIGHT mode selection alone as proof of BSL.
- After a verified flash and safe boot/security state, switch **once to USB** for HA/Z2M. Do not toggle repeatedly to diagnose a Z2M log message.

**Live incident:** At 19:29 CEST the authorized one-time Zigbee2MQTT start opened the correct HA USB serial by-id but failed waiting 30s for SYS_RESET_IND inside herdsman beginRestore/beginCommissioning. Addon is stopped/error. Independent raw USB SYS_VERSION succeeds. The R4 read-only MT SYS F1 management request returned valid B1S1 with source prefix 828b1b5e, stage=2/HOLD_NV, first error=4, probe=4 and latest NV_INIT 0x21. Normal commands are denied by the firmware HOLD. The actual compiled R4 native seal **includes the 4-page A4000 NV4 bridge**, so code 4 is an ambiguous mapped NV4 rejection, not proof of an NV2-only build. There is no established R4 network/state9 acceptance. Do not start the add-on again, power-cycle, restore backup, write NV, raise counters, or re-pair. Pin the precise NV4 rejection against the private unchanged-at-flash captured bytes and new live ROM read **only when properly controlled**.

**Exact-C follow-up:** The hosted-built, source-sealed observer and exact bridge
accept both saved preflash captures: 952 records, 779 active, formed candidate,
bridge probe 7. Original/traced results and all 2,421 reads match. This does not
prove current live NV unchanged. Use the [forensic decision procedure](P7U_NV_HOLD_FORENSICS_20261020.md)
before preparing any new firmware or hardware operation.

**Z2M's beginRestore path may attempt NV deletion and startup-option writes before its reset wait.** The observed firmware HOLD appears to reject those commands, but that is not proof of zero persistent writes; a new read-only live capture must establish any continuity claim. Keep preflash snapshots secret on Zephyrus.

## Minimal R4 flash lane

1. **GitHub Actions only** for build/test. Reuse pinned native candidate from commit `828b1b5e55d24a13dccf88bffe74108bf4b56bcc`, run `39425070812`. No WSL builds, new candidate, or generic repeated CI cycles unless a specific failure demands it. Artifacts live in `C:\Workspace\artifacts`; secret board reads and journals live under `C:\Workspace\.analienx\zigbee-private`, never in a worktree or GitHub.
2. Confirm **actual current device** is reachable through the selected BSL transport; read-only silicon identity, factory CCFG and independently captured full backup, with approved genuine-TI security preflight. Do not use stale NV/counter snapshots as live equivalence evidence.
3. Freeze exact approved sector list from `r4_stock20260311_transition.prepare`. R4 writes **23 APP sectors** and exactly **one AC000 boot/handoff sector**; the latter replaces the factory boot trust boundary. Explicit owner authorization must name AC000. `0xA0000..0xABFFF` (gap/NV) and `0xAE000..0xAFFFF` (top/CCFG) are **never erased or written**.
4. `admit` reads/checks live board identity and all 88 sector SHA/ROM CRC values. `execute` journals each sector, writes APP vector sector last, then AC000 tail and **AC000 vectors last**. A timeout/unknown write stops in BSL with no retry, automatic stock restore, reset, bank erase or counter increment.
5. After exact readback and controlled boot, verify ZNP/identity/security and traffic; **then** switch to USB for HA Z2M. Keep routing issue #137 on HOLD until physical evidence exists.

### Important constraints

- The versioned `p7u_stock20260311_rom_adapter.py` now supports **explicit private IPv4 TCP/6638** as well as COM. [GitHub-hosted adapter regression #39433211887](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39433211887) passed. On 2026-10-20 the real SLZB-06p7U at `192.168.50.59` entered ROM BSL over Ethernet and a 240-byte counted read succeeded. Two independent full 704-KiB captures matched each other; genuine TI8.33 semantic security preflight passed against a previous retained snapshot even though four NV pages changed. **This paragraph originally preceded the successful 2026-10-20 APP+AC000 flash.** The 24 approved sectors were flashed and readback-verified (all 88 sectors parity PASS, no NV/CCFG sector in target list). The app responds to ZNP SYS_VERSION over Ethernet and HA USB. **R4 operational acceptance remains BLOCKED:** one Z2M start failed, and F1 status reports HOLD_NV; do not repeat a start or reset.
- SMLIGHT supports Ethernet flashing of its Zigbee SoC but cautions that a stable **wired** connection is important. Its generic `smlight-cc-flasher -ewv` example is **not** authorization for this partial-sector R4 migration: the `-e` path may erase areas we must preserve.
- Vendor guidance: [SMLIGHT CC2652 flashing methods](https://github.com/smlight-dev/slzb-06-manual/blob/main/docs/guide/flashing-and-updating/updating-cc2652p.md), [SMLIGHT CC flasher transport](https://github.com/smlight-tech/smlight-cc-flasher).
