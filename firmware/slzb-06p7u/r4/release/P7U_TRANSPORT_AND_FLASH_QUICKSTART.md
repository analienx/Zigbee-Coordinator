# P7U transport choice and R4 flash quickstart

Applies only to the **single production SMLIGHT SLZB-06P7U R1.73 / CC2652P7**. Do not substitute the historical 06P7, MR4U, P10, or a hypothetical spare.

## Physical wiring is not the selected transport

The P7U USB cable is physically connected to **Home Assistant (Raspberry Pi)**, **not** to the Zephyrus Windows computer. The coordinator's ESP/SLZB-OS switches which *logical* Zigbee data path is active; switching modes does not move that physical cable. No COM port on Zephyrus in Ethernet mode is expected.

| Situation | Radio mode | Operator/data path | What to do |
|---|---|---|---|
| **Current state: stock after restore, preparing R4** | **Ethernet** | Zephyrus -> wired LAN -> SMLIGHT control + ROM BSL socket (if guarded adapter supports it) | **Keep Ethernet.** Z2M is stopped and still configured to HA USB; do not start it or toggle modes for preparation. |
| R4 flash with validated Ethernet BSL support | **Ethernet** | Native Windows operator -> TCP/6638 in ROM BSL; management control enters BSL separately | Preferred when the exact host, stable link, readback, silicon ID and safety admission work. No WSL or device-mode toggle. Never use a generic mass-erase flasher. |
| Ethernet BSL admission fails, or network path is unstable | Stop, unchanged unless explicitly directed | Assess HA-attached USB path or move physical cable to Windows under a *new explicit plan* | Do not pretend USB mode creates a Zephyrus COM port. Do not flash via an unreviewed TCP bridge. |
| Post-flash verification while still in BSL | **Keep Ethernet/BSL** | Pinned APP+AC000 readback, all unchanged NV/CCFG sectors checked | Do not start Z2M or change mode until the write has been positively verified and the controlled boot action is authorized. |
| Restore normal 107-device Z2M operation | **USB**, *only after verified boot* | P7U USB -> Home Assistant `/dev/serial/by-id/...` -> Z2M configured for USB | User switches mode deliberately, then starts Z2M only after correct firmware/identity/security checks. Do not silently change Z2M settings. |
| Day-to-day HA operation | **USB** | HA owns radio | Leave Ethernet management web UI reachable if its firmware supports `Keep network & web server`. Only one Zigbee host owns serial. |

**Never confuse** (1) physical USB cable to HA, (2) ESP Zigbee-to-USB/Ethernet mode, (3) TI ROM BSL, and (4) the Windows host where artifacts reside.

## Minimal R4 flash lane

1. **GitHub Actions only** for build/test. Reuse pinned native candidate from commit `828b1b5e55d24a13dccf88bffe74108bf4b56bcc`, run `39425070812`. No WSL builds, new candidate, or generic repeated CI cycles unless a specific failure demands it. Artifacts live in `C:\Workspace\artifacts`; secret board reads and journals live under `C:\Workspace\.analienx\zigbee-private`, never in a worktree or GitHub.
2. Confirm **actual current device** is reachable through the selected BSL transport; read-only silicon identity, factory CCFG and independently captured full backup, with approved genuine-TI security preflight. Do not use stale NV/counter snapshots as live equivalence evidence.
3. Freeze exact approved sector list from `r4_stock20260311_transition.prepare`. R4 writes **23 APP sectors** and exactly **one AC000 boot/handoff sector**; the latter replaces the factory boot trust boundary. Explicit owner authorization must name AC000. `0xA0000..0xABFFF` (gap/NV) and `0xAE000..0xAFFFF` (top/CCFG) are **never erased or written**.
4. `admit` reads/checks live board identity and all 88 sector SHA/ROM CRC values. `execute` journals each sector, writes APP vector sector last, then AC000 tail and **AC000 vectors last**. A timeout/unknown write stops in BSL with no retry, automatic stock restore, reset, bank erase or counter increment.
5. After exact readback and controlled boot, verify ZNP/identity/security and traffic; **then** switch to USB for HA Z2M. Keep routing issue #137 on HOLD until physical evidence exists.

### Important constraints

- The current versioned `p7u_stock20260311_rom_adapter.py` is **COM-only**. Ethernet flashing is *not yet implemented* in that adapter; never claim it can flash over TCP until an explicitly scoped, reviewed, GitHub-verified network transport exists and live read-only admission succeeds.
- SMLIGHT supports Ethernet flashing of its Zigbee SoC but cautions that a stable **wired** connection is important. Its generic `smlight-cc-flasher -ewv` example is **not** authorization for this partial-sector R4 migration: the `-e` path may erase areas we must preserve.
- Vendor guidance: [SMLIGHT CC2652 flashing methods](https://github.com/smlight-dev/slzb-06-manual/blob/main/docs/guide/flashing-and-updating/updating-cc2652p.md), [SMLIGHT CC flasher transport](https://github.com/smlight-tech/smlight-cc-flasher).
