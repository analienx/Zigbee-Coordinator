# P7U transport choice and R4 flash quickstart

Applies only to the **single production SMLIGHT SLZB-06P7U R1.73 / CC2652P7**. Do not substitute the historical 06P7, MR4U, P10, or a hypothetical spare.

## One-command R4 operator (versioned, Python, no WSL)

Use `release/p7u_r4_operator.py` rather than manually invoking the
capture/preflight/writer/startup scripts one by one. It is an **orchestrator**,
not another flasher: the audited Windows ROM writer and original one-shot,
source-pinned private adapters still perform physical operations. It verifies
the GitHub candidate and every file hash, validates duplicate 704-KiB live
captures, retained-security admission, the frozen 25-sector APP+AC000 plan,
and saved hardware receipts. Verified stages are skipped; an initiated but
incomplete or failed one-shot stage **always HOLDS** (never retries).

```powershell
# Script + candidate data live outside the private NV/security workspace.
python firmware/slzb-06p7u/r4/release/p7u_r4_operator.py `
  --candidate C:\\Workspace\\artifacts\\p7u-r4-release-8f52d39 `
  --private C:\\Workspace\\.analienx\\zigbee-private\\p7u-r4-8f52d39-current-20261022 `
  --source 8f52d3936bee49be91ab63887f5847666ba6b125 status

# On a NEW prepared deployment only (never rerun current failed startup):
# replace paths and source SHA with its exact CI candidate receipt.
# Add --allow-bsl if capture is required; --allow-flash for APP+AC000,
# and --allow-boot only when a fully verified physical boot is wanted.
python firmware/slzb-06p7u/r4/release/p7u_r4_operator.py `
  --candidate <artifact-dir> --private <private-deployment-dir> `
  --source <40-character-tested-source-commit> `
  run --through flash --allow-bsl --allow-flash
```

The private deployment workspace must contain one-use source-pinned scripts
`capture_current_once.py`, `prepare_upgrade_once.py`,
`flash_upgrade_once.py`, and `startup_once.py`, plus the original
board-specific identity, private security reader and backup provenance.
These source-pinned private files are deliberately not committed or regenerated
over an existing hardware journal. The operator refuses stage replay on
partial captures, journaled erase, or one-shot startup failure.
The remaining improvement is parameterizing the existing private adapters
from a reviewed per-device manifest, without weakening their fail-closed
constraints. No blanket erase, automatic stock restore, NV replay, counter
increase, reset, or Z2M auto-start is provided.

**Physical result of source `8f52d39` on 2026-10-22:** 25/25 sectors
verified and final all-88 parity PASS; NV/CCFG untouched. One approved app
boot and one guarded retained startup produced continuous RAM NPI progress
but did **not** reach coordinator state 9 in 80 seconds. Last state=3,
phase=2 (BDB), status=0, error=0; the source of the stall is unresolved.
`startup-result.json` is a permanently consumed one-shot failure receipt;
**do not rerun**, reflash, reset, or start Z2M to paper over the failure.
Firmware code and live network recovery are separate acceptance gates. The BDB phase-2 marker is recorded after the BDB call returns, so it is not proof of an in-call stall.

## Physical wiring is not the selected transport

The P7U USB cable is physically connected to **Home Assistant (Raspberry Pi)**, **not** to the Zephyrus Windows computer. The coordinator's ESP/SLZB-OS switches which *logical* Zigbee data path is active; switching modes does not move that physical cable. No COM port on Zephyrus in Ethernet mode is expected.

| Situation | Radio mode | Operator/data path | What to do |
|---|---|---|---|
| **Latest owner report (2026-10-21): stock NV restored, startup blocked** | **Ethernet / ZNP** | Stock ZNP at TCP/6638; Z2M stopped | Original network is present in NV, but UTIL state is 0 after two failed starts. Do not repeat restore or startup speculatively. Current work changes firmware only. |
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

**2026-10-21 resolution:** the approved live capture reproduced semantic HOLD:
NIB is inactive and startup option is 3, while APP/boot/CCFG match their pins.
The next candidate protects retained NV at raw MT entry points and ships with
non-destructive host startup. Its firmware work does not re-run capture or
repair the incident state. See the [current candidate procedure](R4_P7U_STOCK20260311_FINALIZATION.md).

## Minimal R4 flash lane

1. **GitHub Actions only** for build/test. Use the exact `source_sha` from the final passing **CURRENT stock20260311** candidate receipt, including its APP and AC000 hashes. Earlier `d924faa` / run `39554982599` and `828b1b5` are historical evidence, not the new reviewed startup candidate. The protected host bundle is optional; production targets ordinary unmodified Zigbee2MQTT. No WSL builds or repeated CI without a changed source or concrete failure. Artifacts live in `C:\Workspace\artifacts`; private board reads and journals stay outside Git.
2. Confirm **actual current device** is reachable through the selected BSL transport; read-only silicon identity, factory CCFG and independently captured full backup, with approved genuine-TI security preflight. Do not use stale NV/counter snapshots as live equivalence evidence.
3. Freeze exact approved sector list from `r4_stock20260311_transition.prepare`. R4 writes **23 APP sectors** and exactly **one AC000 boot/handoff sector**; the latter replaces the factory boot trust boundary. Explicit owner authorization must name AC000. `0xA0000..0xABFFF` (gap/NV) and `0xAE000..0xAFFFF` (top/CCFG) are **never erased or written**.
4. `admit` reads/checks live board identity and all 88 sector SHA/ROM CRC values. `execute` journals each sector, writes APP vector sector last, then AC000 tail and **AC000 vectors last**. A timeout/unknown write stops in BSL with no retry, automatic stock restore, reset, bank erase or counter increment.
5. After exact readback and controlled boot, verify healthy B1/F1, ZNP and retained identity/security on Ethernet. A separately approved one-time retained startup uses the guarded non-forming ZDO path; require actual state 9, continuous ZNP and the configured marker. Then the owner returns once to HA USB and starts ordinary unmodified Zigbee2MQTT with matching network configuration. Do not repeat backup restoration to fix a timeout. Keep routing issue #137 on HOLD until physical evidence exists.

### Important constraints

- The versioned `p7u_stock20260311_rom_adapter.py` now supports **explicit private IPv4 TCP/6638** as well as COM. [GitHub-hosted adapter regression #39433211887](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39433211887) passed. On 2026-10-20 the real SLZB-06p7U at `192.168.50.59` entered ROM BSL over Ethernet and a 240-byte counted read succeeded. Two independent full 704-KiB captures matched each other; genuine TI8.33 semantic security preflight passed against a previous retained snapshot even though four NV pages changed. **This paragraph originally preceded the successful 2026-10-20 APP+AC000 flash.** The 24 approved sectors were flashed and readback-verified (all 88 sectors parity PASS, no NV/CCFG sector in target list). The app responds to ZNP SYS_VERSION over Ethernet and HA USB. **R4 operational acceptance remains BLOCKED:** one Z2M start failed, and F1 status reports HOLD_NV; do not repeat a start or reset.
- SMLIGHT supports Ethernet flashing of its Zigbee SoC but cautions that a stable **wired** connection is important. Its generic `smlight-cc-flasher -ewv` example is **not** authorization for this partial-sector R4 migration: the `-e` path may erase areas we must preserve.
- Vendor guidance: [SMLIGHT CC2652 flashing methods](https://github.com/smlight-dev/slzb-06-manual/blob/main/docs/guide/flashing-and-updating/updating-cc2652p.md), [SMLIGHT CC flasher transport](https://github.com/smlight-tech/smlight-cc-flasher).
