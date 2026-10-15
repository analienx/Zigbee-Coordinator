# P7U R2 operator tool

`p7u_tool.py` is the single entry point for the matched R2 packet. It delegates
application writes and NV recovery to the existing checked implementations.
Management and radio endpoints are separate: a computer on the P7U Wi-Fi AP can
control the TI radio while USB remains the data path. The tool does not change
USB/Ethernet mode, HA services, ESP firmware or network settings.

Create a private `target.json` beside the packet; do not commit real identities:

```json
{
  "schema": "p7u-operator-target-v1",
  "model": "SLZB-06P7U",
  "management_host": "P7U_ADDRESS",
  "management_mac": "AA:BB:CC:DD:EE:FF",
  "board_revision": "1.73",
  "host_version": "ACTUAL_SLZB_OS_VERSION",
  "device": "/dev/ttyACM0",
  "packet": ".",
  "original_stock_file": "official-stock-20240316.bin",
  "candidate_sha256": "EXACT_APP_HEX_SHA256_FROM_VERIFIED_KIT"
}
```

The packet contains unmodified `kit/` and the full manufacturer container
`official-stock-20240710.bin`. Packet paths resolve against the target file.
If the actual original is 20240316, also include its full manufacturer container
as `official-stock-20240316.bin` and select it with `original_stock_file` above.
Omitting that field retains the original 20240710-only behavior. Only those two
explicitly hash-pinned manufacturer versions are accepted. The R2 kit and its
paired 20240710 fallback remain unchanged.
Offline checking and HTTP control need only Python's standard library. Radio
operations use the pinned requirements of the underlying tools.

```text
python p7u_tool.py --target target.json
python p7u_tool.py identify --target target.json
python p7u_tool.py enter-bsl --target target.json --unused-p7u --out bsl-entry.json
python p7u_tool.py probe --target target.json --unused-p7u --already-in-rom-bsl --out probe-1
python p7u_tool.py enter-bsl --target target.json --unused-p7u --out bsl-before-backup.json
python p7u_tool.py backup --target target.json --unused-p7u --already-in-rom-bsl --backup original
python p7u_tool.py verify-backup --target target.json --backup original --copy INDEPENDENT_COPY --out backup-check.json
python p7u_tool.py restart-radio --target target.json --unused-p7u --out radio-restart.json
```

Run radio operations on the computer owning that USB port. `/dev/ttyACM0` on HA
is not a local Windows port. When management and USB are on two computers, use
the same tool/packet on each, with target files naming the local packet path;
issue management commands from the computer with P7U Wi-Fi access. This tool
does not install packages, stop integrations or create a serial proxy. Confirm
exclusive ownership before opening the port. Never run two readers.

Enter ROM BSL freshly before **each separate ROM invocation**, including backup,
probe, inspection and approved execution. This unit acknowledges synchronization
after fresh entry, but a second process sending autobaud sync into an already
synchronized ROM session timed out in physical testing. Do not retry commands
into that stream. Reenter BSL explicitly, then start a new operation. Following
`restart-radio`, allow stock startup to finish before sending a ZNP request; an
immediate request can be lost while startup is still running.

Backup runs two independent reads and ROM CRC checks for every sector. `--resume`
only resumes interrupted read-only capture. Verify an independently stored copy
before NV preparation. The original application must match the pinned recovery
source; the management firmware date alone is insufficient. A mismatch stops NV
preparation and requires a reviewed rollback for the actual installed firmware.

`prepare-nv5`, `restore-nv5`, `flash`, `rollback` and `restore-app` **inspect by default**.
NV plans use a new output directory; app plans use a new JSON file:

```text
python p7u_tool.py prepare-nv5 --target target.json --unused-p7u --already-in-rom-bsl --backup original --copy INDEPENDENT_COPY --independent-copy --out nv-plan
python p7u_tool.py flash --target target.json --unused-p7u --already-in-rom-bsl --out r2-plan.json
```

Execution adds `--write --plan PLAN --approve DIGEST --recovery-proven` to a
separate invocation with a new output. NV execution also needs the same backup
arguments and `--original-network-quiescent`. These attestations are never
inferred from HTTP acknowledgements or builds. Existing cores validate every
plan, exact endpoint, current identity and pre-write CRC. `--recovery-proven`
means stock -> ROM -> stock -> ROM has actually been proved and the pinned
stock rollback is available. Review and approve the concrete first-write plan
as described in [the hardware plan](R2_FIRST_SINGLE_UNIT.md).

`rollback` selects the kit's 20240710 stock app. `restore-app` instead restores
the exact original application (20240316 or 20240710), requiring two verified
same-device backups AND the matching pinned manufacturer source. It checks all
65 sectors outside the app before and after execution, leaves NV/CCFG untouched,
and verifies the same 23 app sectors, with the vector sector programmed last.
Use the backup/copy arguments from NV preparation:

```text
python p7u_tool.py restore-app --target target.json --unused-p7u --already-in-rom-bsl --backup original --copy INDEPENDENT_COPY --independent-copy --out original-app-plan.json
```

After R2 has used NV5, restore the original app, enter BSL freshly, then restore
the original NV with `restore-nv5` **while still in ROM**, before restarting stock.
NV restore checks every original app/gap sector first. Firmware rollback alone
does not restore the old network. See [NV5_RECOVERY.md](NV5_RECOVERY.md).

Only app sectors `0x00000..0x2C000` or separately five NV sectors
`0xA4000..0xAC000` can be written. The CCFG sector at `0xAE000` stays protected.
Commands leave the radio in ROM; `restart-radio` is explicit. An HTTP `ok`
acknowledges a command; it does not prove ROM access or ZNP startup. There is no
automatic retry, interrupted-write resume or implied migration qualification.
