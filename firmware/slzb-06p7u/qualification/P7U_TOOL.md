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
  "candidate_sha256": "EXACT_APP_HEX_SHA256_FROM_VERIFIED_KIT"
}
```

The packet contains unmodified `kit/` and the full manufacturer container
`official-stock-20240710.bin`. Packet paths resolve against the target file.
Offline checking and HTTP control need only Python's standard library. Radio
operations use the pinned requirements of the underlying tools.

```text
python p7u_tool.py --target target.json
python p7u_tool.py identify --target target.json
python p7u_tool.py enter-bsl --target target.json --unused-p7u --out bsl-entry.json
python p7u_tool.py probe --target target.json --unused-p7u --already-in-rom-bsl --out probe-1
python p7u_tool.py backup --target target.json --unused-p7u --already-in-rom-bsl --backup original --out capture-1
python p7u_tool.py verify-backup --target target.json --backup original --copy INDEPENDENT_COPY --out backup-check.json
python p7u_tool.py restart-radio --target target.json --unused-p7u --out radio-restart.json
```

Run radio operations on the computer owning that USB port. `/dev/ttyACM0` on HA
is not a local Windows port. When management and USB are on two computers, use
the same tool/packet on each, with target files naming the local packet path;
issue management commands from the computer with P7U Wi-Fi access. This tool
does not install packages, stop integrations or create a serial proxy. Confirm
exclusive ownership before opening the port. Never run two readers.

Backup runs two independent reads and ROM CRC checks for every sector. `--resume`
only resumes interrupted read-only capture. Verify an independently stored copy
before NV preparation. The original application must match the pinned recovery
source; the management firmware date alone is insufficient. A mismatch stops NV
preparation and requires a reviewed rollback for the actual installed firmware.

`prepare-nv5`, `restore-nv5`, `flash` and `rollback` **inspect by default**.
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

`rollback` selects the stock app and clears the same 23 app sectors. After R2
has used NV5, restore the original NV with `restore-nv5` **while still in ROM**,
after stock app CRC verification, before restarting stock. Firmware rollback
alone does not restore the old network. See [NV5_RECOVERY.md](NV5_RECOVERY.md).

Only app sectors `0x00000..0x2C000` or separately five NV sectors
`0xA4000..0xAC000` can be written. The CCFG sector at `0xAE000` stays protected.
Commands leave the radio in ROM; `restart-radio` is explicit. An HTTP `ok`
acknowledges a command; it does not prove ROM access or ZNP startup. There is no
automatic retry, interrupted-write resume or implied migration qualification.
