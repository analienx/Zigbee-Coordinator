# Run V6 recovery from the local workstation

`p7u_v6_recover_local.py` uses Python and the existing `ssh ha` configuration.
It runs the sealed operator on HA, where the USB device exists. No GitHub runner
needs private-network access. GitHub remains the builder/qualifier; the launcher
does not compile, flash, restore firmware, replay NV or change transport mode.

Download the successful paired-operator artifact for the reviewed operator
commit. Verify its GitHub artifact digest before extraction. The manifest must
bind **both firmware and host to `66ed700c2818c7a0963dad9160d55109009bbaac`**,
image `sha256:b79b875e32819ff9544f2844ba9573c795b9f28694218de0816f35fb00a9f78c`
and `R4D4_MINOR4_R4D5_PAGED_AND_R4D6_OWNED_V1`. The launcher rejects the older
e3/85 pair produced by PR #188's initial package defaults.

From this repository, using private absolute paths:

```powershell
$recoveryState = 'C:\Workspace\artifacts\p7u-v6-recovery-NEW'
python host/flash/p7u_v6_recover_local.py prepare --state $recoveryState `
  --package-directory 'C:\Workspace\artifacts\VERIFIED\operator' `
  --package-pin MANIFEST_SHA256 `
  --deployment 'C:\Workspace\artifacts\DEPLOYMENT\private-stage-result.json' `
  --write-plan 'C:\Workspace\artifacts\DEPLOYMENT\operator-plan-after-recovery-result.json'
python host/flash/p7u_v6_recover_local.py plan --state $recoveryState
python host/flash/p7u_v6_recover_local.py execute --state $recoveryState
python host/flash/p7u_v6_recover_local.py status --state $recoveryState
```

`prepare` only installs the sealed package. `plan` verifies the original write,
held native boot, current stopped owner, control source, protected retained-only
host startup and expected CRCs. It makes a fresh plan, expiring in 30 minutes.
`execute` consumes it before the USB-open-first ROM round-trip, checks all88
sector CRCs and fresh retained-security identity, returns to the unchanged V6
application with USB already open, requires a fresh SYS reset indication, closes
that temporary observer, then starts its protected host once. Startup remains
owned by that host; the recovery operator sends no external ZDO startup request.

Every dispatch has an exclusive local receipt and remote consumed-before-send
intents. A timeout/HOLD is **inspect, no replay**. Do not delete receipts or create
a second state directory to evade a consumed recovery. Read-only `status` may be
repeated; it reports the original write/boot operation. Recovery-specific outcome
is in `execute-result.json` and the remote operation's
`rom-recovery-v6-open-first` directory. If the earlier `rom-recovery-v6` operator
was used, the corrected operator additionally binds its preserved successful
no-write ROM receipt and exact stopped-host ping failure. It creates one distinct
operation for the corrected handoff; the consumed original operation stays sealed.

A running host is provisional. Verify completed herdsman/Z2M startup, fresh
non-retained MQTT reports from at least three devices, and genuine new native
minor4 and V6 STAGE records through the existing serial owner. Keep private
receipts, logs, snapshots, database and network credentials outside Git.
