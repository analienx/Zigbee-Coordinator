# P7U host review and controlled rollout

Issue #144 and draft PR #148 own this change. A direct user instruction on
23 October permits a direct SSH/Supervisor deployment path without Foundry.
It retains exclusive coordinator ownership, exact-source qualification,
private backup and committed-database approval. It does not authorize a radio
flash, reset, commissioning, network-key/counter replay or a second UART reader.

A later direct instruction authorizes the existing ESP32 restart automation
when essential for recovery. That bounded action still needs current device
identity, preserved incident evidence, a stopped serial owner, a unique durable
attempt receipt and independent post-restart evidence. It does not arm the
unattended recovery guard or authorize a factory reset/radio flash.

## Review corrections

- Create or verify the database admission receipt only after the previous
  owner has exited and three fresh host-global FD scans find no UART holder.
  Journal the receipt before requesting a start.
- Check the actual passive guardian options and manual boot/watchdog policy
  for every possible owner; reject a competing third add-on.
- Exclude the legacy HA boot/recovery automations as independent service
  starters. Both exact automations must be off before every stop/start, with
  pending boot retries cancelled by the operator before the handover.
- Qualify the installed prebuilt image even when Supervisor has removed its
  stopped container. Pin the new container ID, image ID and process generation
  after startup, including the Node child that actually holds the UART.
- Handle Paho v2 connection results as `ReasonCode` objects. MQTT acceptance
  requires real, nonretained device publications and an independent HA state
  read; optional F2 evidence does not establish serving health.
- Refuse explicit SYS/SAPI reset commands in the protected runtime. Save the
  candidate's models durably before radio-dependent shutdown awaits. This
  patch cannot change the already running official process's shutdown order.
- Stop optional collection when worker ACKs are missing. Keep naturally idle
  skipped samples distinct from a failed diagnostic transaction and preserve
  earlier v1 evidence.
- Attest the full staged diagnostic, fallback, inspector and manager packages.
  A native-image ID does not identify a differently packaged add-on image.

## Deployment mechanism

`.github/workflows/release-p7u-host.yml` waits for successful source workflows
at the exact candidate SHA, verifies staged-bundle hashes and file inventories,
then builds ARM64 add-on images on a GitHub-hosted runner. Its artifact includes
Docker archives, generated manual-only configurations and `RELEASE.json` with
the actual image IDs. No radio or HA host is accessed by this workflow.

The operator imports those archives and exposes them temporarily through a
registry bound only to HA host loopback port 50144. Supervisor installs the
prebuilt images through its normal registry mechanism. No repository build is
performed on HA, and no registry credential is embedded in the add-ons. Stop
the temporary registry after installation; retain its purpose, image identity
and log location in the private deployment receipt.

First run the separate host-PID inspector. Then run the lifecycle manager with
`execute:false` and an exact SHA256 of its private plan. Only after its real
preflight passes, run the same plan with `execute:true` once. The manager uses
an exclusive journal, one Supervisor stop, quiesced cold backup and DB approval,
then one target start. A lost response is reconciled from current state. A
pending/failed journal must be investigated; changing an operation ID does not
make it safe to replay a mutation. There is no automatic radio recovery or
optional-F2-driven rollback.

## Acceptance still requires live evidence

Source and container checks do not prove installation or network health.
Record the deployed image/container generation, sole UART holder, retained
inventory, real MQTT serving, at least three increasing durable native F2
samples under one owner, counter validity, persistence and the required soak.
Keep radio epoch and unsupported counters UNKNOWN. Leave the issue open and
the PR in draft until its live acceptance requirements are satisfied.

At the initial review preflight, the official add-on was still running
2.14.0-1; the old diagnostic installation was inactive. Subsequent read-only
observations found repeated SRSP timeouts and a loss of fresh traffic. The
complete current host and guard evidence was frozen privately before any
owner stop/start. This incident must not be attributed to an uninstalled
candidate or erased by an unapproved radio reset.
