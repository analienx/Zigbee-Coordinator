# A1 one-shot startup forensics — gates and order

## Verified baseline
- R12 8320062 remains running; post-power event54 unexpectedly still showed **old A0** attempt `0xA0120001`, seq1/site1 entry. A prior retained A0 witness showed seq2/site1 exit. These observations do not prove a clean new diagnostic epoch.
- Original backup SHA256 `bd95f00eb3ce1f7794f9c6406c5b4fd96a0c6aa0ef5cdbaa7a29d25d3f6083b8`: 103 devices, 103 keys, 103 required address associations, counter+2500 safe.
- Live read-only NV lengths: 1=8, 3=1, **33/NIB=0**, **35/address manager=0**, 85=1, 96=0. This is not a verified commissioned network.

## Mandatory correct sequence
1. **Before changing firmware**, independently qualify and restore NIB, address and security tables on current R12 using the original saved 116-byte native NIB and immutable full backup. The older two-stage `restore-native` and `restore-tables` paths have *different prerequisites*; neither may be blindly invoked against simultaneous missing NIB and address manager. Confirm actual APS/TCLK/NWK capacities, original IEEE/PAN/channel/key identity, complete 103 associations, and counter floors.
2. Allow any necessary restoration soft reset **before** arming A1. Verify 103 keys/address rows, exact NIB and updated counters **after** restoration. Do not issue `startupFromApp`.
3. Build/pin new diagnostic `8320063`, attempt `0xA0120002`, epoch `0x20261011`; flash only after restoration proof, `eraseNVM=0`. A1's code consumes **only** an archived, CRC-valid A0 journal with the exact old image/attempt/epoch and seq1/site1-entry or seq2/site1-exit. Any foreign, mixed or visibly corrupted record is preserved.
4. Before a startup, collect the **new kind55 `R12_A1_ARMED`** frame. It attests a successfully enabled recorder, *not* a restored network. If missing, STOP; no blind startup.
5. Check the entire restored security state **again after the diagnostic flash**, because `eraseNVM=0` previously did not guarantee an accessible NIB. If flash destroys the NIB, do not restore-and-reset while claiming the recorder is still armed; plan another verified epoch.
6. Then allow exactly one `startupFromApp`. If hung, issue no second startup; use a separate radio-only reset and passive kind54 capture. Keep Z2M stopped and watchdog off.
7. Recovery by flash/restore from the sealed backup remains available but successful ZNP, complete NV and operational mesh are three separate acceptance conditions.

## A1 source and review
Separate worktree `codex/t832-a1-diagnostic`, preserving original R12. New 8320063 artifact is deliberately named `T832-R12-A1-DIAG-vendor-20240716`. R12 baseline NV/security/CCFG and native TI source gates are unchanged. The one-shot transition does not touch flash/NV/UART, and event55 uses the existing bounded T832D2 export. Native C, parser and artifact tests must pass before considering a flash.

**Current stop:** missing-NIB+missing-tables recovery is not yet qualified on this R12 state; no live NV writes or A1 startup authorized by this document.

## Actual A1 on-device execution — 10 October 2026 (STOP: NV vanished)

The source/host checks passed and the new A1 target firmware candidate was
compiled and linked by TI CCS in [Actions run 38028972584](https://github.com/analienx/Zigbee-Coordinator/actions/runs/38028972584).
The independently audited `T832-R12-A1-DIAG-vendor-20240716.slzb.bin`
is **207508 bytes**, SHA256
`5d0c3f111b9ec821da6c848ec62cfd32f3e08fa0cb22e7d385f2ca39705e0031`,
revision **8320063**. All 35 artifact hashes, linker A1 transition and
CCFG/vendor NVS image layout checks passed. No image NVS records.

**The original-network restoration was completed BEFORE flashing A1**,
using the separately qualified R12 restoration worker:
- First live read-only inspection failed safely (`NV85=00`, not
  assumed `01`), **zero mutations**. Corrected preflight to the
  measured uncommissioned state and passed subsequent live inspection:
  NIB absent, address manager zero, security manager absent,
  actual APS capacity3, TCLK400, NWK material5, saved native NIB
  round-trip true.
- One separately sealed `restore-a1-blank` ran **630 allowed NV mutations**,
  including the 116-byte native NIB and saved 103 associations and
  +2500 TX-counter margin, then one soft reset.
- Native readback **BEFORE AND AFTER** that restore reset verified original
  identity, keys **103/103**, addresses **103/103**, startup flags and
  safe counter floors. ZNP remained responsive (SYS ping3/3) at rev8320062.
- A newly sealed full current backup has SHA256
  `10da53f304940219611496ebee239841ea00b519b33e0f0d035b7d06732e9aaa`;
  the corresponding private current native NIB snapshot SHA256
  `3661b0122649c339cd107ebb03667fc64456386ebeadd4a1ca52216084bc082e`.
  These private files were **not committed**.

The operator-authorized **single A1 firmware flash** used the proven SLZB
P10/index1 endpoint with **`eraseNVM=0`**, no automatic retry. Management
reported completion; exact ZNP SYS_VERSION returned **8320063** and
3/3 SYS pings. **No `startupFromApp`, Z2M start or network formation.**

**BLOCKER A: newly restored network inaccessible again.** A direct
read-only `osalNvLength` after the A1 flash returned **NIB item33=0**,
**address-manager item35=0**, identity item1=8, startup item3=1,
on-network item85=1, configured item96=0. Thus a *second* firmware
transition with requested `eraseNVM=0` resulted in the same loss of
readable original network state. The exact source of the loss is **not
known**: possible physical erase by SLZB management/ROM bootloader versus
NVOCMP initialization/index handling or a runtime NIB cleanup. Image
size/layout/hash verification alone **does not prove** that a flash
command preserved the physical top NVS pages. Do not assert that physical
NVS flash was erased without a raw before/after ROM read.

**BLOCKER B: A1 recorder readiness not demonstrated.** A bounded
receive-only listener, started after firmware update, received 14 valid
T832D2 frames, checksum errors zero, including R11 kinds52/53, but
**zero kind55 `R12_A1_ARMED`** groups. This is inconclusive:
`t832R12ArmEventSent` fires only once when `T832R11_sendGroup`
succeeds; the only event could have been sent before the TCP listener
connected, or the exact A0-to-A1 transition could have been rejected.
Do **not** equate nonreceipt to a proven transition failure. Next
diagnostic firmware must make its arm readiness **reliably observable**
(e.g. repeat until a bounded host acknowledgment/poll, rather than
fire-once before client attachment) before authorizing a startup.

A separate local private forensic receipt at
`C:\Workspace\.analienx\sonoff-private\recovery\p10-a1-singleflash-20261010\a1-postflash-evidence-verdict.json`
is SHA256
`a616e373d0d72e59cf263995276f7e1408b3f0becd49d16f1b2409270cc9a151`.
It records source image SHA256, old/new backup acceptance, postflash
NV-item lengths, the passive capture digest and zero startups. No
network secret values are published.

**Current operational verdict:** **ZNP running, network offline and
uncommissioned, diagnostic A1 startup NOT PERFORMED**. Stop firmware
reflashing or restoring as a loop until the flash/NV persistence root
cause is isolated. A known-good restore backup remains sealed with
all 103 associations. The A1 event55 export reliability defect is
a separate, smaller code change after the NVS blocker is understood.
