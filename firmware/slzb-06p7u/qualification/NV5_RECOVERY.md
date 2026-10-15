# Same-device original backup and deliberate NV5 preparation

This tool implements the missing **software** operations. They have been tested
against a byte-addressable fake ROM, including interrupted erases and writes.
The actual one available P7U has not been contacted. ROM entry/reentry, bridge
reliability, physical recovery and elapsed capture time remain hardware gates.
No second P7U is assumed. The user's intended network exists only in backup;
this unused radio's original raw state is a separate recovery artifact.

`p7u_nv_recovery.py` defaults to offline `verify`. Its live phases connect only
to an explicit endpoint which the operator has **already placed in ROM BSL**.
They never ask SMLIGHT to reset the radio, never issue a ROM reset, and never
reset on failure. USB model, board revision and SLZB-OS version must be physically
confirmed. ROM silicon/flash/factory IEEE/installed CCFG are checked independently.
For a socket connection, a read-only SMLIGHT model and full management MAC check
also precedes opening the radio stream; Ethernet availability is not assumed.

## Capture and independent verification

1. Identify the physical unused **SLZB-06P7U**, fitted board revision, host OS,
   full management MAC and the actual working USB or LAN bridge. Prove stock
   ZNP and repeated ROM BSL entry/exit before a write. A COM port or network
   endpoint must be supplied explicitly; the tool does not discover devices.
   Before committing to a long capture, run the read-only `probe` command with
   `--device`, `--management-mac`, `--board-revision`, `--host-version`,
   `--unused-p7u`, `--already-in-rom-bsl` and a new private `--out-dir`.
   It checks identity, reads the first 8KiB page twice (4,096 scalar read
   transactions plus 52 identity reads), and compares three ROM CRCs. Its
   `probe.json` reports measured page time and an explicit 88-sector
   extrapolation. The latter is an estimate excluding filesystem overhead and
   later bridge variability; a successful small sample cannot certify a full
   backup. No bytes or raw factory IEEE are printed, and no erase/reset occurs.
2. Keep the radio in ROM BSL. Close other radio clients. Run `backup` to a
   **new private directory outside the repository**, using `--backup-dir`,
   `--device`, `--management-mac`, `--board-revision`, `--host-version`,
   `--unused-p7u` and `--already-in-rom-bsl`.
3. Every one of the 88 8KiB sectors is read twice independently. ROM CRC before,
   between and after the reads must match the local CRC; bytes and SHA-256 must
   agree. The complete 704KiB image includes original application bytes, all five
   proposed NV5 pages, and the full protected CCFG sector. Final identity must
   still match. `original.bin`, `manifest.json`, `capture.json`, immutable sector
   files and a durable per-sector `events.jsonl` are retained privately.
4. Copy the **entire directory** to independently controlled storage. Run offline
   `verify --backup-dir <original> --backup-copy-dir <copy>`; both raw files and
   all per-sector digests are rederived. The copy must be a distinct file, not a
   hardlink. Storage independence is an explicit operator confirmation, since
   software cannot infer whether two directories share the same physical disk.

Flash/NV contains network keys and device identifiers. Do not upload these files
to issues, PR artifacts or CI. The directory mode requests owner-only access on
Unix; on Windows use an already private directory with the appropriate ACL.
Console output and journal entries contain bounded status, addresses and hashes,
never the raw key/IEEE/CCFG bytes. Atomic exclusive file publication refuses any
existing destination; originals are never overwritten. The filesystem must
support local hardlinks for atomic publication; otherwise capture stops safely.

An interrupted capture preserves completed sector files and logs. Re-run
`backup --resume` with exactly the same directory, endpoint and identity inputs.
Every retained sector is freshly read and compared; a changed sector stops the
resume. An uncleanly terminated process may leave `capture.lock`; remove only
that lock **after confirming the old capture process is gone**. Partial staging
files remain as evidence. A final manifest exists only after the full read and
identity checks complete.

## Separate five-sector operation

`inspect` requires the verified original directory and independent copy, explicit
endpoint/MAC, `--independent-copy-confirmed`, `--unused-p7u`,
`--already-in-rom-bsl`, `--official-stock-bin` pointing to the SHA-pinned
manufacturer 20240710 container, a **new** `--out-dir`, and one action:

| Action | Desired bytes |
| --- | --- |
| `--action prepare-nv5` | Erased `0xFF` in exactly the five NV5 sectors |
| `--action restore-original-nv5` | Original bytes from the verified same-device capture |

Preparation accepts only the captured original page or an already blank page.
Restore can inspect an interrupted or disposable-test NV state. Both actions
produce a sealed plan with the source backup digest, physical/ROM identity,
five current SHA/CRC pairs, desired SHA/CRC pairs and the live CRCs of **all 83
sectors outside NV5**. Inspect does not write the radio.

Before either operation can even open ROM, the complete vendor container is
independently checked by the existing stock extractor. The captured original
application must exactly match its official application payload; every byte
between that payload and NV5 must be FF. This establishes that the existing
application-only writer can reconstruct the original application without
touching NV or CCFG. An unknown original firmware or non-FF data outside that
contract blocks NV operations; capturing it does not create an unqualified
full-image writer. The pinned vendor hash, original application hash and
rollback plan/hash are bound into the NV approval and rederived at execution.

After reviewing this concrete `plan.json`, `execute` requires `--plan`, its exact
`--approve-digest`, both verified backup directories, a new receipt directory,
`--execute-nv-write`, `--rom-bsl-reentry-twice-confirmed`,
`--stock-application-rollback-available` and this explicit declaration:

`--original-network-declaration ORIGINAL_NETWORK_NOT_USED_SINCE_CAPTURE`

That declaration is required because restoring old NV can roll back security
counters. It is valid only while the captured network has remained quiescent
since capture. If the same network ran elsewhere or transmitted after capture,
do not use raw NV restore as a migration method. Preserve the backups and use a
separately validated counter-aware restore/re-pair procedure. This tool does not
claim to recreate the intended backup-only network or its missing security rows.

Before the first erase, execute rehashes both backups offline, rechecks live
factory/CCFG identity, independently rereads every NV page, and confirms all
outside CRCs. Its **separate** `NvRom` backend admits only complete sectors at
`0xA4000`, `0xA6000`, `0xA8000`, `0xAA000`, `0xAC000`. It rejects application
addresses and `0xAE000`; the existing application writer still rejects NV.
Each erase is logged before transmission, read back as all-FF, and—during
restore—programmed with bounded SEND_DATA packets and reread twice byte for byte.
Identity and the complete CCFG sector CRC are checked after each completed
sector; all outside CRCs are checked again at the end. No chip/bank erase,
MEMORY_WRITE or SET_CCFG exists in this adapter.

On any uncertain erase/write/read result, stop in ROM BSL and preserve the
receipt journal. There is no blind retry/resume-write switch. Create a **new
restore inspection and approval plan** for the observed interrupted state.
Restore the original stock **application first**, using the separately matched
application-only writer while remaining in BSL. Original-NV inspection and
execution both require every application sector below NV5 to match the captured
stock/FF bytes by ROM CRC before an NV erase is possible. Then restore the five
original NV pages, verify them, and re-inspect preparation if needed. Restoring
stock application bytes alone does not recover old NV; restoring old NV alone
does not recover a stock application. Keep the radio in BSL until both selected
parts and CCFG have been verified. No full-image writer
is provided, because writing the captured CCFG sector would defeat its purpose
as the independent escape hatch.

## Scalar protocol and performance evidence

The pinned [SMLIGHT command implementation](https://github.com/smlight-tech/smlight-cc-flasher/blob/9a1d33571c1cdaedc9dfcdcf2df5b5a5fece0b1c/smlight_cc_flasher/command.py)
uses MEMORY_READ with `extra=01 01` for one 32-bit word. Its existing pinned file
SHA-256 is `9fb42418ffa2301be52bfa2fe1208fb465138c2cc4cf432a767df2f6860ee25a`.
[TI SWRA466E, section 3.2](https://www.ti.com/lit/an/swra466e/swra466e.pdf)
documents the corresponding 32-bit memory-read API and explicit sector erase.
These sources do not establish a tested bulk-read path through this P7U bridge.
The tool deliberately retains the already reviewed scalar primitive; it does
not infer a byte-count encoding or silently switch protocols after a failure.

A single 704KiB pass takes **180,224 memory reads**; two independent passes take
**360,448**, plus identity and CRC calls. NV5 alone is 10,240 reads per pass.
For the current framing/status exchange, 29 wire bytes per scalar read at
115200 8N1 is a theoretical lower bound of roughly **15.1 minutes** for the
full double read, before bridge/ROM/round-trip/filesystem latency. This is a
calculation, not a measured device time. Sector progress is durable and resume
prevents an interrupted transfer from discarding verified capture work.

Run the meaningful no-device fault suite with:

`python tests/p7u-rom-bsl-gate/test_nv_recovery.py --vendor <official-20240710-container>`

It checks a nonuniform full-image capture, interrupted-read resume, exact-byte
five-page prepare/restore, unchanged application/CCFG bytes, different-device
and modified-artifact rejection, old application/NV backend separation, and
mid-erase/write/read failures followed by new-plan recovery. None proves actual
ROM BSL access, flash endurance, backup throughput or hardware rollback.
