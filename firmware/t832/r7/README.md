# T832 R7 — restore the audited vendor NVS extent

This candidate is for review and the established supervised coordinator flash
procedure. Its manifest records build evidence, not a live deployment receipt.
The public firmware repository builds and tests only in GitHub-hosted Actions
against the exact candidate SHA.

## Forensic finding

The SHA256-pinned SMLIGHT `20240716` reference container
`633f79058c39e2fc9335bb11f816ad6a045438515da11c36b30a46b7c8d1b7d9`
has internal NVS at **0xF8800, size 0x7800**, and its NV initializer clamps the
region/sector quotient to **15**, checking sector size **0x800**. The binary
audit follows NVS_config[0] to its internal attributes and the NV API initializer.
This is fifteen 2-KiB pages, not five. Source settings of a generic TI seed
cannot establish the geometry of this exact vendor image.

PR40 `546697ef8d44645dabf60b5c2921d6d79e079a60` uses
**0xFD800 / 0x2800 / five pages**. It points into the last five physical pages
of the vendor region and changes their relative numbering. It is a storage
layout change, even with an uploader eraseNVM=0 option and no NV payload bytes.

Retained private incident evidence shows R6 neutral writes initially returning
00 and later 0A; the direct NVINTF update returns 05. The boot recorder reports
NORMAL_RESUME, zero appendable bytes, active page4/tail3, and 112 out-of-space
faults. This proves the failure class is allocation/compaction-destination
exhaustion. The changed layout and retained eager persistent capacities explain
why lowering TCLK alone was insufficient. The precise first event that lost
the original network remains unproven without pre/post raw page snapshots;
failed restore flows also clear NIB and commission provisional state.

## Candidate and gates

R7 restores **0xF8800 / 0x7800 / 15 pages** in compiler options, linker,
SysConfig and actual linked NVS driver attributes/runtime clamp. It retains
400 TCLK slots (also observed by read-only vendor NV length boundaries),
75 device slots (+one parent) and four binding slots; TI derives 485 addresses.
It starts from the pristine pinned TI baseline, with matched BASE and DIAG,
using the already reviewed deferred NV recorder. The optional destructive
compaction-failure reformat remains disabled; inherited TI startup cleanup paths
are unchanged and are not claimed to fail closed on every malformed topology.
The minimal debug follow-up uses distinct SYS revisions
BASE8320031 and DIAG8320032 (the original R7 used8320021/8320022).
Recovery duplicate settling now verifies bounds, both CRCs and payload equality
before inactivation. Hosted post-cut writes verify all saved records and their
fresh-process persistence; a failed required write/recovery gate stops packaging.
The path to the next working debug image does not require a spare board or the
experimental hardware qualification checker. Use the established coordinator
backup, one-shot flash, NV readback and existing-network recovery procedure.

The configured persistent floor is 24,067 B; fourteen data pages provide
28,448 B. A separate 2,048-byte append reserve is required. This does not claim
the older experimental profile's 25% growth or three reserve pages.
Real pinned TI NVOCMP tests must populate all configured families, update,
create/delete, compact and reopen with persistence. A five-page negative
control uses PR40's full 112 TCLK/76 device/197 address configuration and must
reject allocation, so an arithmetic-only fix cannot pass this gate.

Binary audits compare the exact linked candidate with the pinned reference,
not just the generated map. Existing recorder, protocol, decoder and recovery
ordering regressions remain required. Symbols, HEX, BIN, map, generated files,
schema, collector and hashes are packaged together.

The original R7 hosted run exposed interrupted-compaction recovery failures,
including a 1,777-B append reserve below the unchanged 2,048-B gate. R8 addresses
those cases, and this follow-up requires every tested interruption to recover,
write, preserve all saved records and reopen successfully. The reserve gate is
unchanged. Hosted tests exercise the pinned driver against synthetic flash;
they do not claim live coordinator validation.
The Linux backend does not execute the complete TI stack or reproduce private
vendor pages. Exact inherited-page and vendor item-schema compatibility,
boot read/write/reboot behavior, security counters and radio operation remain
checks on the existing coordinator through the established backup and recovery
procedure. A spare board is not a prerequisite. No household backup or key enters
public CI.

## Before any household candidate deployment

Before the next supervised flash, retain a verified current original-network
readback, cold backup and counters above the highest emitted values.
Do not use BDB mode0 to hide a missing NIB, wrong IEEE or wrong key. Prove uploader
erase/program ranges and a complete rollback/restore receipt. Do not form a
replacement network, erase NV, touch MG26, or use a reset/restore retry loop.
Use the DIAG candidate for the minimum working debug path; BASE remains its
matched control image. Capture diagnostics before recovery, including init
action, page topology, request size, deepest status and first failure.

For raw evidence use the bundled manifest-bound `decode_raw.py`; report identity
mismatches, missing telemetry and partial captures as failures. No live or
hardware qualification is implied by the image's successful compilation.
