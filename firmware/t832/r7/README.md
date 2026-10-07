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
compaction-failure reformat remains disabled. The R10 follow-up classifies every
page before startup writes, rejects nonblank incompatible headers or NACT data,
and latches failed initialization instead of FORCE_CLEAN on ambiguous topology.
Fully erased pages can still be initialized. This does not qualify every torn
electrical write, legacy migration or private vendor schema.
The minimal debug follow-up uses distinct SYS revisions
BASE8320041 and DIAG8320042 (PR45 used8320031/8320032).
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

## R10 motivation and bounded preservation evidence

PR45's actual flash booted DIAG8320032 and answered SYS/DEBUG but lost the
commissioned NIB. Additional telemetry showed fresh initialization,467 successful
NV transactions,zero compactions and16756 appendable bytes. The complete physical
post-boot NV snapshot contained no native NIB, including inactive records. This
differs from R6's exhausted five-page configuration. It does not identify whether
the management uploader or TI's original destructive scan/init path removed NV.
Private snapshots and network keys remain outside this public repository.

The actual pinned-driver gate now checks 81 rejecting cases across asserting and
embedded-style nonfatal assertion lanes: 50 hand-picked cases (topologies,
compact-header negatives, legacy fail-closed, mixed recovery, RDY cursor,
multi-page erase range, duplicate PGCDST, divergent ACT twins and same-page duplicates, reserved header
fields, erase-tail divergent pairs, tail trios, stale end offsets, FULL-scope pairs, XSRC-scope pairs, RDY data, mixed twin+divergent trios, unmarkable erase tails) plus 31 enumerated generated cases (valid-NOR torn header bytes,
ambiguous destination/source/ready pairs, lone-ready, torn-erase remnants).
Each must reject repeated init and a full extended-API sweep
(create/update/delete/read/readCont/write/getItemLen/doNext/expectComp/
compact/erase/getFree/sanity plus a balanced lock/unlock pair) with zero
physical operations and identical full-image hashes. A dedicated adverse probe
verb shows expectComp(nonzero) cannot reach the page walker after a rejected
init; the whole sweep also runs under AddressSanitizer+
UndefinedBehaviorSanitizer with no findings. ACT/FULL/XSRC live IDs must agree pairwise across and within ACT, FULL, and XSRC pages:
every pair of live copies sharing an ID is proved verbatim (bounds, both CRCs, payload bytes) or fails closed, except divergent pairs on the live CRC-valid tail ID of a resume topology with at most one older copy and no older twin alongside, which resume dedups (lab-proven by mutation cuts). Below-end erase offsets admit only with the suffix proof (every live item above the offset verbatim-twinned on dst), since cleanPage hides the suffix. Non-end range pages admit when blank or all-live-twinned on dst, and drained ends admit when blank or twinned, since cleanPage erases them (twins survive). Erase admission also requires the driver's XDST tail-mark to land on an erased page, or on a page cleanPage erases first (in-range), or init fails every boot. Missing recovery destinations return a
latched error instead of the upstream startup spin. Healthy reopen stays
unchanged; truly blank initialization still succeeds. Existing exhaustive
compaction/write gates apply. The 15,504 state-count families in the report are
Python model combinatorics, not driver executions; execution evidence is the
counted probe runs (648 reject, 64 admit, 324 sanitizer).

An original-state-only host recovery has now been designed with a retained genuine
native NIB and saved associations; it does not require provisional formation.
Factory NV can also lack the address and security-manager tables, so an offline
fixture that pre-creates these does not establish live restore qualification.
The next authorized firmware experiment must retain original native records and
physical NV before upload, capture first boot, and establish uploader erase-range
evidence before calling this an inherited-NV fix. R10 is not authorized to flash
by its build manifest; do not automatically deploy it after vendor recovery.

## R10 startup-cost qualification (Q2)

Per-read costs on T832 (CC26X4, FASTOFF=1, no RAM_OPTIMIZATION, 2KB pages,
XFERBLKMAX=32): findOffset is 1 call x 2048B; readHeader is 1 call x 7B;
the erased scan is at most 64 calls x 2048B; the boundary walk is at most
513 calls x 7B; CopiesEqual(len) re-reads both payloads at
2*ceil((len+4)/32) + 2*ceil(len/32) calls and 4*len+8 bytes. Every
classifier walk is capped (512 steps, 64 slides); anomalies and early
rejects only read less, so a clean-end census soundly bounds any image.

Per-init classify ceiling for C chk pages (ACT/FULL/XSRC) with Htot live
headers (Hmax max per page) and max payload Lmax: the 15-page header loop
plus one tail block, a tail census of C walks with at most Htot re-proofs,
and the pairwise proof of C outer walks with Htot x C conflict walks and at
most Htot x C x Hmax cmpid-match re-proofs; erase-branch twin proofs run
only when a PGCDST page exists. The hosted gate computes this ceiling from
each measured image's own census (q2_classify_bound in
verify_startup_guard.py) and fails if two bare inits exceed twice the
classify ceiling plus a flat driver scan/resume allowance. Measured cases:
all 8 admit pre-images (including PGCDST erase shapes, which exercise
PageTwinned/SuffixTwinned), one 220-item dense page, and its two-page
identical twin (which exercises the quadratic pairwise proof with
byte-compare re-proofs on every live ID).

Stack/RAM: the classify frame is capped at 1KB by host -fstack-usage
(frames recorded in report.json; exact array accounting is 5 x 15B page
vectors + 30B offsets + locals, under 200B). Helpers nest at most two
walks deep (~8B each) plus one 64B compare-buffer pair and one header
struct; no recursion, no malloc. The 2KB tBuffer page buffer is
pre-existing driver static storage. Measured startup reads (hosted): see
the run table below once the instrumented gate goes green.
