# PR #38 update — DRAFT (not posted; no live actions this session)

Title: `T832-DIAG-R0 R2: fix S01–S16, seal A01–A16 to exact-SHA hosted evidence`

Body:

R2 fixes all S01–S16 defects and seals ACCEPTANCE-R2
(`docs/T832_DIAG_R0_ACCEPTANCE_R2.md`): every A01–A16 row maps to hosted
regressions at the exact code SHA, with matched images and raw evidence.
Independent acceptance review requested; no merge, no flash, no live runs
from this session.

Evidence run: https://github.com/analienx/Zigbee-Coordinator/actions/runs/37192825360
(completed success, 7m35s, headSha
`fb7b64182d0950e0010afc8e40114bb4fc4c0810`)

- Fast lane (job 111408470109): C recorder HARNESS RESULT: PASS on the real
  implementation; Python suites 73 tests OK + 22 tests OK.
- Firmware (job 111408470176): policy contract PASS; 73 + 22 tests OK;
  C harness HARNESS RESULT: PASS; compiled `T832_BUILD_ID 0xfb7b6418`;
  capacity/NVS/stack/RAM contract PASS; `flash_authorized: false`.
- Interop (job 111408470195): HARNESS RESULT: PASS; `INTEROP PASS:
  10 records round-tripped, negatives rejected`.
- Control (job 111408470198): matched T832-KCTRL-R0 image built.

Images (hashes recomputed locally from run artifacts, equal to bundle
SHA256SUMS; manifests bind `repository_commit fb7b641`):

- `T832-DIAG-R0.hex` (549646 B)
  `2b0b5d430668505ce982b4fe41a188e261365a71d2afe3c4bb7ff2c56f6a92e6`
- `T832-DIAG-R0.out` (2593608 B)
  `e19876578c24e8957a4638a27ddeb01ccff449684e04c8ad316a85232839f2af`
- `T832-CONTROL-R0.hex`
  `bf2a178b04276a9af0dfe75ca2a6ddb324d3da9d636491c829d5d4a0b11d54a5`
- `T832-CONTROL-R0.out`
  `f4eed7bfea6aca2016d8f605a68fbb721aaf21a6f71885242e03089a11d7fc0d`

Scope honesty: hosted evidence does not cover real-HW allocator
exhaustion/timing, 72 h soak, or fault injection; production board/CCFG/
recovery/backup flash gates remain separate.

Reviewer: please verify each A01–A16 row against the cited fixtures and
the run above. Do not merge on Muse's word alone.
