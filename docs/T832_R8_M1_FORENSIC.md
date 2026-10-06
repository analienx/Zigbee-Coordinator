# T832 R8 M1 — interrupted-compaction forensic record (R7 base)

Base: R7 SHA `3d8129daa97522ee53514e3872ad9f0b73710055`, hosted run
`37494326769` (branch `codex/t832-r7-vendor-nvs`, workflow
T832 R7 vendor-layout NV regression). TI SDK pin
`6499c3f53fc5fb5806213be695450a7b43fbaf3d`, `source/ti/common/nv/nvocmp.c`
LF sha256 `d37c7f31...012d6d6` (full: `d37c7f314696c8669413cfb098900e41ffd2a4d48704481e5dd8c9a8c012d6d6`).

Fixture: vendor-20240716 profile, 15 pages x 2 KiB, 400 TCLK, 76 device
records, 485 addresses, MINIMUM_FREE_BYTES=2048. Each lane compacts with
201 physical operations; 108 cut points sampled, 98 pass, 10 fail.
BASE and DIAG lanes fail identically (parity holds on R7).

Immutable evidence: hosted artifact `t832-r7-nv-evidence`,
`vendor-20240716-BASE/` (`fault-base.bin`, `cut-N.bin` pristine
post-cut images, `negative-init/headroom-N.bin` inspection copies,
`reopen-N.bin` post-verify images) and `nv-lab-report.json`.

## Failure classes (source-level)

Page states: NACT FF / XDST FE / RDY 7E / ACT 7C / FULL 78 / XSRC 70.
Mode byte at page offset 6: NORMAL FF / CDST FE / CDONE FC / CSRC F8.
`NVOCMP_changePageState` = 1-byte write at page offset 0 (nvocmp.c).
On a fresh boot the NV handle is zeroed (initNvApi), so
`pNvHandle->tailPage` is 0 until assigned.

### H1 — stale resume-destination mark (nvocmp.c initNv decision block)

```
else if(noPgNact)
{
  pgXdst = pgNact;
  NVOCMP_changePageState(pNvHandle, pNvHandle->tailPage, NVOCMP_PGXDST);
  action = NVOCMP_NORMAL_RESUME;
}
```

`tailPage` is stale zero here; the selected erased page `pgXdst` is
ignored for the mark. Six cuts take this branch (no XSRC/XDST state,
ACT or FULL present, no CDST-mode page, erased pages present):

| cut | page 0 | NACT pages (pgXdst=last) | effect |
|-----|--------|--------------------------|--------|
| 26 | ACT | 2, 4 | init FAILURE: 0x7C->0xFE rejected 0->1 |
| 116 | ACT | 3, 9 | init FAILURE (same) |
| 144 | ACT | 3, 11 | init FAILURE (same) |
| 172 | ACT | 3, 13 | init FAILURE (same) |
| 187 | FULL | 3, 14 | init FAILURE: 0x78->0xFE rejected 0->1 |
| 200 | NACT | 0, 3 | init ok, wrong page stranded XDST, free 1772 |

Hosted errors: `flash program rejected 0-to-1: page=0 offset=0 bytes=1`
+ `init index=0 status=1` (H1a x5); `headroom=1772 required=2048`
(H1b x1). For cut 200, 1772 + 2032 (hidden page 0) = 3804, the true
free of the converged image (byte-identical to passing reopen-201).

### H2 — interrupted-transfer duplication (RECOVER_COMPACT path)

`NVOCMP_compact` never invalidates source originals while copying;
invalidation happens only when `cleanPage` erases a fully drained
source after the transfer ends. Interrupting a transfer (XSRC present,
no XDST) and re-compacting re-copies both the partial destination and
the intact sources, leaking ~one page permanently:

| cut | XSRC page | CDST dst (mode/hdrs) | reopen free |
|-----|-----------|----------------------|-------------|
| 19 | 2 | pg1 CDST, hdrs absent (cut pre-compact-end) | 1777 |
| 81 | 7 | pg6 CDST, hdrs present (cut post-compact-end) | 1795 |
| 109 | 9 | pg8 CDST, hdrs present | 1777 |
| 179 | 14 | pg13 CDST, hdrs present | 1993 + cleanPage offset-writeback rejected (`page=14 offset=4 bytes=2`, swallowed by a later `NVOCMP_failW` reset at compact entry) |

Recomputed post-recovery free values match the hosted report exactly
(1777 = 1500+18+18+223+18 over ACT pages; 1795 and 1993 likewise).

## Fix direction (M2)

P1: mark `pgXdst`, not stale `tailPage`. P2: settle the CDST
destination (complete the transfer when its compact headers prove the
copy finished; erase it when headers are absent/torn, which proves
cleanPage never ran; never erase on disagreement). P3: drop the
unconditional resume-time maintenance compaction so a read-only reopen
performs zero physical mutations in the normal path. Implemented as
`t832-r8-nv-recovery-01` in `firmware/t832/r6/nv_recovery_fix.py`,
applied identically to BASE/DIAG firmware sources and lab sources,
fingerprinted by `audit_source.py` and `run_nv_lab.py`.
