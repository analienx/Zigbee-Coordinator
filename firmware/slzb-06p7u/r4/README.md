# SLZB-06P7U R4 firmware — tree overview

R4 is a stock-derived Z-Stack ZNP for the SLZB-06P7U (TI CC2652P7). The image currently on the production coordinator is **V53** (source `8ec1439`, tag `p7u-v53-firmware-source`), installed 31 October 2026. For its state, open items and review, see the coordinator folder:

- [Status, 31 Oct 2026](../../../coordinators/slzb-06p7u/STATUS_2026-10-31.md)
- [V53 long-term reliability review](../../../coordinators/slzb-06p7u/REVIEW_V53_2026-10-31.md)
- [Safety and acceptance gates](../../../coordinators/slzb-06p7u/README.md)

Nothing in this tree authorizes a flash, reset, BSL entry or NV change.

## How the image is built

No modified TI source is stored here. The image is TI SimpleLink `lpf2-8.33.00.16` (`simplelink-lowpower-f2-sdk` `3615ad5d`) with these stages applied, in this order:

1. **B0** — board contract, donor inventory and native build (`b0/`).
2. **B1** — fail-closed NV, management/HOLD path and retained startup (`b1/`, applied by `b1/tools/apply_b1.py` and `b1/tools/patch_*.py`).
3. **B1+B3 security fusion** — `tools/r4_b1_b3_security_fuse.py` at the repository root.
4. **The composite stage**, `tools/r4_b0_b4_composite_stage.py` at the repository root. It applies, in order:
   - B2 MTO guards and B4 v3/v4. Their donor scripts are fetched by SHA in CI (tags `archive/r4-donor-*`).
   - AF register handoff.
   - F2 v4.2 causal evidence.
   - V43 UART TX liveness.
   - F2 v4.3 progress.
   - V44 SRSP service.
   - V45 SRSP reserve.
   - F2 v5 flight recorder.
   - V46 runtime priority.
   - F2 v6 owned stage.
   - V47 startup ingress.
   - V48 ZDApp fairness.
   - **V50–V53** (`tools/r4_v50_stack_service.py`).
   - **V52 timers** (`tools/r4_v52_osal_timers.py`).

   Every stage checks exact preimage hashes, then compiles the emitted C and rejects mutants (`tools/*_harness.py`).
5. **Native build and seal** — `.github/workflows/test-r4-stock20260311-native.yml`, `qualification/build_native.py`, `b1/tools/seal_native.py`.

## Directories

| Path | Contents |
|---|---|
| `b0/` | Board contract, donor inventory, TI toolchain install/provision tools, artifact-audit fixtures (`b0/fixtures/` — synthetic oracle inputs, never native proof) |
| `b1/` | `b1_management.c`, `b1_admission.c`, their C tests, patchers and harnesses; design notes (`MANAGEMENT.md`, `NV_INTEGRITY.md`, `FAULT_MATRIX.md`, `B1_SECURITY_GATE.md`) |
| `qualification/` | Native build driver, board profile, NV4 admission oracle, transport smoke tests |
| `release/` | Operator, sealing and packaging; dated incident and finalization notes (see below) |
| `release/rom_writer/` | ROM/BSL low-level transport, strict APP-sector writer and image gate |
| `profiles/` | NV4 profiles (`p7u-r4-full-nv4.json`, `p7u-r4-stock20260311-nv4.json`) |

Host side, outside this tree:

- `tools/p7u_ha_flash_driver.py` and `host/flash/` — single flash driver and sealed HA operator.
- `host/r4-b4/` — custom host apps, uninstalled 31 Oct.

## Latest version only

`main` carries the V53 lineage as one commit. Files used only by earlier versions or phases were left out, among them the R4-00 provenance phase (design memo, provenance and parity tools, their fixtures) and the R4-01a diagnostics reference. They remain in the PR #195/#196 history. The V43–V52 stages are **not** earlier versions in this sense: each is a layer composed into V53 and stays.

## Dated documents are historical

Files with a date in their name (for example `release/R4_FIRST_PHYSICAL_FLASH_INCIDENT_2026-10-17.md`, `release/P7U_TRANSPORT_AND_FLASH_QUICKSTART.md` from the Ethernet/stock period, and `docs/r4/b4/*_2026102*.md`) record the state at that date. They are kept for traceability. When one conflicts with the coordinator status or review, the newer coordinator documents win.

## Running the tests

```sh
python -m pytest tests          # from the repository root
```

As of 1 November 2026: 924 passed, 31 skipped. Harnesses that need the pinned TI SDK or the TI toolchain skip, or run only in the native workflows.
