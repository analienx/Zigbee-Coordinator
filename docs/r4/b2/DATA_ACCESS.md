# R4 B2 evidence access — reproducible hosted receipts

**Status:** SOURCE_CONFIRMED for pinned TI definitions, preliminary B0
HOSTED_NATIVE_LINKED build previously successful, B2-specific linked extraction
pending the next exact-HEAD hosted native job. PHYSICAL_UNVERIFIED.

## Canonical immutable inputs

- TI Z-Stack examples: `TexasInstruments/simplelink-zstack-examples@87ff5b638b632050228a7504f35cf3b95581c278`.
- TI LPF2 SDK: `TexasInstruments/simplelink-lowpower-f2-sdk@3615ad5d3f4f271258d18a2f5ce1785064ff9a58`.
- Sealed B0 ancestor: `1baefbee8e4de2c9d28c5e1a7c339cf2025a2afe`.
- This branch: `feat/p7u-r4-b2-routing-capacity`, draft PR #96, issue #95.

## Source evidence (available)

GitHub Actions workflow **R4 B2 pinned TI source evidence**:
https://github.com/analienx/Zigbee-Coordinator/actions/workflows/test-r4-b2-source-evidence.yml

Proven successful run (exact source commit `b0909b63fa4c11337b019338ee4814c4357dc7a4`):
https://github.com/analienx/Zigbee-Coordinator/actions/runs/38953742308

Artifact `r4-b2-source-evidence-b0909b63fa4c11337b019338ee4814c4357dc7a4` (ID 12070055941)
contains:

- `B2_SOURCE_INVENTORY.json`: Git commit pins, file SHA-256 and line counts.
- `B2_EFFECTIVE_LIMITS.json`: source declarations and conditional macro candidates;
  linked counts, `sizeof` and ELF positions explicitly null.
- `B2_SOURCE_REFERENCES.json`: exact path:line source references; **not**
  a proven caller/callee graph.
- `SOURCE_CALL_GRAPH.md`: verified entry points and unresolved edges.
- `B2_BASELINE_MEMORY.md`: unresolved stack/heap/RTOS ledger.
- `DATA_STATUS.md`, `SHA256SUMS.txt`: evidence receipt and file digests.

These artifacts are deliberately short-lived (30-day CI retention). The
checked-in source extractor can regenerate them from pinned source commits;
no dependence on an external model, paid code editor, Zephyrus, HA or radio.

## Native B0 compiled artifact (available)

Native P7U ZNP build run:
https://github.com/analienx/Zigbee-Coordinator/actions/runs/38952302280

The genuine B0 native build job completed **successfully** at checkout head
`6d3b3cf462cc22572962b8224515a68ad9668faa`.
It published `r4-b0-native-f0bfba793257d8789c96886a5de552d0774fad98`
(artifact ID 12070035804), containing linker/image receipts plus real
ELF/XML/HEX/BIN. Note: GitHub's artifact name interpolates event
`github.sha` (PR merge SHA) while the job explicitly checks out the PR
head SHA; refer to the in-job head checkout for true source provenance.

The enhanced B2-branch native workflow now runs
`tools/b2_collect_native_evidence.py` after successful B0 native audit.
It generates `b2-linked-baseline/B2_BASELINE_ELF_SYMBOLS.json` and
`BASELINE_ELF_SYMBOLS.md` inside subsequent B0 native artifacts.
Until those are actually inspected, **do not infer effective linked limits
from the source defaults**. Collector reports missing symbols UNKNOWN.

## Strict interpretation

- `SOURCE_CONFIRMED`: pinned TI source definitions only.
- `HOSTED_NATIVE_LINKED`: authentic ELF/XML and directly recovered
  linked storage evidence, with exact build SHA.
- `HOSTED_SYNTHETIC`: unit/harness tests, not RF validation.
- `PHYSICAL_UNVERIFIED`: no deployed/network on-air proof.
- B2 source-ready remains BLOCKED until issue #95 native T01–T32 and
  P0–P3, compiler-defined effective limits, independent review and
  B1 integration conditions are satisfied.

No actual B2 routing firmware modifications, TC persistence changes,
live coordinator access or merge are authorized by these data receipts.
