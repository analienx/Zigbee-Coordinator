# T832 R8 hardware-only gates (A11)

Hosted CI proves the algorithm, the geometry, and the packaging. It does
not prove a radio network. Nothing below can be closed from hosted
evidence, and household deployability must not be claimed until every
row passes on sacrificial hardware first, then on a restorable household
path.

| # | Gate | Why hosted evidence is insufficient |
|---|------|--------------------------------------|
| H1 | Sacrificial P10 BASE runbook green (`QUAL-SEAL.json`) | Real NOR timing, brownout behavior, and vendor page contents are not modeled by the Linux fault harness |
| H2 | Sacrificial P10 DIAG runbook green | DIAG instrumentation path must prove identical recovery on silicon |
| H3 | Inherited-page compatibility: real vendor NV items readable after BASE/DIAG boot | The lab populates synthetic families, not the vendor item schema |
| H4 | Boot read/write/reboot behavior with synthetic state | Init/resume/compaction interplay on silicon, including cold power loss mid-compaction |
| H5 | Each TX and RX security counter independently non-decreasing across every step; exactly one sealed candidate flash per BASE/DIAG phase | Counter slots and operator sequencing live outside hosted firmware execution |
| H6 | Radio operation (join, route, report) on the sacrificial unit | No radio exists in CI |
| H7 | Rollback to vendor image restores exact vendor bytes | Byte equality must be observed on a real dump, not asserted from containers |
| H8 | Household path only after H1-H7: verified restore/readback, cold backup, counters above highest emitted, rollback receipt | Household keys and network state never enter public CI by design |

Stop boundary (unchanged): no live coordinator flashing, no Z2M
re-pairing or network restore, no HA mutation, no MG26 touch, no NVM
erase, no reset/restore retry loops, no BDB mode0 to hide a missing
NIB/IEEE/key. `flash_authorized` stays false in every sealed manifest
until H1-H7 pass.
