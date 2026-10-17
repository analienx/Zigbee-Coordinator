# R4 B2 — isolated source development (issue #95)

**Base:** B0 exact commit `1baefbee8e4de2c9d28c5e1a7c339cf2025a2afe`.
**Scope:** CC2652P7 / SLZB-06P7U routing capacity, route failures, NWK/MAC queues and bounded memory.
**Status:** B2-00 IN PROGRESS; NO native-capacity claim; PHYSICAL_UNVERIFIED.

The first commit includes a conservative evidence validator, not a firmware patch.
`tools/b2_capacity_gate.py` rejects missing ELF/map attribution, ineffective
source defines, non-disjoint memory estimates and oversubscribed SRAM. Its unit
tests use **invented arithmetic fixtures only**, intentionally NOT proof of a TI
native binary. It must not be counted toward T01–T32 native-source acceptance.

Next: map actual immutable TI 8.33 symbols and route failure call graph, capture
B0 exact-SHA native linker/map receipts, and produce P0 baseline before selecting
P1/P2; P3 must fail specifically for SRAM overbudget. Do not tune TC/security
tables (B3). Native-source hostile C harness and two hosted CCS builds remain open.

No flash, no radio/HA/Z2M activity, no release, no merge. B1 integration requires
a later independent branch and verification of HOLD_NV/HOLD_SECURITY at MAC
admission. Do not claim B2_SOURCE_READY from these preliminary files.
