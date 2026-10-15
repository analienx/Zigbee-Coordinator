# P10-to-P7 feature parity and R2 acceptance

The [feature ledger](feature-parity.json) records the disposition of all
**F01-F17 and D01-D19**. Schema 2 reconciles the original 2026-10-12 G0 audit
with G5/G6/G7/F07, the firmware review and R2 routing work. It replaces the
stale `p7_implemented=false` / `p7_tested=false` pair with separate source,
linked, host and physical stages. No physical feature has passed.

Read the [R2 acceptance matrix and release limits](R2_ACCEPTANCE_MATRIX.md)
before interpreting an implemented source feature as a production capability.
The essential milestone policy in that matrix controls R2 scope; all 36
historical features are not a release implementation checklist.
Each ledger row preserves its original P10 name, reference commit,
`evidence_path`, patch target, disposition and acceptance intent. Its new
`p7_evidence`, `decision`, stage values and acceptance cases state what the P7
actually has and what remains.

| Field | Meaning |
| --- | --- |
| `source` | Implemented in available source, partial, absent, or intentionally excluded |
| `linked` | Independent native artifact evidence, partial evidence, not verified, or not applicable |
| `host` | Actual-source/protocol host tests, partial coverage, not tested, or not applicable |
| `physical` | Currently `not_tested` for every item |
| `r2_disposition` | Essential, explicit alternative, retained default, deferred, or blocked |
| `release_qualified` | Currently false for every item; a compiler result cannot change it |

`partial` is deliberate: a requirement with several clauses is not marked
complete because one part works. For example, routing sizes are linked, but
runtime concentrator NV/RAM, sleepy broadcasts and real route behavior still
need separate evidence. A strict P7 diagnostic decoder is an alternative to
the P10 protocol; it does not implement that old wire format.

The original G0 lineage remains pinned: P10 CAP192 PR #60, R7-R12/A1, TI SDK
`6499c3f53fc5fb5806213be695450a7b43fbaf3d`, examples
`87ff5b638b632050228a7504f35cf3b95581c278`, and Herdsman 10.9.1 at
`0968f979d558874b17396c96b66382d4236bbdcd`. The original 18 SDK / 2 example
file delta and 25 ordered P10 SYS F0 counters are historical reference
contracts, not a claim that P7 emits the P10 ABI. Software results at a given
head do not certify a later source-changing head; PR #82 must carry fresh
native artifact and host-test evidence for its final candidate.

The validator checks all 36 IDs, original authority pins, nonempty decisions,
valid stages, existing repository evidence paths, all 18 acceptance categories,
and explicit hardware limits. Its negative controls reject fake physical
passes, missing evidence and accidental return to the low neighbor capacity.
It neither runs the SDK nor tests a radio:

```sh
python firmware/slzb-06p7/ti832/phase0/validate_inventory.py --selftest
```

The hardware scope is one **unused P7U**, with a network available from backup
only. No backup, key material, frame counters or device database belongs in
this public ledger. No source or host result authorizes device contact,
flash/reset/erase, Home Assistant/Zigbee2MQTT changes, or P10 operations.
