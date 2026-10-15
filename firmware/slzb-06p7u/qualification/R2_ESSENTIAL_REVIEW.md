# Issue 80 follow-up: essential scope and review disposition

The source review in PR 81 remains complete for its available-source/linked
coordinator scope. Its demonstrated persistence, packet bounds, ownership and
security-counter fixes remain in place. Closed TI internals and fitted hardware
are still outside that proof. This follow-up closes practical gaps rather than
reimplementing the historical 36-feature P10 inventory.

## Keep for the first hardware candidate

- Same-unit original-state capture, a verified independent copy, repeatable ROM
  entry and a recoverable original stock application. The scalar reader needs a
  measured probe before a long capture; theoretical throughput is not evidence.
- Separate exact-five-sector NV5 preparation and original-NV restoration. The
  application writer still rejects NV and CCFG. Original NV restoration requires
  stock application CRCs first and a quiescent captured network.
- Source-route cache 192 and neighbors 64, plus actual runtime concentrator
  readback. Cache entries and relay hops solve different problems. Retain 12
  relay hops, broadcast 9/queue 10, data retries 2 and inherited NWK buffers until
  a measured failure justifies tuning.
- Ordinary host/RF operation, multihop commands, bindings/groups, battery polls,
  rejoin and clean-restart persistence on a small disposable network, followed
  by real stock rollback. Household migration and the intended network load
  follow that recovery proof.
- A small read-only health report: AF completion categories, transport errors,
  first NV failure/site, current free heap and actual concentrator RAM values.
  Keep the existing v1 snapshot unchanged. Use the existing ZNP owner for live
  queries; preserve evidence before an operator chooses recovery.

The app writer and stock tail cleanup retain their original 23-sector envelope
ending at 0x2E000. The native image fits with 116 bytes to this artificial boundary;
there is no need to extend it for this candidate. Silicon flash is not exhausted.

## Defer or qualify only when used

Do not copy P10 buffer/retry counts, implement retained AUX/previous-boot state,
add unsolicited tracing, walk the heap or add automatic reset loops. OTA is a
capability test before relying on OTA, not a first-flash gate. Deliberate power
cuts during writes/compaction wait until normal recovery is proven on this only
P7U. Ordinary clean restart/counter persistence remains essential.

The 32-bit sleepy broadcast mask is a real inherited limitation to investigate,
not an invitation to widen an array consumed by a closed library. Test actual
association slots before claiming 0xFFFF delivery above slot 31, and establish
whether household traffic needs that path. Binding/group traffic and ordinary
sleepy reports still need representative functional tests.

See the [milestone policy](../../slzb-06p7/ti832/phase0/R2_ACCEPTANCE_MATRIX.md)
and its tracked historical feature dispositions.

## Related drafts and remaining integration

PR 83 already operationalizes the existing v1 endpoint and stages an optional
Zigbee2MQTT bridge. This change preserves v1; its new length-prefixed v2 adapter
is an alternative owner integration, not a second connection or bridge to run
alongside it. Both define SYS F0; select one definition/integration. The new
adapter rejects a competing definition instead of silently replacing it.

PR 84 contains migration counter-floor planning, a read-only escrow reader and
an offline NV preservation report. Those are not proof of a physical backup,
stock recovery or safe same-network restore. The new two-pass/resumable raw
capture and NV tool use their own matched manifest format; do not mix escrow
receipts between the tools. Keep original backup material immutable. The
three missing security records and historical counter/key conflicts reported
in issue 80 remain migration work, with an explicit re-pair fallback.

Issue 80 reports P7U USB enumeration at Home Assistant but no stock ZNP ping
reply. That does not establish ROM entry or a working radio bridge. This review
has not contacted any device, changed HA/Z2M, used network keys, flashed or
erased a radio. All physical milestones remain open.

## Follow-up review findings

- Rejected a CRC-valid shortened v2 health success payload in the JS owner
  adapter; version 2 requires the actual 118-byte schema, or an 18-byte error.
- Updated the independent runtime-NV test to consume the actual C health
  schema after the bounded heap fields were added.
- Catch asyncio's timeout type explicitly: Python 3.10 does not alias it to
  the built-in TimeoutError, so the initial host client leaked that exception.
- Retained the original 23-sector writer and stock-cleanup boundary after the
  actual native image proved it fits. The offline planner now also rejects the
  next sector, matching the writer's existing limit. Boundary/cleanup fault
  tests verify the upper sector and unchanged bytes outside the envelope.
- Removed an unsubstantiated 16-hop change; native capacity checks now verify
  the retained 12-hop constant and 24-byte relay list rather than requiring
  numerical parity without a demonstrated need.

Host tests are software evidence. Fresh native linked/resource checks and the
actual one-device recovery sequence are required for their respective stages.
