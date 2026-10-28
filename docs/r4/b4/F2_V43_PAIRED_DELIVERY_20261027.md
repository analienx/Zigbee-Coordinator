# F2 v4.3 paired radio and host delivery

This candidate combines the UART failure unwind with its matching F2 decoder,
durable writer and collection admission. The release pins the firmware and host
source commits independently, with compiled and physical proof of the shared
wire contract. The host accepts deployed minor1 and minor2 while staged; minor3 radio
acceptance requires a genuine 240-byte reply and the new native fields.

## Firmware

F2 keeps the eight-byte request nonce and the original header, base counters,
18 response-stage counters and nonce offsets. Minor3 appends twenty little-endian
u32 fields at byte160 and changes the declared response length to240. This fits
TI's pinned 250-byte MT maximum. Minor1/2 remain exactly160 bytes. Reserved bytes
and invalid legacy counter slots retain their strict zero rules.

The new fields, in wire order, are:

`npiRequests`, `mtEntered`, `mtReturned`, `uartWriteAccepted`,
`uartWriteRejected`, `uartCallbackOk`, `uartCallbackError`,
`uartLengthMismatch`, `stateFlags`, `uartRxBytes`, `firstFaultKind`,
`firstFaultStatusBits`, `firstFaultExpected`, `firstFaultActual`,
`firstFaultFlags`, `firstFaultTick`, `firstFaultCommand`, `npiWakes`,
`b1FirstFailure`, `tickPeriodUs`.

Request counters cover SREQ consumption by the existing NPI owner and entry/return
of the actual MT dispatcher. F2 excludes itself from these new request counters.
UART counters distinguish immediate write rejection, accepted submission,
successful driver callback, callback error and length mismatch. They do not claim
wire EOT or host receipt; the existing TX_FINISHED and passive host counters remain
separate. Counters saturate. No new task, UART owner, allocation, NV operation or
reset is introduced.

State bits0..3 mean TL busy, physical B1 HOLD, MT dispatcher active and frozen
first-fault present. Bits16..31 contain the last observed SREQ cmd0/cmd1.
First-fault kinds1..5 are immediate TX rejection, TX callback status error,
TX callback length mismatch, RX callback error and completion after preexisting
physical HOLD. The first record is immutable until boot. Its command is the last
observed request, not an invented per-write transaction ID. Status is signed32
encoded as u32 bits. Ticks are the wrapping RTOS clock with the supplied tick
period, not a wall clock or proof of radio uptime. B1 failure is the existing
startup first-failure field; B1 source and physical HOLD policy are preserved.

The original eight-function C fixture now compiles the final instrumented bodies.
A second fixture executes the actual240-byte F2 handler, request wrapper,
saturation and first-fault preservation; mutations overwrite the first fault or
remove dispatcher return instrumentation and must fail.

## Collection under sustained traffic

The first three worker-ACKed native records reserve a baseline through the existing
owner. Later60–90-second attempts use idle admission. After15 minutes
without a worker-ACKed native record, monotonic time enables one F2 reservation
at the next transaction boundary of the existing ZNP mutex. The adapter queue may
remain nonempty. F2 never interrupts the active request. Its reservation expires
after at most1000ms without acquiring ownership. Once admitted, its reply budget
is20seconds, covering a physical7.9second valid reply observed under retained
network traffic. Waiting production requests resume afterward. The protected
startup F1 and UTIL reads use the same20second budget; production request defaults
remain unchanged. No request is retransmitted when its budget expires.

OTA, disconnect, inter-PAN and live blocking SRSP gates are rechecked at the actual
write boundary. Expiry, queue clear and veto cannot leave an orphaned reservation
or submit a delayed frame. F0 remains unchanged. Existing nonce correlation,
timeout cooldown/progress requirement and bounded failure policy remain active.
The collector records passive evidence on skipped reads and first host timeouts.

A dead MT task, physical transport HOLD or continuous OTA can still prevent a
native reply. A missed objective is reported explicitly, never counted as VALID
and never used to reset the radio automatically. This change prevents ordinary
adapter backlog alone from starving F2 for hours.

## Paired release and physical acceptance

The firmware source must pass composed-C, current-stock dual native, existing
NV/CCFG/security and boot checks. The host source must pass the real compiled
host tests and deployable-image qualification. Native source sealing binds the modified
TL, MT, NPI and SYS sources and requires the progress helpers in the ARM ELF.

Stage the matched host before the radio update; it remains compatible with the
current radio. Use the existing guarded single-owner APP+AC000 operation with
fresh protected-region backups and readback verification. Accept only after normal
Zigbee/MQTT responses resume and at least three genuine minor3 snapshots with
advancing native sequence and complete progress fields are durably committed.
Preserve prior diagnostic history and original network/security state.

The host and firmware remain a pair even when the separately qualified operator
is repaired. The qualified pair is source899f179. A live read-only preflight
found ten normal short-address changes and one user3 to user2 association release.
Pinned TI `source/ti/zstack/stack/nwk/addr_mgr.h` at SDK3615ad5d (SHA256
b3112594ba8332efdae74f6f7b482e5b93524e01b14b27acace76db51e4b84b9)
defines ASSOC=1 and SECURITY=2. Runtime comparison permits only release of ASSOC
while retaining SECURITY, IEEE identity, padding and every other ownership bit.
Keys, replay floors and APS references keep their original strict checks. This
normalizes comparison only; it never edits any NV byte.

A consumed zero-write HOLD is not replayed. A pinned continuation binds every
file of that operation and the stopped owner, rejects any flash-admission or
write artifact, and creates a new server-generated operation. It must recapture
the same current image with88 ROM CRCs and fresh NV, rerun all security checks,
and avoid repeating BSL entry. It cannot continue a failed or ambiguous write.

If that read-only attachment times out before any capture or admission, a second
pinned witness may authorize exactly one fresh BSL entry. A separate immutable
consumption record is written before dispatch. Any earlier BSL-entry, capture,
admission or write artifact on the failed attachment rejects this path. The new
capture must equal the original held image before security and flash admission.

After verified programming, a host timeout waiting for state9 can use the named
`resume-native` phase once. It verifies the original writer package and write
receipts, the failed single owner, fresh pristine B1 checkpoints and the retained
IEEE/key identity. It then requests retained startup once with formation denied,
observes native state9, releases its temporary serial ownership and starts the
paired host. The tested existing resume protocol and timeout limits are retained.

The serial socket adapter returns the first available bytes immediately; it does
not wait to fill a512-byte read for every short SRSP. If native READY was observed
but final verification timed out, `finish-native` performs fresh read-only F1,
UTIL and configured-marker verification plus a nonce-bound240-byte F2 probe. It
does not reset or repeat ZDO startup. Only the original terminal acceptance proof
may authorize starting the paired host; each finish attempt is consumed once.
