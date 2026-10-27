# F2 v4.3 paired radio and host delivery

This candidate combines the UART failure unwind with its matching F2 decoder,
durable writer and collection admission. Both artifacts must name the same source
commit. The host accepts deployed minor1 and minor2 while staged; minor3 radio
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

Normal60–90-second attempts keep their existing idle admission. After15 minutes
without a worker-ACKed native record, monotonic time enables one F2 reservation
at the next transaction boundary of the existing ZNP mutex. The adapter queue may
remain nonempty. F2 never interrupts the active request. Its reservation expires
after at most1000ms without acquiring ownership. Once admitted, its reply budget
is500ms. Waiting production requests resume afterward.

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

One source commit must pass the focused composed-C and real compiled host tests,
current-stock dual native build, existing NV/CCFG/security and boot checks, and
deployable-host artifact qualification. Native source sealing binds the modified
TL, MT, NPI and SYS sources and requires the progress helpers in the ARM ELF.

Stage the matched host before the radio update; it remains compatible with the
current radio. Use the existing guarded single-owner APP+AC000 operation with
fresh protected-region backups and readback verification. Accept only after normal
Zigbee/MQTT responses resume and at least three genuine minor3 snapshots with
advancing native sequence and complete progress fields are durably committed.
Preserve prior diagnostic history and original network/security state.
