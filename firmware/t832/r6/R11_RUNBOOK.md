# T832 R11 observer candidate

Matched BASE revision 8320051 and DIAG revision 8320052 preserve the R10 NV
recovery/startup policy. Both use the vendor profile: 15 pages, 30,720 bytes,
FLASH_NV at 0xF8800 through 0xFFFFF. The image contains no bytes in that region.
These are custom builds, not bitwise vendor firmware. Physical geometry and
live network behavior remain hardware qualification checks.

DIAG adds operation-aware first meaningful NV failure (event 51), eight bounded
startup milestones (52), and runtime progress snapshots (53). Successful inner
compaction statuses 0/1/2/3 do not mean failure; only 0x10 is compact failure.
Historical NV_FAULT(a8,b1,c27) remains ambiguous. API return status and inner
compaction status use different domains. Unknown item/status fields are marked
unavailable. No values, keys or packet payloads are included.

Each extension is an atomic four-record T832D2 frame. The existing five-second
attempt limit and UART/command gates apply. Runtime is due every 30 seconds;
first NV fault and latest startup repeat at 60 seconds when transport permits.
Every third extension opportunity is reserved for legacy telemetry. These are
eligibility intervals, not guarantees during a hung stack or blocked transport.
Ordinary SRAM is cleared on boot; bit31 stays clear and no reset-survival claim
is made. Missing exits or missing frames alone do not establish the hang cause.

Use the private versioned recovery controller in analienx/home-assistant-stack
for a fresh original-network backup, sealed image/hash validation, stopped
Zigbee2MQTT ownership, one flash, capture-before-recovery and rollback. Run the
same-vendor rehearsal before the R11 trial. Never form a network or erase NV.
If hung, try the normal radio reset first; true power removal is a fallback only
after reset fails. A responding state0 radio gets one canonical existing-network
startup per reset epoch. Preserve all original keys and monotonic counters.

Capture raw UART while Zigbee2MQTT is stopped; during operation consume its
zh:zstack:znp debug log without opening a second coordinator connection. The
included decoder accepts the real Herdsman Buffer representation and rejects
incomplete, mixed or duplicated extension groups. Keep captures private.

Before runtime soak, require the exact candidate build ID/capability, a startup
snapshot and two increasing runtime snapshots at least 30 seconds apart in one
observed boot epoch. Missing calibration requires evidence capture and rollback.
Seventy-two-hour soak, radio reset/power behavior, bridge loss and observer cost
are hardware checks. Hosted green builds do not prove them.
