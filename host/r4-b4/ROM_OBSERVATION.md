# One-shot P7U ROM protocol observation

This role distinguishes an already responding TI ROM bootloader from the silent
ZNP status path. It does not enter bootloader mode, reset, commission, access NV,
send a synchronization pulse, or contain a flash/erase/download command.

The fixed transcript is PING `0x20`, GET_STATUS `0x23`, GET_CHIP_ID `0x28`, and
GET_STATUS. Each request is framed as `03 opcode opcode`; received data packets
must have the exact expected length and checksum and receive a data ACK. RESET
`0x25`, DOWNLOAD `0x21`, SEND_DATA `0x24`, SECTOR_ERASE `0x26`, MEMORY_READ
`0x2a`, MEMORY_WRITE `0x2b`, BANK_ERASE `0x2c` and CCFG `0x2d` are absent.
Framing and the GET_STATUS success value follow the pinned SMLIGHT command.py
SHA256 `9fb42418ffa2301be52bfa2fe1208fb465138c2cc4cf432a767df2f6860ee25a`.

The same pinned herdsman SerialPort/native binding opens the one fixed P7U USB
by-id path at 115200 with no RTS/CTS or explicit modem toggles. Inherited HUPCL
is cleared and verified through that already-owned descriptor before any byte
is sent. There is no normal Znp, Adapter or Controller startup. The role's
dedicated image entrypoint cannot be selected through normal Z2M options.

The source/image-bound gateway requires the original inactive owner epochs,
both old HOLD journals, global incident pointer, passive guard, disabled
competing starters, board/USB identity, approved database/cold archive/backup,
and the exact completed 9d13e8c F1 failure receipts and container. It admits one
new manual-only app and one new durable observation intent within the existing
incident. Three independent host-PID zero-holder checks precede startup and
follow close. The old F1 app and normal Zigbee hosts cannot be started by this
role. No HA button or vendor-private HTTP mutation is permitted. The temporary
loopback registry is stopped and post-probe host proofs are retained.

`ROM_PROTOCOL_OBSERVED` requires all four exchanges. A ROM chip ID is not a
board identity, firmware attestation, NV continuity proof, or network recovery.
A timeout is `ROM_STATE_UNKNOWN`: it does not rule out ROM awaiting autobaud,
nor distinguish an ESP/UART failure from a silent radio. Noise, partial packets,
NACK, bad checksum/length, transport errors and deadline consume the attempt
without retry, SYNC, reset, another baud, transport switch or normal startup.

GitHub-hosted tests exercise the fixed fragmented transcript and hostile input,
durable admission and replay refusal, and the real compiled native SerialPort
on a Linux PTY with inherited HUPCL set. An ARM64 role is sealed from the same
audited filesystem as the diagnostic image, without executing it or contacting
hardware. A source build and a simulated ROM response do not establish the
physical coordinator's current mode. No reset-only recovery is authorized or
implemented by this observation role.
