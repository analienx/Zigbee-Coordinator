# Temporary R2 startup diagnosis

This opt-in build distinguishes a silent NV initialization failure from stack
pressure and later stack/NPI startup failures. The default R2 build is unchanged.
Run the integrated native workflow manually with `bootdiag=true`. It first
reproduces normal R2 and requires its app HEX SHA-256 to equal the image that
was programmed, then exports TI `tiarmofd --call_graph` evidence for that ELF.

The temporary variant reserves 4096 bytes for the C/interrupt stack, retaining
the old 1024-byte boundary as a measured threshold. It measures two separate
watermark windows: main/board startup before opening the diagnostic UART, and
the actual NV initialization call. The NV driver and persistence/security
guards are unchanged. The status and first existing NV failure/site are sent
before retaining the normal failure halt.

The watermark is a lower bound including instrumented caller/sampler frames.
An intact old boundary does not prove safety; a crossing must be assessed with
the emitted stack call graph and diagnostic frame overhead. A larger-stack
build booting by itself does not establish the cause. Stacks used by individual
RTOS tasks are separate and remain unchanged. Initial C runtime before main is
outside these two measurements.

The helper opens the existing UART0 configuration (115200, RX DIO12, TX DIO13,
hardware flow control disabled) after `Board_initGeneral`. Fixed eight-byte
numeric records use bounded FIFO/nonbusy polling, with no printf, allocation,
BIOS clock dependency or UART2 DMA writes. Diagnostic ownership remains with
the initialization path until immediately before NPI's normal UART open. It
closes only after successful bounded TX-idle confirmation. A TX timeout refuses
handoff rather than calling the driver's unbounded close or competing with NPI.
The final marker is emitted by the initializing NPI task using its own handle,
before its normal reads and transmit service begin. No diagnostic writes occur
after that point.

## Capture and interpret

Before any further flash, use `p7u_tool.py inspect-installed` to verify the
current R2 bytes/vectors and original CCFG/IEEE fingerprints, retaining private
NV5 metadata/CRCs. The native diagnostic artifact must fit at most 24 app
sectors. Its report identifies whether it needs 23 or 24; the restricted writer
and paired stock cleanup must cover the same count before an actual write.
This workflow never contacts or writes to the P7U.

With one exclusive USB reader, begin raw capture before the explicit management
radio restart. Capture through startup; do not flush input after the restart.
The normal household Zigbee2MQTT owner/configuration is outside this trial.
Decode a saved file with `decode.py CAPTURE.bin`; no serial port is opened by
the decoder. Raw captures and identity evidence remain private.

Each record is `A5 5A stage arg_lo arg_hi value_lo value_hi xor`, where xor makes
the XOR of all eight bytes zero. Stage meanings:

| Stage | Meaning | Argument / value |
| --- | --- | --- |
| 1 | Board startup returned | watermark flags / board-window bytes used |
| 2 | About to initialize NV | zero / zero |
| 3 | NV initialization returned | raw NVINTF status / NV-window bytes used |
| 4 | First recorded NV failure | site in high byte, status in low byte / watermark flags |
| 5 | About to start BIOS | zero / zero |
| 6 | Stack task entered | zero / zero |
| 7 | Crypto/PRNG seed | argument 0 before, 1 after / return status after |
| 8–10 | MAC / NV globals / stack services | argument 0 before, 1 after |
| 11 | Stack initialization returned | zero / zero |
| 12 | Diagnostic UART handoff | zero / zero |
| 13 | NPI's UART opened | 1 / zero |
| 14 | Existing assertion handler reached | assertion reason / zero |

Watermark flags: bit 0 measurement armed; bit 1 old 1024-byte boundary crossed;
bit 2 the lowest byte of the full 4096-byte allocation changed. No raw memory,
NV payload, device address, PAN, IEEE or key material is emitted.

An error return with comfortable stack margin demonstrates an NV reject; use
its failure site. A boundary crossing needs overhead analysis and a clean,
minimal stack-only confirmation. NV success with no crossing directs the next
investigation to the last reached stack/NPI stage. Missing records alone are
not conclusive. Neither RAM read after reset nor post-reset watermark retention
is required or assumed. Remove this overlay and all temporary output from the
final corrected candidate, then require normal ping/version/health/settings,
three successful restarts and isolated Zigbee2MQTT connection.

## Native candidate measured on 15 October 2026

[Pinned TI native build 38789101355](https://github.com/analienx/Zigbee-Coordinator/actions/runs/38789101355)
passes at source commit `671b3d2d92a64f3fde2b8b06eeac522daadf8450`.
The normal R2 app reproduced its installed source SHA exactly before the
temporary overlay was applied. Both variants pass the linked capacity, G6/G7,
F07/persistence, NV reservation, CCFG and ELF/HEX audits.

- Diagnostic application: 189,628 initialized bytes, end `0x2E4BC`; 1,328 bytes
  above normal R2. It requires 24 sectors ending `0x30000`, leaving 6,980 bytes
  inside that envelope. No initialized NV bytes are present.
- Diagnostic app HEX SHA-256:
  `058ec30b34e0f238f89fd0ef28e612a10dba62316d3c3026c0b8f6cfbfea8574`.
- Linked C/interrupt stack: 4096 bytes at `0x20023000..0x20023FFF`.
  Linked SRAM increases by 3084 bytes, chiefly the additional 3072-byte stack.
- `main` retains a 32-byte frame in both builds. All 44 named NV-driver function
  frame sizes match. `NVOCMP_initNvApi` retains 144 bytes. NV-driver source hash
  matches the normal R2 evidence exactly; it was not instrumented or changed.
- The measurement result helper uses 24 bytes and its watermark sampler 16;
  the paint helper has a zero-byte frame. UART logging follows NV measurement.
  These observations support interpreting the measurement, but do not close
  the unresolved indirect/combined nodes in the static call graph.

The separate diagnostic writer and paired original-stock cleanup pass the
[three operator CI jobs](https://github.com/analienx/Zigbee-Coordinator/actions/runs/38790060409)
at operator commit `97302e6838c0b5be033e2c913177f08293da2197`. The default
23-sector ROM/writer/package path is unchanged. The temporary profile admits
exactly 24 sectors, rejects `0x30000` and all NV/CCFG writes, binds NV CRCs into
its plan and verifies them after programming. Full simulated diagnostic write
and paired cleanup preserve all bytes beyond `0x30000`; both pinned vendor
sources have FF cleanup through both tail sectors. Native artifacts and paired
images were rederived and rehashed offline in a private 51-file operator packet.

This candidate has not been written to the P7U. Fresh installed inspection,
boot-stage/NV return/stack readout and normal ZNP qualification remain pending.
Neither the NV-failure hypothesis nor original-stack exhaustion is confirmed.
