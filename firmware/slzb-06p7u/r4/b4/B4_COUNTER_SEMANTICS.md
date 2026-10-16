# B4 counter semantics / proof boundary

Status: **not native-linked**. `B4_SOURCE_HOOK_MATRIX.json` is a source-to-function research crosswalk, not a claim that any counter increments at runtime.

A metric may transition `NOT_MEASURED -> SOURCE_PATH_IDENTIFIED -> HOSTED_NATIVE_LINKED` only when a real event producer, caller context (ISR/callback/task), increment, type, storage, validity and output serialization are each verified at the pinned source and in the actual linked ELF. Only then may CI qualify width, saturation/wrap, concurrency, stack overhead and performance under loaded SRSP/AREQ traffic. In particular, a function name match is not a counter hook.

* **Units and chronology:** UART bytes != NPI frames != MT requests != AF local SRSP != `AF_DATA_CONFIRM` != ZCL response != RF delivery. `UART2_write` acceptance != `NPITLUART_writeCallBack` completion != host USB receipt. The callback at `npi_tl_uart.c:255` has a `status` argument; classification of successful TX_FINISHED requires linked semantic proof.
* **Absent hook:** validity bit **0**, not a zero-valued counter, and never an all-ones sentinel. Unavailable B2 route/NWK or B3 nonsecret NV error remains UNKNOWN.
* **Unsigned 32-bit:** zero and `0xffffffff` are valid values when validity=1. Wrap-aware subtraction is disallowed by default. It requires source-qualified matching radio epoch, coherent monotonic uptime/sequence, same counter validity, documented width and positive non-ambiguous sample interval. Host-process epoch alone is insufficient.
* **Reset:** radio boot entropy/reset-cause provider is NOT_MEASURED. v3 on-wire capability is not an attestation. No radio epoch identity generation is implemented here.
* **HOLD:** B1 `HOLD_NV/HOLD_SECURITY` read-only status is an optional capability only where NPI is reachable; no key/NV reads, formation, RF or security-gate bypass.
* **Concurrency:** NPI task and UART callback producers have separate scheduling. No `volatile`-only multiword snapshot may be promoted to stable evidence. Use tiny bounded critical sections around read/copy, not MT send/formatting under critical section; no synchronous IO from callbacks.
* **Probe effect:** B4 must not alter SRSP retry, queue priority, radio control, NPI transport scheduling or OTA pacing. Read-only must be tested against unchanged stock ping/version/AF/ZDO control.
* **Saturation and provenance:** explicit per-counter validity plus wrap/saturation policy must come from actual native code. Placeholder data is never serialized into F0 to manufacture coverage.

**Native gate:** verify compiled TI 8.33 source, two genuine CCS 12.8 + ARM Clang 3.2.2 links at identical head, ELF/XML/HEX/BIN hashes, map symbols and SRAM/heap/stack delta, protected NV `0xAA000..0xADFFF`, CCFG geometry and known UART0 DIO12/DIO13 at 115200 without RTS/CTS. Do not treat offline Python or C fixture success as linked firmware evidence.
