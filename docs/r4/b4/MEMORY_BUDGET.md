# R4 B4 memory/performance proof — deliberately blocked

**Baseline native ELF memory budget:** NOT_MEASURED (awaiting successful B0 and B4 link artifacts). **Experimental B4 native stack delta:** NOT_MEASURED. Do not treat `sizeof(payload)==132` as a stack-budget proof; C compiler may spill or optimize, and RTOS stack headroom is unknown.

The source-only F0 handler allocates a fixed 132-byte array on the MT task stack. The only additional NPI state is one static volatile 32-bit counter; one static 32-bit sample sequence. It takes an existing tiny `OsalPort_enterCS` around two scalar values, then constructs and queues the reply outside the critical section. This is an architectural claim to test on genuine TI ARM ELF/map, not an observed timing guarantee. F0 increases SRSP traffic only when explicitly requested; on stock firmware, no poll.

**Required evidence:** compare pinned B0 ELF and B4 ELF maps/sections, executable size, .bss, task/IRQ stack analysis, TI linker XML, SRAM stack low-water, SysConfig pin proof, NV 0xAA000..0xADFFF exclusion and CCFG 88 bytes. Two independent B4 builds must match/produce provenance; no B4_SOURCE_READY without measured deltas and actual source-to-symbol call reachability. Real hardware/RTOS saturation and radio load remain PHYSICAL_UNVERIFIED. The draft must remain blocked if the toolchain is missing or sample-rate/probe overhead is unknown.
