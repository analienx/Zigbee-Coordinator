# T832-MIN v4 — M0–M2 independent review and corrected offline build
Date: 2026-10-10. Authority: https://github.com/analienx/Zigbee-Coordinator/issues/48
PR: https://github.com/analienx/Zigbee-Coordinator/pull/49 (**draft, unmerged**)
Disposition: **LINKED_OFFLINE_UNQUALIFIED**; `flash_authorized=false`.

## Review findings and corrections

1. **P0 SYS_VERSION length:** Original compiled firmware changed TI product=0 to ZStack3x0 product=1 but retained 5 bytes. The pinned Herdsman v10.9.1 SYS/version definition specifies 5 UINT8 fields followed by UINT32 LE revision. It therefore requires **9 bytes**. `build_min_real.py` now emits firmware revision `20261010` in four LE bytes. `harden_real.py source` verifies the actual modified TI source against Herdsman commit `0968f979d558874b17396c96b66382d4236bbdcd`.
2. **P0 CC26x4 CCFG flash layout:** The original model carved CCFG from main flash NVS tail. The pinned TI linker actually defines FLASH 0–0xFD800, FLASH_NV 0xFD800–0x100000, and physically separate CCFG 0x50000000–0x50000800. `harden_real.py linked` parses actual linker map, forbids **all** main-flash NVS image writes, requires CCFG at 0x50000000, validates Intel HEX checksum, duplicate addresses, EOF and nonflash spans. The planning models and regression fixtures were corrected.
3. **P1 page size/toolchain:** `nv_lab.py` erroneously used 0x1000-byte pages for 5 pages occupying 0x2800 bytes. Correct = 5×0x800. `upstream.lock.json` and static checks now match the actual successful CCS XDCTools **3.62.01.16**, not aspirational 3.62.01.15.
4. **P1 deceptive proof classes:** The historical `patch_min.py`, `host_contract.cjs`, `nv_lab.py`, `verify_compiler.py` remain static models/tests, **not** TI linked firmware or true NVOCMP/SYS/AF driver tests. Actual pinned TI source, Herdsman ABI and linker/HEX are validated in the separate real-build workflow.
5. **Focused regression only:** six bounded hosted cases: valid separated CCFG/main flash; invalid NVS write, checksum, missing CCFG, duplicated bytes and fake map row. No broad CI/instrumentation matrix or new firmware variant.

## Real hosted evidence, two exact commits

**Real CCS linked image at build SHA `98c1d8f9de665bf3bf1f9bddf1f4bc4334f512d8`:**
https://github.com/analienx/Zigbee-Coordinator/actions/runs/38020449131

**Download offline-only artifact:**
https://github.com/analienx/Zigbee-Coordinator/actions/runs/38020449131/artifacts/11657782443

- Pinned SDK 8.32.00.07 git SHA `6499c3f53fc5fb5806213be695450a7b43fbaf3d`; example SHA `87ff5b638b632050228a7504f35cf3b95581c278`.
- TI Clang 3.2.2, CCS 12.8.0.00012, SysConfig 1.21.1.3772, XDCTools 3.62.01.16.
- TI ZNP compilation/link: **SUCCESS, 0 project errors.**
- Actual compiled linked FLASH 0x0–0xFD800; FLASH_NV 0xFD800–0x100000 (10,240 bytes); SRAM 262,144 bytes with 218,356 unused; CCFG 0x50000000–0x50000800 (124 bytes used).
- Intel HEX contains 188,968 populated bytes across main flash and separate CCFG, with none in main-flash NV. Output `linked-geometry.json`: `PASS_REAL_LINK_GEOMETRY`.
- Corrected `T832-MIN.hex`: **531,620 bytes**, SHA-256 `0ad37902d12c4f5153d8de1942edca44b0fc7cccda0c46be5b88fc7ffea37fee`.
- Corrected `T832-MIN.out`: **2,547,312 bytes**, SHA-256 `8685cfe5fcc0c041b674f7d4b85810c4425ce9c77ec13670a2c0638db1b9fc01`.
- Follow-up source/static/negative tests green at `19ac0b2385f2f9c4eda919ce6de430e4d9640d75`: https://github.com/analienx/Zigbee-Coordinator/actions/runs/38020453718; the only difference from linked build SHA is a focused test fixture, not linked candidate source.
- **All earlier HEX artifacts including `4deb8f8` / SHA256 `ae624...` are superseded, not compatible/hardware-qualified.**

## Explicitly NOT tested/qualified

No production Zigbee, HA, Z2M, MQTT, radio interface, ROM BSL, flash operation or secret material accessed. RF pins, oscillator, PA, CCFG backdoor values, physical UART, actual host handshake, groupcast, join/rejoin, real NVOCMP driver index0/persistence, 103 keys and 192 slot capacity, backup/restore identity and counters, and router-heavy live behavior remain **UNTESTED**. No independent post-hardening 3-reviewer+challenger PASS is claimed (original Muse's old review aggregate was not PASS).

The practical next decision remains one separately authorized **spare P10 / disposable-network M3 smoke** (with hardware-specific firmware settings and rollback validated first), then M4 103/192-key and backup/restore on disposable data. **Never flash the corrected HEX on the recovered household P10.**
