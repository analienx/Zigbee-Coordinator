# B3-00 — exact linker geometry, experimental page candidates

Pinned source: TI 8.33 `cc13x2x7_cc26x2x7_tirtos7_ticlang.cmd`, SHA donor `3615ad5d3f4f271258d18a2f5ce1785064ff9a58`. 8,192 bytes/page; each page has a 4-byte page header, 3 × 4-byte compaction headers, leaving **8,176 payload+item-header bytes per page**. Individual live record consumes `payload_bytes + 7`; duplicates and obsolete records consume space until compaction. Target alignment assumption is source-derived; native compiled size/bitfield proof still pending.

| Geometry | FLASH app [start, exclusive end) | FLASH_NV | FLASH_LAST / protected CCFG | Raw NV | Stable nominal ACTIVE capacity excluding swap (before item headers) |
|---|---|---|---|---:|---:|
| NV2 / B0 actual | 0x00000..0xAA000 | 0xAA000..0xAE000 | 0xAE000..0xB0000 | 16,384 | 8,176 |
| NV3 / experimental | 0x00000..0xA8000 | 0xA8000..0xAE000 | 0xAE000..0xB0000 | 24,576 | 16,352 |
| NV5 / experimental | 0x00000..0xA4000 | 0xA4000..0xAE000 | 0xAE000..0xB0000 | 40,960 | 32,704 |

All `0xB0000` addresses are exclusive. These are **upper bounds**, not available safe state bytes under compaction. Effective safe capacity requires exact serialized item mix, append/update dynamics, redundant page state and copy reserve from fault modeling; no capacity recommendation can be finalized yet.

Relative to B0, NV3 removes **8,192** app bytes and NV5 removes **24,576**. Both reclassify sectors that could hold program content or different old NV formats. A linker boundary edit without isolated sector writer, occupied-sector read-only proof, vendor-CCFG equality and stock rollback is expressly **NOT FLASH SAFE**. In particular, historical R2 NV5 `0xA4000` allocation does not establish that currently installed vendor 20260310/11 is NV5. **Unknown format -> HOLD_NV / no migration / no erase.**

See `B3_ITEM_CAPACITY.json` for exact page/header inputs and unresolved row types; no device-quantity acceptance is implied by the nominal bound.
