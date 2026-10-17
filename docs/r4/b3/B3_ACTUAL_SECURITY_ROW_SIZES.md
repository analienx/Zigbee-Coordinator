# B3-00: exact TI 8.33 APS/TCLK serialized row sizing, **conditional** occupancy

The pinned header `source/ti/zstack/stack/nwk/aps_mede.h` declares
`APSME_ApsLinkKeyNVEntry_t` with 16-byte key and two uint32 counters
and `APSME_TCLinkKeyNVEntry_t` with two uint32 counters, 8-byte IEEE
address and 4 one-byte attributes. The pinned `ssp.h` sets
`SEC_KEY_LEN=16` and `zcomdef.h` sets `Z_EXTADDR_LEN=8`.
The independent host C job **compiles the exact extracted TI typedefs**,
asserting APS=24 bytes and TCLK=20 bytes, on the pinned SDK commit
`3615ad5d3f4f271258d18a2f5ce1785064ff9a58`.
Native TICLANG layout/linked usage for every row remains a separate gate.

NVOCMP uses 7 on-flash bytes per compressed item header, so a unique
APS row is 31 bytes and a unique TCLK row is 27 bytes before obsolete
copies and application-level cross-item journal state.

| Hypothetical distinct peers in EACH table | APS bytes | TCLK bytes | Combined bytes | NV2 8,176-byte upper-bound remaining |
|---:|---:|---:|---:|---:|
| 106 | 3,286 | 2,862 | 6,148 | 2,028 |
| 128 | 3,968 | 3,456 | 7,424 | 752 |
| 160 | 4,960 | 4,320 | 9,280 | **−1,104 (impossible)** |
| 192 | 5,952 | 5,184 | 11,136 | **−2,960 (impossible)** |

This is a **conditional upper-population exercise**. Not every
device necessarily has *both* types of key row, and the actual B2
table limits may be lower than N. It would be false to claim this
proves 106-device capacity; at 106 both-full, nominal NV2 headroom
is only 2,028 bytes for **all** other state, compaction updates and
safe free reserve. At 160/192 both-full, NV2 is mathematically unable
to fit these two tables alone, regardless of rest of Zigbee state.

There is no automatic selection of NV3/NV5: B1 preflight must establish
format identity first; B2 must decide authentic table maxima and SRAM;
B3 must measure all other live items and compaction peak; native ELF
link/CCFG/rollback must be separately proven. The source donor NV2
remains unchanged and **NOT FLASH READY**.
