# Offline vendor image/CCFG work — no firmware approval

The exact P7U catalog request uses device17, per the pinned pysmlight model map.
Select only coordinator type0/115200 with exact version and URL. It provides
the named P7U SDK832 beta20260311 and historical20240316 public image. Neither
is proven to match installed content. The acquisition workflow checks catalog
binding before download, hashes the files, and publishes only derived evidence.
It does not redistribute vendor binaries or execute a flasher.

Flat BIN interpretation requires explicit base0, P7 flash bounds and plausible
SRAM/Thumb vectors. A short vendor update may omit CCFG; missing/partial CCFG
is UNKNOWN, never padded or treated as a match. The22 CCFG registers and bitfields come from
the exact pinned TI P7 header. Comparison against accepted b308eb1 native stock
BASE/G6 independently rechecks ELF/HEX equality. IEEE words are redacted, while
full CCFG equality uses the88-byte digest. No private board NV is read.

A full BIN contains all NV and final-sector addresses even when they hold FF.
FF bytes do not imply that a management flasher will preserve those sectors.
Erase behavior remains UNKNOWN. Preserving vendor BL_CONFIG fields alone is
also not proof that the fitted board can enter ROM BSL or roll back through
this SLZB-OS console. Physical revision, UART DIO, RF/clocks and console recovery
remain separate requirements. Binary provenance does not identify silicon by
itself; the P7 family selection is bound to the manufacturer catalog.

This research produces OFFLINE_COMPARISON_COMPLETE_NOT_FLASHABLE, including
differences rather than suppressing them. It cannot enable the board's disabled
image gate. Initial vendor hashes are discovery observations; once acquisition
succeeds they must be frozen in vendor-images.json before repeatable acceptance.
