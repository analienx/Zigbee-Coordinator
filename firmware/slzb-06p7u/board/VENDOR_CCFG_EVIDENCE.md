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

Hosted acquisition at9bd1963 recorded both hashes and actual lengths273894 and
172356bytes. Both start with SLZB container markers, not ARM vectors. Offline
interpretation uses an observed big-endian address/size/CRC32 descriptor table
followed by the segment payloads; an initial interleaved-record hypothesis
failed real CRCs and was discarded. Legacy table count requires a unique full
length resolution; the observed0103 form requires exactly three descriptors. It requires
every CRC and byte extent, rejects overlap/out-of-range/trailing/truncated data,
and preserves the newer opaque01/03 prefix without guessing its semantics.
This inferred container structure is not an authoritative console parser or
erase-policy proof. IEEE words are redacted. Record CRC32 follows the public
[SMLIGHT CC flasher CRC primitive](https://github.com/smlight-tech/smlight-cc-flasher/blob/9a1d33571c1cdaedc9dfcdcf2df5b5a5fece0b1c/smlight_cc_flasher/firmware.py).

This research produces OFFLINE_COMPARISON_COMPLETE_NOT_FLASHABLE, including
differences rather than suppressing them. It cannot enable the board's disabled
image gate. Observed vendor hashes are frozen in vendor-images.json; installed
content is still unknown. ERASE_CONF chip permission refers to the JTAG WUC
request/reset path; the separate bank permission concerns ROM serial bank erase.

The current user-reported20240710 image was added with its exact catalog URL
and frozen observed digest. Its CRC-validated CCFG differs from accepted G6
only in MODE_CONF DC/DC-active and recharge settings: vendor disables both,
while the TI reference enables them. BL_CONFIG agrees (ROM BSL enabled,
backdoorDIO15 active-low). These are image facts, not original-unit readback.
The newer image must resolve its ROM vector via IMAGE_VALID_CONF, whose
[pinned TI register definition](https://github.com/TexasInstruments/simplelink-lowpower-f2-sdk/blob/6499c3f53fc5fb5806213be695450a7b43fbaf3d/source/ti/devices/cc13x2x7_cc26x2x7/inc/hw_ccfg.h)
explicitly specifies the vector-table start address. A loader outside the
ordinary TI app range is reported as encoded NV-range overlap; it cannot be
silently imported into our NV2/NV5 layout. R1 uses stock/NV2 as its first target.
