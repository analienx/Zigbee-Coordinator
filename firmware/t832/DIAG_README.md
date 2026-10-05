# T832-DIAG-R0 — diagnostic candidate, do not flash

This bundle contains the **diagnostic** CC2674P10 firmware, layered on
T832-KCTRL-R0. It includes bounded telemetry, blocked-export RAM snapshots,
generation-bound SREQ stages, UART2 callbacks/events, NWK/task sampling, and
an allocation-free fatal RAM latch. The matched control excludes these hooks.

`T832-BUILD-MANIFEST.json` binds the exact repository SHA, variant, image and
symbol hashes. SYS_VERSION revision 8320002 identifies this DIAG variant
(matched control 8320001); DEBUG carries the exact candidate short SHA and
capability bitmap. Revisions retain the same pinned Herdsman feature thresholds;
a random git SHA in SYS_VERSION would change its date-based feature selection.
Bind the deployed image through the collector's
manifest validation and preserve the actual image hash.

`flash_authorized` is **false**. Green hosted CI proves build and regression
integrity; it does not prove board wiring, real-time cost, reset retention, or
hardware behaviour. See `docs/T832_DIAG_R0_R5.md` in the repository for the
requirement matrix, sideband contract, pending bench gates and runbook.

Fatal evidence is RAM-only (`t832DiagFatal`, `t832R5`), read by SWD before reset.
It is not transmitted synchronously, retained through reset, or written to NV.
Heap largest-free and Hwi stack scans are absent pending timing measurements.

The KCTRL base changes TX completion timing, NV recovery policy and capacities;
a hang-free DIAG/control trial must not be called proof of a production fix.
