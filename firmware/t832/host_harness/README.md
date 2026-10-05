# T832-DIAG-R0 host harness

Compiles the REAL `../t832_diag_impl.inc` on the host with stubbed SDK
symbols (`t832_host_sdk.h`, `stubs/ti/drivers/dpl/ClockP.h`; macro values
verified against pinned SDK 8.32.00.07 `mt_rpc.h`/`mt.h`) and exercises
recorder behavior end to end: sizes, boot/capabilities, sync gate, flooding
with critical protection and coalescing, diag-traffic exclusion, MT task
event bits, AF outstanding/confirm correlation, NV begin/end/failure/
reformat/init, frame budget, and critical-section balance.

Allocation inside the recorder is forbidden at link time via
`--wrap=malloc,calloc,realloc,free`.

Run exactly as CI does (from the repository root):

```sh
gcc -std=c11 -Wall -Wextra \
  -I firmware/t832 \
  -I firmware/t832/host_harness \
  -I firmware/t832/host_harness/stubs \
  firmware/t832/host_harness/t832_diag_host_test.c \
  -o /tmp/t832harness \
  -Wl,--wrap=malloc -Wl,--wrap=calloc \
  -Wl,--wrap=realloc -Wl,--wrap=free \
&& /tmp/t832harness
```

Expected output ends with `HARNESS RESULT: PASS`.
