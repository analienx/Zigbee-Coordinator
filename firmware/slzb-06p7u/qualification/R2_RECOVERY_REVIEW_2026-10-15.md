# R2 independent recovery review — 15 October 2026

R2 is not ready for household network restoration. The reported first write
verified all 23 application sectors and preserved CCFG, but subsequent raw
SYS_PING attempts received no bytes. ROM identity reads succeeded. This narrows
the investigation without establishing whether the application boots or whether
its current contents still match the write receipt.

## Independent offline checks

The reviewed source is PR #82 head
`bdc05f49dc5994a346a6d7f87a7cca1fa3b2157a`, native build
[38746343005](https://github.com/analienx/Zigbee-Coordinator/actions/runs/38746343005).
Its application-only HEX SHA-256 is
`16837972afeb3a502e03505e2998c5d2b2b8a1ce61ce91450f5999e175e908de`.

| Check | Independently observed result | Limit |
| --- | --- | --- |
| Retained original radio image | 720,896 bytes; all 88 sector shards match the image and sealed manifest | Original stock capture, not current flash |
| Retained ZIP | CRC check passes; every original capture file matches the retained directory byte for byte | Rechecks the retained local copy; no fresh HA comparison |
| Original firmware recovery material | Original application matches pinned manufacturer 20240316; gap up to NV5 is FF; app can be rederived exactly | Does not prove a physical rollback |
| Matched operator packet | All 31 recorded file sizes and SHA-256 hashes match | Does not authorize or execute a write |
| Actual linked UART | UART0, RX DIO12, TX DIO13, 32-byte RX/TX rings, hardware flow control disabled | Board electrical path and successful UART open remain unmeasured |
| Actual NPI initialization | Disassembly sets 115200, opens UART index 0 and immediately starts reads | Does not prove that execution reaches this function |
| Manufacturer comparison | Pinned 20240710 image has the same UART peripheral/pin/flow/ring settings | Does not establish equivalence of the whole board configuration |
| Actual linked NVS | Base `0xA4000`, length `0xA000` (five 8 KiB pages) | Runtime initialization/readback remains unmeasured |

The UART decoding follows the ARM EABI layout of `UART2_BASE_HWATTRS` in
[pinned TI UART2.h](https://github.com/TexasInstruments/simplelink-lowpower-f2-sdk/blob/6499c3f53fc5fb5806213be695450a7b43fbaf3d/source/ti/drivers/UART2.h)
and `UART2CC26X2_HWAttrs`. It also follows the linked `UART2_config` pointer,
rather than assuming an unrelated hardware-attribute object is selected.
There is no demonstrated UART pin/flow mismatch to fix. Do not change pins on
the strength of ROM BSL access alone.

The existing full fake-flash original-app-then-NV restoration regression was
rerun successfully for both pinned 20240316 and 20240710 sources. This covers
ordered restoration and protected-region preservation in the host model;
physical recovery remains open.

The existing whole TI NVOCMP regression was also rerun independently under local
Linux with AddressSanitizer/UndefinedBehaviorSanitizer: all 88 expected cases
passed, covering NV2/NV5 blank initialization, population, compaction/reopen and
the injected failure cases with pre-fix falsification. This exercises the real
driver with mock NVS/RTOS interfaces. It does not prove the fitted NVS driver,
startup task ordering or the live unit passes those paths.

## Next diagnostic decision

After the refused live diagnostic has an available supported execution/review
path, compare all 23 current application-sector CRCs against the exact candidate
and pinned original, verify vectors and unchanged CCFG/IEEE, with no writes.
Do not infer installed bytes from an offline image or repeat the R2 write merely
because ZNP is silent.

If current bytes match R2, examine startup before NPI (including NV initialization
and board power/clock setup), plus the bridge/serial path. If they differ,
preserve the discrepancy before deciding on a repair. More capacity tuning or
additional telemetry is not a prerequisite for this diagnosis.

For original-unit recovery, use the already implemented `restore-app` path with
the exact captured 20240316 source, two verified same-unit backup copies and a
fresh inspection plan. Restore the original NV5 region separately while still
in ROM BSL, after the original application has been verified, then restart and
require a valid stock SYS_PING/SYS_VERSION. The captured stock CCFG is preserved
throughout. See [P7U_TOOL.md](P7U_TOOL.md) and [NV5_RECOVERY.md](NV5_RECOVERY.md).
No new live plan or restore was executed in this review.

## Household restore is a separate operation

The retained stock radio image never contained the household network. It cannot
recover that network. PR #84's historical migration inventory still leaves
three current device identities without matching coordinator security records
(one router and two end devices), historical key conflicts and counter-floor
reconciliation. Qualify those records against a quiescent source; retain an
explicit controlled re-pair outcome where current key proof is unavailable.
Do not transplant an old key merely because its device address matches.

Require responsive P7U ZNP, verified network identity/counters, source-radio
isolation and both Zigbee2MQTT serial configuration layers before starting the
household network. Starting Zigbee2MQTT is not a substitute for diagnosing the
silent application. Issue #80 and both draft PRs remain open.
