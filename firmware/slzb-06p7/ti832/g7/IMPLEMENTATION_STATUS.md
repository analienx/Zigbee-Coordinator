# G7 source implementation - native acceptance pending, NOT FLASHABLE

G6 PR64 is accepted and merged into the P7 feature, source b308eb1 and feature
merge 2ddcb4d. Separate P7U profile and vendor evidence PR65/66 are accepted.
They do not establish fitted-board UART/RF/clock or physical approval.

G7 now composes explicit UART/TL outcomes with actual task-level bounded
ownership, a static one-shot retry clock, validated MT SRSP/AREQ FIFO lanes,
4:1 submitted-attempt fairness and a bounded lost-callback fault. See README
for exact semantics, clock uncertainty and the guarded profile.

Hosted Actions runs38521321039 at731db37 and38521527551 at270161e passed actual
pinned Queue/frame/task/UART/TL composition and specific old-code negative
controls. Follow-up review adds no-repost and rejected-head expiry assertions
and a specific old-task busy-repost control. These require another hosted run.
The ownership negative uses old G6 task plus repaired lower transport to
isolate unconditional free; it is not a complete original firmware image.

The G7 native stock+CAP192 workflow is wired after G6. It retains unchanged
independent ELF/HEX/NV/CCFG audits, verifies surviving G5/G6 source hooks and
new G7 producer/service integration, and checks the actual linked UART2.c.obj
call path. Native acceptance is pending; do not mark F11/F12 fully accepted
until exact candidate checks and independent artifact review pass.

All repository tests/builds run on GitHub-hosted Actions. No local test/build,
serial-open, flash, reset, erase or production migration follows from these
source results. Original physical/network acceptance fields remain false.

The adopted P7U plan next requires F07/R10 non-destructive durable startup,
vendor-correct P7U native CCFG and board binding, then separate stock NV2 R1
and CAP192/NV5 R2 qualification. Exact P10 F13 v2 ABI and speculative retained
telemetry are deferred unless needed; they are not R1 completion prerequisites.
