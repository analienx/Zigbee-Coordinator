# V5 successor: service an already-produced SRSP despite stack task contention

The physical V5 image `85ce37c24802b0f16fec0afd00a1a0457656cd80` booted the retained network and initially served fresh MQTT traffic. Its three genuine minor4 records then showed the maximum SRSP queue age rise to **35.54613 seconds** and the maximum ready-service gap to **35.55051 seconds**. The last valid sample had 9,588 asynchronous bytes queued, with no UART rejection, callback-error or B1 first-failure latch. AF SRSP timeouts later increased and both incoming UART bytes and successful replies stopped progressing. These are separate congestion and terminal-outage observations; they do not establish one shared cause.

The existing two-class transmit queue runs in NPI at TI priority4. The stack runs at5. Queue preference cannot make a runnable lower-priority NPI task execute while a higher-priority stack task remains runnable. The earlier virtual-UART fixture did not model a competing runnable stack task, so its latency result did not establish a bound under that condition.

## Candidate change

`r4_srsp_runtime_priority.py` applies after the frozen V5 composition. It retains NPI's initial priority4, which TI needs while the stack registers its MT service. An already-framed pending SRSP temporarily elevates the **existing NPI task** to6. The reserved and dynamic producers request this only after queue admission and ownership/critical-section cleanup. Before NPI pends, it restores4 when no SRSP remains or physical transport HOLD is active.

The priority predicate and update run under the Task scheduler lock, outside the OSAL critical section. This distinction matters: TI documents that a root `Task_restore()` may enable interrupts. No UART ISR, driver, physical completion handshake, NPI owner, class FIFO, four-SRSP AREQ fairness window, heap reservation, radio setting, NV, CCFG or security policy is changed. A busy UART continues to pend normally.

The pinned example configures only six priorities (0–5). The native build therefore changes the live SysConfig input `Task.numPriorities` from6 to8 before generation, retaining all existing task priorities. It does not edit generated kernel C. The native sealer must find the actual `ti_sysbios_knl_Task_numPriorities` u32 object in the linked ARM ELF, require exactly8, and bind the priority helper to live `npi_task.o` code. Unsupported configurations cannot qualify for delivery; runtime also avoids an out-of-range priority call. The original compile of this candidate exposed the six-level configuration and failed this gate before any flash.

The producer commits its admission counters before requesting a priority handoff. Since an elevation can immediately preempt MT, earlier placement could let NPI submit a frame before its enqueue bookkeeping was visible. A negative mutation explicitly checks that ordering.

## Required evidence

The new C fixture executes the final composed producer/queue/consumer bodies with an explicit competing-priority scheduler model. It covers reserved and dynamic SRSP admission, restoration to4, physical HOLD, delayed UART completion, FIFO/ownership and existing AREQ fairness. Broken priority, missing reserved/dynamic hooks and missing restoration must be rejected. V5 observer side effects are mocked here; its separate actual-source encoder/decoder harness remains mandatory. The model is not real TI-RTOS or physical timing proof.

GitHub exact-source composition, genuine dual native builds, reproducibility, the native priority-count/ownership seal, paired artifacts and same-device deployment gates remain required. No local public build/test or speculative live priority poke is part of this change.

Physical acceptance must show that the composed image keeps SRSP replies below the host's six-second deadline during the reproduced traffic load, that essential AREQs progress and queues drain, and that current-owner minor4 and V5 FLIGHT records actually persist. A container health status or a one-time MQTT burst is insufficient. The historical final silent hang remains open unless separately demonstrated fixed.
