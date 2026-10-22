/* Owner-controlled engineering handoff, CC2652P7 Cortex-M4F only.
 * Replaces one 8-KiB resident stage; does NOT implement MCUboot authentication.
 * It runs only as a ROM-selected reset entry, never as a callable function.
 * All constants come from the frozen, independently audited native APP.
 */
    .syntax unified
    .cpu cortex-m4
    .thumb

    .section .r4_vectors,"a",%progbits
    .balign 256
    .global R4_Vectors
R4_Vectors:
    .word EXPECTED_APP_SP
    .word R4_Reset
    /* TI's pinned x2x7 hw_ints.h has NUM_INTERRUPTS=54 (includes core). */
    .rept 52
    .word R4_Hold
    .endr

    .section .r4_handoff,"ax",%progbits
    .balign 4
    .global R4_Reset
    .type R4_Reset,%function
    .thumb_func
R4_Reset:
    cpsid i
    /* Provide real NMI/HardFault entries throughout the stage itself. */
    ldr r0, =0xE000ED08
    ldr r1, =0x000AC000
    str r1, [r0]
    dsb sy
    isb sy
    mrs r0, ipsr
    cmp r0, #0
    bne R4_Hold
    movs r0, #0
    ldr r2, [r0]
    ldr r1, =EXPECTED_APP_SP
    cmp r2, r1
    bne R4_Hold
    ldr r3, [r0, #4]
    ldr r1, =EXPECTED_APP_RESET
    cmp r3, r1
    bne R4_Hold

    /* Disable SysTick and discard its old reload/current count. */
    ldr r0, =0xE000E010
    movs r1, #0
    str r1, [r0]
    str r1, [r0, #4]
    str r1, [r0, #8]
    /* CC2652P7 has 38 external IRQs: exactly two NVIC register words. */
    ldr r0, =0xE000E180
    movs r1, #0
    mvns r1, r1
    str r1, [r0]
    str r1, [r0, #4]
    ldr r0, =0xE000E280
    str r1, [r0]
    str r1, [r0, #4]
    ldr r0, =0xE000ED04
    ldr r1, =0x0A000000 /* PENDSTCLR | PENDSVCLR */
    str r1, [r0]
    dsb sy
    isb sy

    /* Restore reset-like privileged thread/MSP and mask state. TI Hwi_enable
     * uses BASEPRI; leaving PRIMASK set would suppress its interrupts forever.
     * No C prologue/epilogue and no stack access occurs in this program.
     */
    movs r0, #0
    msr control, r0
    isb sy
    msr psp, r0
    msr basepri, r0
    msr faultmask, r0
    msr msp, r2
    ldr r1, =0xE000ED08
    str r0, [r1]
    dsb sy
    isb sy
    cpsie i
    bx r3 /* genuine native ResetISR, including TI trim and C runtime */
    .size R4_Reset, .-R4_Reset

    .balign 2
    .global R4_Hold
    .type R4_Hold,%function
    .thumb_func
R4_Hold:
    cpsid i
1:  b 1b
    .size R4_Hold, .-R4_Hold
    .ltorg
