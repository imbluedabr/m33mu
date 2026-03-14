/* m33mu -- LPC55S69 SDK MRT test
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Exercises fsl_mrt.c against the emulated MRT0 peripheral.
 * Uses one-shot mode (not repeat) to avoid infinite interrupt loops:
 * sets a 1ms timer, polls the interrupt flag, checks it fires.
 */
#include <stdio.h>
#include "fsl_mrt.h"

/* MRT clock = core clock = 96 MHz */
#define MRT_CLK_HZ  96000000u

/* MRT0 base */
#define MRT0  ((MRT_Type *)0x4000D000u)

static volatile int mrt_fired = 0;

void MRT0_IRQHandler(void)
{
    MRT_ClearStatusFlags(MRT0, kMRT_Channel_0, kMRT_TimerInterruptFlag);
    mrt_fired = 1;
}

int main(void)
{
    mrt_config_t cfg;
    uint32_t ticks;
    uint32_t timeout;
    int pass = 1;

    printf("=== MRT test ===\n");

    MRT_GetDefaultConfig(&cfg);
    MRT_Init(MRT0, &cfg);

    /* Channel 0: one-shot mode, 1ms */
    MRT_SetupChannelMode(MRT0, kMRT_Channel_0, kMRT_OneShotMode);
    MRT_EnableInterrupts(MRT0, kMRT_Channel_0, kMRT_TimerInterruptEnable);

    /* Enable MRT IRQ at NVIC */
    __asm volatile("cpsie i");
    /* NVIC ISER0 — MRT is IRQ 10, bit 10 of ISER[0] */
    *((volatile uint32_t *)0xE000E100u) = (1u << 10);

    ticks = USEC_TO_COUNT(1000u, MRT_CLK_HZ);  /* 1ms */
    printf("Starting 1ms timer (ticks=%lu)...\n", (unsigned long)ticks);
    MRT_StartTimer(MRT0, kMRT_Channel_0, ticks);

    /* Wait for interrupt (with timeout) */
    timeout = 10000000u;
    while (!mrt_fired && --timeout > 0u) { }

    if (mrt_fired) {
        printf("MRT fired: PASS\n");
    } else {
        printf("MRT timeout: FAIL\n");
        pass = 0;
    }

    /* Check INTFLAG clears correctly */
    {
        uint32_t stat = MRT_GetStatusFlags(MRT0, kMRT_Channel_0);
        printf("INTFLAG after clear: 0x%lx  exp 0  %s\n",
               (unsigned long)(stat & kMRT_TimerInterruptFlag),
               (stat & kMRT_TimerInterruptFlag) == 0u ? "PASS" : "FAIL");
        if ((stat & kMRT_TimerInterruptFlag) != 0u) pass = 0;
    }

    printf("=== %s ===\n", pass ? "ALL PASS" : "SOME FAIL");
    return pass ? 0 : 1;
}
