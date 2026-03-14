/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include <stdint.h>

extern void Reset_Handler(void);
extern unsigned long _estack;

static void default_handler(void) { while (1) { } }

void NMI_Handler(void)        __attribute__((weak, alias("default_handler")));
void HardFault_Handler(void)  __attribute__((weak, alias("default_handler")));
void MemManage_Handler(void)  __attribute__((weak, alias("default_handler")));
void BusFault_Handler(void)   __attribute__((weak, alias("default_handler")));
void UsageFault_Handler(void) __attribute__((weak, alias("default_handler")));
void SVC_Handler(void)        __attribute__((weak, alias("default_handler")));
void DebugMon_Handler(void)   __attribute__((weak, alias("default_handler")));
void PendSV_Handler(void)     __attribute__((weak, alias("default_handler")));
void SysTick_Handler(void)    __attribute__((weak, alias("default_handler")));

/* PIC32CK SG: 16 core + 64 peripheral interrupts */
__attribute__((section(".isr_vector")))
const uint32_t vector_table[16 + 64] = {
    [0]  = (uint32_t)&_estack,
    [1]  = (uint32_t)&Reset_Handler,
    [2]  = (uint32_t)&NMI_Handler,
    [3]  = (uint32_t)&HardFault_Handler,
    [4]  = (uint32_t)&MemManage_Handler,
    [5]  = (uint32_t)&BusFault_Handler,
    [6]  = (uint32_t)&UsageFault_Handler,
    [11] = (uint32_t)&SVC_Handler,
    [12] = (uint32_t)&DebugMon_Handler,
    [14] = (uint32_t)&PendSV_Handler,
    [15] = (uint32_t)&SysTick_Handler,
};
