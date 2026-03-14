/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Minimal board support for SDK tests running under the m33mu emulator.
 * Provides:
 *   - Reset_Handler (data/bss init + main)
 *   - FLEXCOMM0 USART init for printf output
 *   - Stubs for SDK board/clock/power functions
 */
#include <stdint.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * Memory layout symbols from linker script
 * ------------------------------------------------------------------------- */
extern uint32_t _sidata, _sdata, _edata, _sbss, _ebss, _estack;
extern void __libc_init_array(void);
extern int main(void);
extern void _exit(int status);

/* -------------------------------------------------------------------------
 * SYSCON — clock and reset control
 * ------------------------------------------------------------------------- */
#define SYSCON_BASE         0x40000000u
#define AHBCLKCTRL0   (*(volatile uint32_t *)(SYSCON_BASE + 0x200u))
#define AHBCLKCTRL1   (*(volatile uint32_t *)(SYSCON_BASE + 0x204u))
#define PRESETCTRL0   (*(volatile uint32_t *)(SYSCON_BASE + 0x100u))
#define PRESETCTRL1   (*(volatile uint32_t *)(SYSCON_BASE + 0x104u))
#define MAINCLKSELA   (*(volatile uint32_t *)(SYSCON_BASE + 0x280u))
#define MAINCLKSELB   (*(volatile uint32_t *)(SYSCON_BASE + 0x284u))
#define AHBCLKDIV     (*(volatile uint32_t *)(SYSCON_BASE + 0x380u))
/* FROCTRL — enable 96MHz FRO */
#define ANACTRL_BASE        0x40013000u
#define FROCTRL       (*(volatile uint32_t *)(ANACTRL_BASE + 0x010u))

static void syscon_clock_enable1(uint32_t bit)
{
    AHBCLKCTRL1 |= (1u << bit);
    PRESETCTRL1 |= (1u << bit);
}

/* -------------------------------------------------------------------------
 * FLEXCOMM0 USART — base 0x40086000
 * ------------------------------------------------------------------------- */
#define FC0_BASE            0x40086000u
#define FC0_PSELID    (*(volatile uint32_t *)(FC0_BASE + 0xFF8u))
#define FC0_CFG       (*(volatile uint32_t *)(FC0_BASE + 0x000u))
#define FC0_FIFOCFG   (*(volatile uint32_t *)(FC0_BASE + 0xE00u))
#define FC0_FIFOSTAT  (*(volatile uint32_t *)(FC0_BASE + 0xE04u))
#define FC0_FIFOWR    (*(volatile uint32_t *)(FC0_BASE + 0xE20u))

void fc0_putc(char c)
{
    while ((FC0_FIFOSTAT & (1u << 5)) == 0u) { }
    FC0_FIFOWR = (uint32_t)(unsigned char)c;
}

static void fc0_usart_init(void)
{
    syscon_clock_enable1(0u);    /* MRT0 clock + reset release */
    syscon_clock_enable1(11u);   /* FC0 clock + reset release */
    FC0_PSELID = (FC0_PSELID & ~0x7u) | 1u;  /* USART */
    FC0_CFG    = (1u << 0) | (1u << 2);       /* ENABLE | DATALEN=8 */
    FC0_FIFOCFG = (1u << 0) | (1u << 1);      /* ENABLETX | ENABLERX */
}

/* -------------------------------------------------------------------------
 * Reset handler
 * ------------------------------------------------------------------------- */
__attribute__((naked)) void Reset_Handler(void)
{
    __asm volatile(
        "ldr  r0, =_estack\n"
        "mov  sp, r0\n"
        "b    reset_handler_c\n"
    );
}

void reset_handler_c(void)
{
    uint32_t *src, *dst;

    /* Copy .data from flash to RAM */
    src = &_sidata;
    dst = &_sdata;
    while (dst < &_edata) { *dst++ = *src++; }

    /* Zero .bss */
    dst = &_sbss;
    while (dst < &_ebss) { *dst++ = 0u; }

    fc0_usart_init();
    __libc_init_array();
    _exit(main());
}

/* -------------------------------------------------------------------------
 * SDK stubs — only needed when FSL_SDK_DISABLE_DRIVER_CLOCK_CONTROL is off
 * or when other SDK code calls these.  Provide minimal implementations.
 * ------------------------------------------------------------------------- */

/* CLOCK_GetCoreSysClkFreq: return 96 MHz (FRO_HF) */
uint32_t CLOCK_GetCoreSysClkFreq(void) { return 96000000u; }
uint32_t CLOCK_GetFreq(uint32_t clk) { (void)clk; return 96000000u; }
uint32_t SystemCoreClock = 96000000u;

/* CLOCK_EnableClock / CLOCK_DisableClock: manipulate AHBCLKCTRL bits.
 * The kCLOCK_* enum values map directly to (reg_idx<<5)|bit in the SDK.
 * For our purposes just accept the call without crashing. */
void CLOCK_EnableClock(uint32_t clk)  { (void)clk; }
void CLOCK_DisableClock(uint32_t clk) { (void)clk; }
void CLOCK_AttachClk(uint32_t src)    { (void)src; }
void CLOCK_SetClkDiv(uint32_t div, uint32_t val) { (void)div; (void)val; }

/* POWER stubs */
void POWER_SetBodVbatLevel(uint32_t a, uint32_t b, uint32_t c) { (void)a;(void)b;(void)c; }
void EnableDeepSleepIRQ(uint32_t irq)  { (void)irq; }
void DisableDeepSleepIRQ(uint32_t irq) { (void)irq; }

/* RESET stubs */
void RESET_PeripheralReset(uint32_t r) { (void)r; }
void RESET_ClearPeripheralReset(uint32_t r) { (void)r; }
