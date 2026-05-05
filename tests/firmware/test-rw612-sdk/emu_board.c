/* m33mu -- RW612 emulator-side board bring-up.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Direct-MMIO bring-up of FlexComm0 USART for printf().  Uses the SET/CLR
 * register aliases of CLKCTL0 / RSTCTL0 — same pattern the NXP MCUXpresso
 * SDK uses on real silicon, exercising the emulator's set/clear logic.
 */
#include <stdint.h>
#include <string.h>

extern uint32_t _sidata, _sdata, _edata, _sbss, _ebss, _estack;
extern void __libc_init_array(void);
extern int main(void);
extern void _exit(int status);

/* CLKCTL0 / RSTCTL0 — domain 0 */
#define RSTCTL0_BASE     0x40000000u
#define CLKCTL0_BASE     0x40001000u
#define PSCCTL1_OFF      0x14u
#define PSCCTL1_SET      0x44u   /* base + 0x40 */
#define PSCCTL1_CLR      0x74u   /* base + 0x70 */
#define FC0_CLK_BIT      8u

#define CLKCTL0_PSCCTL1_SET (*(volatile uint32_t *)(CLKCTL0_BASE + PSCCTL1_SET))
#define RSTCTL0_PRSTCTL1_CLR (*(volatile uint32_t *)(RSTCTL0_BASE + PSCCTL1_CLR))

/* FlexComm0 USART — 0x40106000 */
#define FC0_BASE         0x40106000u
#define FC0_PSELID       (*(volatile uint32_t *)(FC0_BASE + 0xFF8u))
#define FC0_CFG          (*(volatile uint32_t *)(FC0_BASE + 0x000u))
#define FC0_FIFOCFG      (*(volatile uint32_t *)(FC0_BASE + 0xE00u))
#define FC0_FIFOSTAT     (*(volatile uint32_t *)(FC0_BASE + 0xE04u))
#define FC0_FIFOWR       (*(volatile uint32_t *)(FC0_BASE + 0xE20u))

#define FIFOSTAT_TXNOTFULL (1u << 5)

void fc0_putc(char c)
{
    while ((FC0_FIFOSTAT & FIFOSTAT_TXNOTFULL) == 0u) { }
    FC0_FIFOWR = (uint32_t)(unsigned char)c;
}

static void fc0_init(void)
{
    /* Enable FC0 clock and release reset */
    CLKCTL0_PSCCTL1_SET   = (1u << FC0_CLK_BIT);
    RSTCTL0_PRSTCTL1_CLR  = (1u << FC0_CLK_BIT);

    /* Select USART, enable, 8N1 */
    FC0_PSELID  = (FC0_PSELID & ~0x7u) | 1u;       /* USART */
    FC0_CFG     = (1u << 0) | (1u << 2);            /* ENABLE | DATALEN=8 */
    FC0_FIFOCFG = (1u << 0) | (1u << 1);            /* TX | RX enable */
}

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

    src = &_sidata;
    dst = &_sdata;
    while (dst < &_edata) { *dst++ = *src++; }

    dst = &_sbss;
    while (dst < &_ebss) { *dst++ = 0u; }

    fc0_init();
    __libc_init_array();
    _exit(main());
}
