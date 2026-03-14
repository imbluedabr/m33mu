/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Minimal board support for PIC32CK tests running under the m33mu emulator.
 * Provides:
 *   - Reset_Handler (data/bss init + main)
 *   - SERCOM0 USART init for printf output
 */
#include <stdint.h>
#include <string.h>

extern uint32_t _sidata, _sdata, _edata, _sbss, _ebss, _estack;
extern void __libc_init_array(void);
extern int main(void);
extern void _exit(int status);

/* -------------------------------------------------------------------------
 * MCLK -- clock enable for APB peripherals
 * CLKMSK registers at MCLK_BASE + 0x3C + n*4
 * SERCOM0 is in CLKMSK2, bit 9
 * ------------------------------------------------------------------------- */
#define MCLK_BASE        0x44012000u
#define MCLK_CLKMSK2     (*(volatile uint32_t *)(MCLK_BASE + 0x44u))

/* -------------------------------------------------------------------------
 * SERCOM0 USART -- base 0x44810000
 * CTRLA  [0x00]: MODE [4:2] = 1 for USART internal clock, ENABLE = bit 1
 * INTFLAG[0x18]: DRE=bit0 (TX ready), TXC=bit1
 * DATA   [0x28]: TX/RX data register
 * ------------------------------------------------------------------------- */
#define SC0_BASE         0x44810000u
#define SC0_CTRLA        (*(volatile uint32_t *)(SC0_BASE + 0x00u))
#define SC0_INTFLAG      (*(volatile uint16_t *)(SC0_BASE + 0x18u))
#define SC0_DATA         (*(volatile uint32_t *)(SC0_BASE + 0x28u))

#define CTRLA_MODE_USART (1u << 2)   /* MODE=001 */
#define CTRLA_ENABLE     (1u << 1)
#define INTFLAG_DRE      (1u << 0)

void sercom0_putc(char c)
{
    while ((SC0_INTFLAG & INTFLAG_DRE) == 0u) { }
    SC0_DATA = (uint32_t)(unsigned char)c;
}

static void sercom0_usart_init(void)
{
    /* Enable SERCOM0 clock in MCLK */
    MCLK_CLKMSK2 |= (1u << 9u);
    /* Configure SERCOM0 as USART and enable */
    SC0_CTRLA = CTRLA_MODE_USART | CTRLA_ENABLE;
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

    src = &_sidata;
    dst = &_sdata;
    while (dst < &_edata) { *dst++ = *src++; }

    dst = &_sbss;
    while (dst < &_ebss) { *dst++ = 0u; }

    sercom0_usart_init();
    __libc_init_array();
    _exit(main());
}
