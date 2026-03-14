/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Minimal board support for PIC32CK SDK tests running under the m33mu emulator.
 * Uses SDK-accurate clock/SERCOM init sequences.
 */
#include <stdint.h>
#include <string.h>

extern uint32_t _sidata, _sdata, _edata, _sbss, _ebss, _estack;
extern void __libc_init_array(void);
extern int main(void);
extern void _exit(int status);

/* -------------------------------------------------------------------------
 * MCLK -- clock enable for APB peripherals (0x44012000)
 * CLKMSK registers at MCLK_BASE + 0x3C + n*4
 * SERCOM0 is in CLKMSK2 (offset 0x44), bit 9
 * GCLK    is in CLKMSK0 (offset 0x3C), bit 2
 * ------------------------------------------------------------------------- */
#define MCLK_BASE        0x44012000u
#define MCLK_CLKMSK0     (*(volatile uint32_t *)(MCLK_BASE + 0x3Cu))
#define MCLK_CLKMSK1     (*(volatile uint32_t *)(MCLK_BASE + 0x40u))
#define MCLK_CLKMSK2     (*(volatile uint32_t *)(MCLK_BASE + 0x44u))

/* -------------------------------------------------------------------------
 * SUPC (0x44008000)
 * VREGCTRL at 0x1C: AVREGEN bit 10
 * STATUS   at 0x0C: ADDVREGRDY0 = bit 8
 * ------------------------------------------------------------------------- */
#define SUPC_BASE        0x44008000u
#define SUPC_STATUS      (*(volatile uint32_t *)(SUPC_BASE + 0x0Cu))
#define SUPC_VREGCTRL    (*(volatile uint32_t *)(SUPC_BASE + 0x1Cu))
#define SUPC_STATUS_ADDVREGRDY_MSK  (1u << 8)
#define SUPC_VREGCTRL_AVREGEN_MSK   (1u << 10)

/* -------------------------------------------------------------------------
 * OSCCTRL (0x4400C000)
 * STATUS      at 0x10: PLL0LOCK = bit 24
 * FRACDIV0    at 0x6C
 * SYNCBUSY    at 0x78: FRACDIV0 = bit 2
 * PLL0REFDIV  at 0x40
 * PLL0FBDIV   at 0x44
 * PLL0POSTDIVA at 0x48
 * PLL0CTRL    at 0x3C
 * ------------------------------------------------------------------------- */
#define OSCCTRL_BASE        0x4400C000u
#define OSCCTRL_PLL0CTRL    (*(volatile uint32_t *)(OSCCTRL_BASE + 0x3Cu))
#define OSCCTRL_PLL0REFDIV  (*(volatile uint32_t *)(OSCCTRL_BASE + 0x40u))
#define OSCCTRL_PLL0FBDIV   (*(volatile uint32_t *)(OSCCTRL_BASE + 0x44u))
#define OSCCTRL_PLL0POSTDIVA (*(volatile uint32_t *)(OSCCTRL_BASE + 0x48u))
#define OSCCTRL_FRACDIV0    (*(volatile uint32_t *)(OSCCTRL_BASE + 0x6Cu))
#define OSCCTRL_SYNCBUSY    (*(volatile uint32_t *)(OSCCTRL_BASE + 0x78u))
#define OSCCTRL_STATUS      (*(volatile uint32_t *)(OSCCTRL_BASE + 0x10u))
#define OSCCTRL_STATUS_PLL0LOCK_MSK (1u << 24)
#define OSCCTRL_SYNCBUSY_FRACDIV0_MSK (1u << 2)

/* -------------------------------------------------------------------------
 * GCLK (0x44010000)
 * SYNCBUSY at 0x04
 * GENCTRL[n] at 0x20 + n*4
 * PCHCTRL[n] at 0x80 + n*4
 * ------------------------------------------------------------------------- */
#define GCLK_BASE        0x44010000u
#define GCLK_SYNCBUSY    (*(volatile uint32_t *)(GCLK_BASE + 0x04u))
#define GCLK_GENCTRL(n)  (*(volatile uint32_t *)(GCLK_BASE + 0x20u + (n)*4u))
#define GCLK_PCHCTRL(n)  (*(volatile uint32_t *)(GCLK_BASE + 0x80u + (n)*4u))
#define GCLK_SYNCBUSY_GENCTRL0_MSK  (1u << 2)
#define GCLK_SYNCBUSY_GENCTRL1_MSK  (1u << 3)
#define GCLK_PCHCTRL_CHEN_MSK       (1u << 6)

/* -------------------------------------------------------------------------
 * SERCOM0 USART -- base 0x44810000
 * CTRLA  [0x00]: MODE [4:2] = 1 for USART internal clock, ENABLE = bit 1
 * CTRLB  [0x04]
 * BAUD   [0x0C]
 * INTFLAG[0x18]: DRE=bit0 (TX ready), TXC=bit1
 * SYNCBUSY[0x1C]
 * DATA   [0x28]: TX/RX data register
 * ------------------------------------------------------------------------- */
#define SC0_BASE         0x44810000u
#define SC0_CTRLA        (*(volatile uint32_t *)(SC0_BASE + 0x00u))
#define SC0_CTRLB        (*(volatile uint32_t *)(SC0_BASE + 0x04u))
#define SC0_BAUD         (*(volatile uint16_t *)(SC0_BASE + 0x0Cu))
#define SC0_INTFLAG      (*(volatile uint16_t *)(SC0_BASE + 0x18u))
#define SC0_SYNCBUSY     (*(volatile uint32_t *)(SC0_BASE + 0x1Cu))
#define SC0_DATA         (*(volatile uint32_t *)(SC0_BASE + 0x28u))

#define CTRLA_MODE_USART (1u << 2)   /* MODE=001 */
#define CTRLA_ENABLE     (1u << 1)
#define CTRLA_DORD       (1u << 30)  /* LSB first */
#define CTRLB_TXEN       (1u << 16)
#define CTRLB_RXEN       (1u << 17)
#define INTFLAG_DRE      (1u << 0)

/* -------------------------------------------------------------------------
 * Clock init -- SDK-accurate PLL0 sequence
 * Emulator stubs these with ready-always semantics.
 * ------------------------------------------------------------------------- */
static void clock_init(void)
{
    /* Enable GCLK in MCLK */
    MCLK_CLKMSK0 |= (1u << 2u);

    /* Enable additional voltage regulator (for PLL) */
    SUPC_VREGCTRL |= SUPC_VREGCTRL_AVREGEN_MSK;
    while ((SUPC_STATUS & SUPC_STATUS_ADDVREGRDY_MSK) == 0u) { }

    /* Configure PLL0: REFDIV=12, FBDIV=240, POSTDIV0=8 => 200 MHz */
    OSCCTRL_PLL0REFDIV   = 12u;
    OSCCTRL_PLL0FBDIV    = 240u;
    OSCCTRL_FRACDIV0     = 0u;
    while ((OSCCTRL_SYNCBUSY & OSCCTRL_SYNCBUSY_FRACDIV0_MSK) != 0u) { }
    OSCCTRL_PLL0POSTDIVA = (1u << 8) | 8u;  /* OUTEN0 | POSTDIV0=8 */
    OSCCTRL_PLL0CTRL     = (1u << 16) | (2u << 4) | (1u << 1); /* BWSEL|REFSEL=XOSC0|ENABLE */
    while ((OSCCTRL_STATUS & OSCCTRL_STATUS_PLL0LOCK_MSK) == 0u) { }

    /* GCLK0: PLL0/1 => 200 MHz */
    GCLK_GENCTRL(0) = (1u << 16) | (6u << 8) | (1u << 1); /* DIV=1|SRC=PLL0|GENEN */
    while ((GCLK_SYNCBUSY & GCLK_SYNCBUSY_GENCTRL0_MSK) != 0u) { }

    /* GCLK1: PLL0/2 => 100 MHz */
    GCLK_GENCTRL(1) = (2u << 16) | (6u << 8) | (1u << 1); /* DIV=2|SRC=PLL0|GENEN */
    while ((GCLK_SYNCBUSY & GCLK_SYNCBUSY_GENCTRL1_MSK) != 0u) { }

    /* Enable SERCOM0_CORE clock (PCHCTRL[9]) from GCLK1 */
    GCLK_PCHCTRL(9) = (1u << 0) | GCLK_PCHCTRL_CHEN_MSK; /* GEN=1 | CHEN */
    while ((GCLK_PCHCTRL(9) & GCLK_PCHCTRL_CHEN_MSK) == 0u) { }

    /* Enable SERCOM0 APB clock in MCLK (CLKMSK2 bit 9) */
    MCLK_CLKMSK2 |= (1u << 9u);
}

/* -------------------------------------------------------------------------
 * SERCOM0 USART init
 * ------------------------------------------------------------------------- */
static void sercom0_usart_init(void)
{
    /* Disable first */
    SC0_CTRLA &= ~CTRLA_ENABLE;
    while (SC0_SYNCBUSY) { }

    /* CTRLA: MODE=USART_INT_CLK, TXPO=0 (PAD0), RXPO=1 (PAD1), DORD=LSB */
    SC0_CTRLA = CTRLA_MODE_USART | CTRLA_DORD;

    /* Baud for 115200 @ 100 MHz GCLK: BAUD = 65536*(1 - 16*115200/100e6) */
    /* = 65536 - 16*115200*65536/100000000 = 65536 - 1207 = 64329 => ~0xFB49 */
    SC0_BAUD = 64329u;

    /* CTRLB: 8-bit, 1 stop, TX+RX enable */
    SC0_CTRLB = CTRLB_TXEN | CTRLB_RXEN;
    while (SC0_SYNCBUSY) { }

    /* Enable */
    SC0_CTRLA |= CTRLA_ENABLE;
    while (SC0_SYNCBUSY) { }
}

void sercom0_putc(char c)
{
    while ((SC0_INTFLAG & INTFLAG_DRE) == 0u) { }
    SC0_DATA = (uint32_t)(unsigned char)c;
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

    clock_init();
    sercom0_usart_init();
    __libc_init_array();
    _exit(main());
}
