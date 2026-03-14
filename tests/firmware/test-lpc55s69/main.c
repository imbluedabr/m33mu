/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * LPC55S69 test firmware: exercises FLEXCOMM0 USART, SPI1, MRT0, GPIO, SysTick.
 */
#include <stdint.h>
#include <stdio.h>

extern uint32_t _sidata;
extern uint32_t _sdata;
extern uint32_t _edata;
extern uint32_t _sbss;
extern uint32_t _ebss;
extern uint32_t _estack;
extern void __libc_init_array(void);

/* -------------------------------------------------------------------------
 * SYSCON — 0x40000000
 * AHBCLKCTRL0 (0x200): GPIO0=bit14, GPIO1=bit15
 * AHBCLKCTRL1 (0x204): MRT=bit0, FC0=bit11, FC1=bit12
 * PRESETCTRL0/1 mirror the same bit positions; write 1 to release reset.
 * ------------------------------------------------------------------------- */
#define SYSCON_BASE         0x40000000u
#define AHBCLKCTRL0         (*(volatile uint32_t *)(SYSCON_BASE + 0x200u))
#define AHBCLKCTRL1         (*(volatile uint32_t *)(SYSCON_BASE + 0x204u))
#define AHBCLKCTRLSET1      (*(volatile uint32_t *)(SYSCON_BASE + 0x228u))
#define PRESETCTRL0         (*(volatile uint32_t *)(SYSCON_BASE + 0x100u))
#define PRESETCTRL1         (*(volatile uint32_t *)(SYSCON_BASE + 0x104u))
#define PRESETCTRLSET1      (*(volatile uint32_t *)(SYSCON_BASE + 0x128u))

static void syscon_enable0(uint32_t bit)
{
    AHBCLKCTRL0 |= (1u << bit);
    PRESETCTRL0 |= (1u << bit);
}

static void syscon_enable1(uint32_t bit)
{
    AHBCLKCTRL1 |= (1u << bit);
    PRESETCTRL1 |= (1u << bit);
}

/* -------------------------------------------------------------------------
 * FLEXCOMM0 USART — base 0x40086000
 * LPC55S69 USART uses FIFO registers, not LPUART-style.
 * CFG: bit0=ENABLE, bits[3:2]=DATALEN (01=8-bit)
 * FIFOCFG: bit0=ENABLETX, bit1=ENABLERX
 * FIFOSTAT: bit5=TXNOTFULL (ready to write)
 * FIFOWR: write byte to TX FIFO
 * ------------------------------------------------------------------------- */
#define FC0_BASE            0x40086000u
#define FC0_PSELID          (*(volatile uint32_t *)(FC0_BASE + 0xFF8u))
#define FC0_CFG             (*(volatile uint32_t *)(FC0_BASE + 0x000u))
#define FC0_FIFOCFG         (*(volatile uint32_t *)(FC0_BASE + 0xE00u))
#define FC0_FIFOSTAT        (*(volatile uint32_t *)(FC0_BASE + 0xE04u))
#define FC0_FIFOWR          (*(volatile uint32_t *)(FC0_BASE + 0xE20u))
#define FC0_FIFORD          (*(volatile uint32_t *)(FC0_BASE + 0xE30u))

#define PSELID_PERSEL_USART  1u
#define PSELID_PERSEL_SPI    2u
#define CFG_ENABLE           (1u << 0)
#define CFG_DATALEN_8BIT     (1u << 2)
#define FIFOCFG_ENABLETX     (1u << 0)
#define FIFOCFG_ENABLERX     (1u << 1)
#define FIFOSTAT_TXNOTFULL   (1u << 5)
#define FIFOSTAT_RXNOTEMPTY  (1u << 6)

static void fc0_usart_init(void)
{
    syscon_enable1(11u);  /* FC0 clock + reset release */

    FC0_PSELID = (FC0_PSELID & ~0x7u) | PSELID_PERSEL_USART;
    FC0_CFG    = CFG_ENABLE | CFG_DATALEN_8BIT;
    FC0_FIFOCFG = FIFOCFG_ENABLETX | FIFOCFG_ENABLERX;
}

void fc0_putc(char c)
{
    while ((FC0_FIFOSTAT & FIFOSTAT_TXNOTFULL) == 0u) { }
    FC0_FIFOWR = (uint32_t)(uint8_t)c;
}

/* -------------------------------------------------------------------------
 * FLEXCOMM1 SPI — base 0x40087000
 * SPI CFG: bit0=ENABLE, bit2=MASTER
 * FIFOSTAT: bit5=TXNOTFULL, bit6=RXNOTEMPTY
 * FIFOWR: bits[15:0]=TXDATA, bit22=RXIGNORE, bits[27:24]=LEN (7=8-bit)
 * FIFORD: bits[15:0]=RXDATA
 * ------------------------------------------------------------------------- */
#define FC1_BASE            0x40087000u
#define FC1_PSELID          (*(volatile uint32_t *)(FC1_BASE + 0xFF8u))
#define FC1_SPI_CFG         (*(volatile uint32_t *)(FC1_BASE + 0x400u))
#define FC1_FIFOCFG         (*(volatile uint32_t *)(FC1_BASE + 0xE00u))
#define FC1_FIFOSTAT        (*(volatile uint32_t *)(FC1_BASE + 0xE04u))
#define FC1_FIFOWR          (*(volatile uint32_t *)(FC1_BASE + 0xE20u))
#define FC1_FIFORD          (*(volatile uint32_t *)(FC1_BASE + 0xE30u))

#define SPI_CFG_ENABLE      (1u << 0)
#define SPI_CFG_MASTER      (1u << 2)
#define FIFOWR_RXIGNORE     (1u << 22)
#define FIFOWR_LEN(n)       ((uint32_t)(n) << 24)

static void fc1_spi_init(void)
{
    syscon_enable1(12u);  /* FC1 clock + reset release */

    FC1_PSELID  = (FC1_PSELID & ~0x7u) | PSELID_PERSEL_SPI;
    FC1_SPI_CFG = 0u;
    FC1_FIFOCFG = FIFOCFG_ENABLETX | FIFOCFG_ENABLERX;
    FC1_SPI_CFG = SPI_CFG_ENABLE | SPI_CFG_MASTER;
}

static uint8_t fc1_spi_xfer(uint8_t out)
{
    while ((FC1_FIFOSTAT & FIFOSTAT_TXNOTFULL) == 0u) { }
    FC1_FIFOWR = (uint32_t)out | FIFOWR_LEN(7u);
    while ((FC1_FIFOSTAT & FIFOSTAT_RXNOTEMPTY) == 0u) { }
    return (uint8_t)(FC1_FIFORD & 0xFFu);
}

/* -------------------------------------------------------------------------
 * MRT0 — base 0x4000D000, IRQ10
 * Channel 0: INTVAL @ +0x00 (bit31=LOAD, bits[30:0]=value)
 *            TIMER  @ +0x04 (current count, read-only)
 *            CTRL   @ +0x08 (bit0=INTEN, bits[2:1]=MODE: 0=repeat, 1=oneshot)
 *            STAT   @ +0x0C (bit0=INTFLAG w1c, bit1=RUN)
 * IRQ_FLAG   @ +0xF8 (bit per channel, w1c)
 * ------------------------------------------------------------------------- */
#define MRT0_BASE           0x4000D000u
#define MRT_CH0_INTVAL      (*(volatile uint32_t *)(MRT0_BASE + 0x00u))
#define MRT_CH0_TIMER       (*(volatile uint32_t *)(MRT0_BASE + 0x04u))
#define MRT_CH0_CTRL        (*(volatile uint32_t *)(MRT0_BASE + 0x08u))
#define MRT_CH0_STAT        (*(volatile uint32_t *)(MRT0_BASE + 0x0Cu))
#define MRT_IRQ_FLAG        (*(volatile uint32_t *)(MRT0_BASE + 0xF8u))

#define MRT_INTVAL_LOAD     (1u << 31)
#define MRT_CTRL_INTEN      (1u << 0)
#define MRT_CTRL_MODE_ONESHOT (1u << 1)
#define MRT_STAT_INTFLAG    (1u << 0)
#define MRT_STAT_RUN        (1u << 1)

/* NVIC enable register for IRQ10 (MRT_IRQn) */
#define NVIC_ISER0          (*(volatile uint32_t *)0xE000E100u)

volatile uint32_t mrt_fired = 0u;

void MRT0_IRQHandler(void)
{
    ++mrt_fired;
    MRT_CH0_STAT  = MRT_STAT_INTFLAG;    /* clear channel flag */
    MRT_IRQ_FLAG  = 0x1u;                /* clear global flag  */
}

static void mrt_oneshot(uint32_t ticks)
{
    syscon_enable1(0u);       /* MRT clock + reset release */

    NVIC_ISER0 |= (1u << 10u);
    MRT_CH0_CTRL  = MRT_CTRL_INTEN | MRT_CTRL_MODE_ONESHOT;
    MRT_CH0_INTVAL = ticks | MRT_INTVAL_LOAD;
}

/* -------------------------------------------------------------------------
 * GPIO — base 0x4008C000
 * DIR[port]  @ 0x2000 + port*4
 * DIRSET     @ 0x2380 + port*4
 * PIN[port]  @ 0x2100 + port*4
 * SET[port]  @ 0x2200 + port*4
 * CLR[port]  @ 0x2280 + port*4
 * NOT[port]  @ 0x2300 + port*4
 * GPIO0 clock: AHBCLKCTRL0 bit14; GPIO1: bit15
 * ------------------------------------------------------------------------- */
#define GPIO_BASE           0x4008C000u
#define GPIO_DIRSET0        (*(volatile uint32_t *)(GPIO_BASE + 0x2380u))
#define GPIO_PIN0           (*(volatile uint32_t *)(GPIO_BASE + 0x2100u))
#define GPIO_SET0           (*(volatile uint32_t *)(GPIO_BASE + 0x2200u))
#define GPIO_CLR0           (*(volatile uint32_t *)(GPIO_BASE + 0x2280u))
#define GPIO_NOT0           (*(volatile uint32_t *)(GPIO_BASE + 0x2300u))

static void gpio_init(void)
{
    syscon_enable0(14u);      /* GPIO0 clock + reset release */
    GPIO_DIRSET0 = (1u << 0); /* P0.0 as output */
}

/* -------------------------------------------------------------------------
 * SysTick
 * ------------------------------------------------------------------------- */
#define SYST_CSR    (*(volatile uint32_t *)0xE000E010u)
#define SYST_RVR    (*(volatile uint32_t *)0xE000E014u)
#define SYST_CVR    (*(volatile uint32_t *)0xE000E018u)

volatile uint32_t systick_ms = 0u;

void SysTick_Handler(void)
{
    ++systick_ms;
}

static void systick_init(uint32_t cpu_hz)
{
    uint32_t reload = cpu_hz / 1000u - 1u;
    SYST_CVR = 0u;
    SYST_RVR = reload;
    SYST_CSR = (1u << 2) | (1u << 1) | (1u << 0); /* CLKSRC | TICKINT | ENABLE */
}

static void delay_ms(uint32_t ms)
{
    uint32_t start = systick_ms;
    volatile uint32_t spin = 0u;
    while ((uint32_t)(systick_ms - start) < ms) {
        if (++spin > 5000000u) break;
    }
}

/* -------------------------------------------------------------------------
 * Main
 * ------------------------------------------------------------------------- */
int main(void)
{
    uint8_t id0, id1, id2;
    uint32_t pin_before, pin_after;

    fc0_usart_init();
    __asm volatile("cpsie i");
    systick_init(12000000u);  /* FRO12M default clock */

    printf("LPC55S69 test start\n");

    /* --- GPIO test --- */
    gpio_init();
    pin_before = (GPIO_PIN0 >> 0) & 1u;
    GPIO_SET0  = (1u << 0);
    pin_after  = (GPIO_PIN0 >> 0) & 1u;
    printf("GPIO P0.0: %lu -> %lu\n",
           (unsigned long)pin_before, (unsigned long)pin_after);
    GPIO_NOT0 = (1u << 0);
    printf("GPIO P0.0 NOT: %lu\n", (unsigned long)((GPIO_PIN0 >> 0) & 1u));

    /* --- SPI test --- */
    fc1_spi_init();
    printf("FLEXCOMM1: SPI mode\n");
    id0 = fc1_spi_xfer(0x9Fu);
    id1 = fc1_spi_xfer(0xFFu);
    id2 = fc1_spi_xfer(0xFFu);
    printf("SPI JEDEC ID: %02x %02x %02x\n",
           (unsigned)id0, (unsigned)id1, (unsigned)id2);

    /* --- MRT timer test --- */
    mrt_oneshot(1000u);
    delay_ms(10u);
    printf("MRT0 fired: %lu\n", (unsigned long)mrt_fired);

    /* --- SysTick timing --- */
    printf("SysTick ms: %lu\n", (unsigned long)systick_ms);
    delay_ms(5u);
    printf("After 5ms delay: %lu ms elapsed\n", (unsigned long)systick_ms);

    printf("LPC55S69 test done\n");

    __asm volatile("bkpt #0x7f");
    while (1) {
        __asm volatile("wfi");
    }
}

void Reset_Handler(void)
{
    uint32_t *src;
    uint32_t *dst;

    src = &_sidata;
    for (dst = &_sdata; dst < &_edata; ) {
        *dst++ = *src++;
    }
    for (dst = &_sbss; dst < &_ebss; ) {
        *dst++ = 0u;
    }

    __libc_init_array();
    main();
}

void HardFault_Handler(void)
{
    __asm volatile("bkpt #0x7e");
    while (1) { }
}
