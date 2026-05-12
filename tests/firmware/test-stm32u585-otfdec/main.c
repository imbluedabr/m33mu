/* m33mu -- OTFDEC firmware test for STM32U585
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Verifies that the OTFDEC peripheral correctly decrypts bytes read from
 * the mmap'd SPI flash region at 0x60000000.
 *
 * Test parameters match gen_blob.py:
 *   KEY0..KEY3 = 0x03020100 / 0x07060504 / 0x0b0a0908 / 0x0f0e0d0c
 *   (key bytes: 0x00..0x0f)
 *   NONCE_LO  = 0xDEADBEEF  (RxNONCER0)
 *   NONCE_HI  = 0xCAFEBABE  (RxNONCER1)
 *   START_ADDR = 0x60000000
 *   END_ADDR   = 0x600000FF
 *
 * Expected plaintext at 0x60000000[0..15]:
 *   01 23 45 67  89 AB CD EF  FE DC BA 98  76 54 32 10
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

extern uint32_t _sidata;
extern uint32_t _sdata;
extern uint32_t _edata;
extern uint32_t _sbss;
extern uint32_t _ebss;
extern void __libc_init_array(void);

/* systick_ms referenced by syscalls.c */
volatile uint32_t systick_ms = 0;

/* -----------------------------------------------------------------------
 * OTFDEC register map (NS, 0x420C5000)
 * ----------------------------------------------------------------------- */
#define OTFDEC_BASE         0x420C5000u

#define OTFDEC_CR           (*(volatile uint32_t *)(OTFDEC_BASE + 0x000u))

/* Region 0 base: 0x20 + 0*0x30 = 0x20 */
#define OTFDEC_R0_BASE      (OTFDEC_BASE + 0x020u)
#define OTFDEC_R0_CFGR      (*(volatile uint32_t *)(OTFDEC_R0_BASE + 0x00u))
#define OTFDEC_R0_STARTADDR (*(volatile uint32_t *)(OTFDEC_R0_BASE + 0x04u))
#define OTFDEC_R0_ENDADDR   (*(volatile uint32_t *)(OTFDEC_R0_BASE + 0x08u))
#define OTFDEC_R0_NONCE0    (*(volatile uint32_t *)(OTFDEC_R0_BASE + 0x0Cu))
#define OTFDEC_R0_NONCE1    (*(volatile uint32_t *)(OTFDEC_R0_BASE + 0x10u))
#define OTFDEC_R0_KEY0      (*(volatile uint32_t *)(OTFDEC_R0_BASE + 0x14u))
#define OTFDEC_R0_KEY1      (*(volatile uint32_t *)(OTFDEC_R0_BASE + 0x18u))
#define OTFDEC_R0_KEY2      (*(volatile uint32_t *)(OTFDEC_R0_BASE + 0x1Cu))
#define OTFDEC_R0_KEY3      (*(volatile uint32_t *)(OTFDEC_R0_BASE + 0x20u))

#define OTFDEC_CR_EN        (1u << 0)
#define OTFDEC_CFGR_EN      (1u << 0)

/* -----------------------------------------------------------------------
 * USART3 (for printf)
 * ----------------------------------------------------------------------- */
#define RCC_BASE            0x46020C00u
#define RCC_APB1LENR        (*(volatile uint32_t *)(RCC_BASE + 0x9Cu))
#define RCC_AHB2ENR         (*(volatile uint32_t *)(RCC_BASE + 0x8Cu))

#define GPIOD_BASE          0x42020C00u
#define GPIO_MODER(x)       (*(volatile uint32_t *)((x) + 0x00u))
#define GPIO_OTYPER(x)      (*(volatile uint32_t *)((x) + 0x04u))
#define GPIO_OSPEEDR(x)     (*(volatile uint32_t *)((x) + 0x08u))
#define GPIO_PUPDR(x)       (*(volatile uint32_t *)((x) + 0x0Cu))
#define GPIO_AFRH(x)        (*(volatile uint32_t *)((x) + 0x24u))

#define USART3_BASE         0x40004800u
#define USART_CR1(b)        (*(volatile uint32_t *)((b) + 0x00u))
#define USART_CR2(b)        (*(volatile uint32_t *)((b) + 0x04u))
#define USART_CR3(b)        (*(volatile uint32_t *)((b) + 0x08u))
#define USART_BRR(b)        (*(volatile uint32_t *)((b) + 0x0Cu))
#define USART_ISR(b)        (*(volatile uint32_t *)((b) + 0x1Cu))
#define USART_TDR(b)        (*(volatile uint32_t *)((b) + 0x28u))

#define SYSCLK_HZ           64000000u

static void gpio_config_usart3_pd8_pd9(void)
{
    uint32_t v;
    RCC_AHB2ENR |= (1u << 3);
    v = GPIO_MODER(GPIOD_BASE);
    v &= ~((3u << (8u*2u)) | (3u << (9u*2u)));
    v |= (2u << (8u*2u)) | (2u << (9u*2u));
    GPIO_MODER(GPIOD_BASE) = v;
    v = GPIO_OTYPER(GPIOD_BASE);
    v &= ~((1u << 8) | (1u << 9));
    GPIO_OTYPER(GPIOD_BASE) = v;
    v = GPIO_OSPEEDR(GPIOD_BASE);
    v &= ~((3u << (8u*2u)) | (3u << (9u*2u)));
    v |= (2u << (8u*2u)) | (2u << (9u*2u));
    GPIO_OSPEEDR(GPIOD_BASE) = v;
    v = GPIO_PUPDR(GPIOD_BASE);
    v &= ~((3u << (8u*2u)) | (3u << (9u*2u)));
    v |= (1u << (9u*2u));
    GPIO_PUPDR(GPIOD_BASE) = v;
    v = GPIO_AFRH(GPIOD_BASE);
    v &= ~((0xFu << ((8u-8u)*4u)) | (0xFu << ((9u-8u)*4u)));
    v |= (7u << ((8u-8u)*4u)) | (7u << ((9u-8u)*4u));
    GPIO_AFRH(GPIOD_BASE) = v;
}

static void usart3_init(void)
{
    RCC_APB1LENR |= (1u << 18);
    USART_CR1(USART3_BASE) = 0;
    USART_CR2(USART3_BASE) = 0;
    USART_CR3(USART3_BASE) = 0;
    USART_BRR(USART3_BASE) = SYSCLK_HZ / 115200u;
    USART_CR1(USART3_BASE) = (1u << 0) | (1u << 2) | (1u << 3);
}

void usart3_putc(char c)
{
    while ((USART_ISR(USART3_BASE) & (1u << 7)) == 0u) {}
    USART_TDR(USART3_BASE) = (uint32_t)c;
}

int _write(int file, const char *ptr, int len)
{
    (void)file;
    for (int i = 0; i < len; ++i) {
        usart3_putc(ptr[i]);
    }
    return len;
}

/* -----------------------------------------------------------------------
 * Expected plaintext (must match gen_blob.py PLAINTEXT)
 * ----------------------------------------------------------------------- */
static const uint8_t expected[16] = {
    0x01u, 0x23u, 0x45u, 0x67u,
    0x89u, 0xABu, 0xCDu, 0xEFu,
    0xFEu, 0xDCu, 0xBAu, 0x98u,
    0x76u, 0x54u, 0x32u, 0x10u,
};

int main(void)
{
    volatile uint8_t *mmap = (volatile uint8_t *)0x60000000u;
    uint32_t i;
    uint32_t errors = 0;

    gpio_config_usart3_pd8_pd9();
    usart3_init();

    printf("OTFDEC test start\r\n");

    /* ---------------------------------------------------------------
     * Configure OTFDEC region 0
     * --------------------------------------------------------------- */

    /* Write key (little-endian word order) */
    OTFDEC_R0_KEY0 = 0x03020100u;
    OTFDEC_R0_KEY1 = 0x07060504u;
    OTFDEC_R0_KEY2 = 0x0b0a0908u;
    OTFDEC_R0_KEY3 = 0x0f0e0d0cu;

    /* Write nonce: NONCE_LO (NONCE R0) = 0xDEADBEEF, NONCE_HI (NONCE R1) = 0xCAFEBABE */
    OTFDEC_R0_NONCE0 = 0xDEADBEEFu;
    OTFDEC_R0_NONCE1 = 0xCAFEBABEu;

    /* Address range */
    OTFDEC_R0_STARTADDR = 0x60000000u;
    OTFDEC_R0_ENDADDR   = 0x600000FFu;

    /* Enable region */
    OTFDEC_R0_CFGR = OTFDEC_CFGR_EN;

    /* Enable global OTFDEC */
    OTFDEC_CR = OTFDEC_CR_EN;

    /* ---------------------------------------------------------------
     * Read 16 bytes from the mmap'd flash and compare to expected
     * --------------------------------------------------------------- */
    printf("Reading from mmap @ 0x60000000:\r\n");
    for (i = 0; i < 16u; ++i) {
        printf("%02x ", (unsigned)mmap[i]);
    }
    printf("\r\n");

    printf("Expected plaintext:\r\n");
    for (i = 0; i < 16u; ++i) {
        printf("%02x ", (unsigned)expected[i]);
    }
    printf("\r\n");

    for (i = 0; i < 16u; ++i) {
        if (mmap[i] != expected[i]) {
            errors++;
            printf("MISMATCH at [%lu]: got 0x%02x expected 0x%02x\r\n",
                   (unsigned long)i, (unsigned)mmap[i], (unsigned)expected[i]);
        }
    }

    if (errors == 0u) {
        printf("OTFDEC TEST SUCCESSFUL\r\n");
        __asm volatile("bkpt #0x42");
    } else {
        printf("OTFDEC TEST FAILED: %lu mismatches\r\n", (unsigned long)errors);
        __asm volatile("bkpt #0x77");
    }

    while (1) {}
    return 0;
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
    printf("HardFault!\r\n");
    __asm volatile("bkpt #0x77");
    while (1) {}
}

void UsageFault_Handler(void)
{
    __asm volatile("bkpt #0x77");
    while (1) {}
}
