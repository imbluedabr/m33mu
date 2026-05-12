/* m33mu -- an ARMv8-M Emulator
 *
 * Copyright (C) 2025  Daniele Lacamera <root@danielinux.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

extern uint32_t _sidata;
extern uint32_t _sdata;
extern uint32_t _edata;
extern uint32_t _sbss;
extern uint32_t _ebss;
extern void __libc_init_array(void);

/* -----------------------------------------------------------------------
 * PKA handle instance (referenced as extern in wolfssl/stm32.c)
 * --------------------------------------------------------------------- */
PKA_HandleTypeDef hpka = { .Instance = (volatile uint32_t *)STM32U5_PKA_BASE, .sz = 0 };

/* -----------------------------------------------------------------------
 * Peripheral definitions (STM32U585)
 * --------------------------------------------------------------------- */
#define SYSCLK_HZ               64000000U

/* RCC */
#define RCC_BASE                0x46020C00U
#define RCC_AHB2ENR             (*(volatile uint32_t *)(RCC_BASE + 0x8CU))
#define RCC_APB2ENR             (*(volatile uint32_t *)(RCC_BASE + 0xA4U))

/* GPIOA */
#define GPIOA_BASE              0x42020000U
#define GPIO_MODER(x)           (*(volatile uint32_t *)((x) + 0x00U))
#define GPIO_OTYPER(x)          (*(volatile uint32_t *)((x) + 0x04U))
#define GPIO_OSPEEDR(x)         (*(volatile uint32_t *)((x) + 0x08U))
#define GPIO_PUPDR(x)           (*(volatile uint32_t *)((x) + 0x0CU))
#define GPIO_AFRH(x)            (*(volatile uint32_t *)((x) + 0x24U))

/* USART1 (console) */
#define USART1_BASE             0x40013800U
#define USART_CR1(b)            (*(volatile uint32_t *)((b) + 0x00U))
#define USART_CR2(b)            (*(volatile uint32_t *)((b) + 0x04U))
#define USART_CR3(b)            (*(volatile uint32_t *)((b) + 0x08U))
#define USART_BRR(b)            (*(volatile uint32_t *)((b) + 0x0CU))
#define USART_ISR(b)            (*(volatile uint32_t *)((b) + 0x1CU))
#define USART_TDR(b)            (*(volatile uint32_t *)((b) + 0x28U))

/* SysTick */
#define SYST_CSR                (*(volatile uint32_t *)0xE000E010U)
#define SYST_RVR                (*(volatile uint32_t *)0xE000E014U)
#define SYST_CVR                (*(volatile uint32_t *)0xE000E018U)

/* -----------------------------------------------------------------------
 * Globals
 * --------------------------------------------------------------------- */
volatile uint32_t systick_ms = 0;

/* -----------------------------------------------------------------------
 * SysTick handler
 * --------------------------------------------------------------------- */
void SysTick_Handler(void)
{
    systick_ms++;
}

/* -----------------------------------------------------------------------
 * Console UART (USART1, PA9=TX, PA10=RX, AF7)
 * --------------------------------------------------------------------- */
static void gpio_config_usart1_pa9_pa10(void)
{
    uint32_t v;

    /* Enable GPIOA clock (AHB2ENR bit 0) */
    RCC_AHB2ENR |= (1U << 0);

    /* PA9 and PA10 to AF mode (MODER = 0b10) */
    v = GPIO_MODER(GPIOA_BASE);
    v &= ~((3U << (9U * 2U)) | (3U << (10U * 2U)));
    v |=  (2U << (9U * 2U)) | (2U << (10U * 2U));
    GPIO_MODER(GPIOA_BASE) = v;

    /* Push-pull */
    v = GPIO_OTYPER(GPIOA_BASE);
    v &= ~((1U << 9) | (1U << 10));
    GPIO_OTYPER(GPIOA_BASE) = v;

    /* High speed */
    v = GPIO_OSPEEDR(GPIOA_BASE);
    v &= ~((3U << (9U * 2U)) | (3U << (10U * 2U)));
    v |=  (2U << (9U * 2U)) | (2U << (10U * 2U));
    GPIO_OSPEEDR(GPIOA_BASE) = v;

    /* Pull-up on RX */
    v = GPIO_PUPDR(GPIOA_BASE);
    v &= ~((3U << (9U * 2U)) | (3U << (10U * 2U)));
    v |=  (1U << (10U * 2U));
    GPIO_PUPDR(GPIOA_BASE) = v;

    /* AF7 on PA9/PA10 (AFRH covers pins 8-15) */
    v = GPIO_AFRH(GPIOA_BASE);
    v &= ~((0xFU << ((9U - 8U) * 4U)) | (0xFU << ((10U - 8U) * 4U)));
    v |=  (7U << ((9U - 8U) * 4U)) | (7U << ((10U - 8U) * 4U));
    GPIO_AFRH(GPIOA_BASE) = v;
}

static void usart1_init(void)
{
    /* Enable USART1 clock (APB2ENR bit 14) */
    RCC_APB2ENR |= (1U << 14);
    USART_CR1(USART1_BASE) = 0;
    USART_CR2(USART1_BASE) = 0;
    USART_CR3(USART1_BASE) = 0;
    USART_BRR(USART1_BASE) = SYSCLK_HZ / 115200U;
    /* UE | RE | TE */
    USART_CR1(USART1_BASE) = (1U << 0) | (1U << 2) | (1U << 3);
}

void console_putc(char c)
{
    while ((USART_ISR(USART1_BASE) & (1U << 7)) == 0U) {
    }
    USART_TDR(USART1_BASE) = (uint32_t)(uint8_t)c;
}

static void systick_init(void)
{
    SYST_RVR = (SYSCLK_HZ / 1000U) - 1U;
    SYST_CVR = 0U;
    SYST_CSR = 7U;  /* ENABLE | TICKINT | CLKSOURCE */
}

/* -----------------------------------------------------------------------
 * PKA clock enable
 * --------------------------------------------------------------------- */
static void pka_clock_enable(void)
{
    /* PKA: AHB2ENR bit 19 (per stm32u585_mmio.c emulator code) */
    RCC_AHB2ENR |= (1U << 19);
}

/* -----------------------------------------------------------------------
 * ECDSA sign + verify self-test using wolfSSL with STM32 PKA hardware
 * --------------------------------------------------------------------- */
static int pka_ecdsa_selftest(void)
{
    int ret;
    int verified = 0;
    WC_RNG rng;
    ecc_key key;

    /* Fixed 32-byte test digest (SHA-256 of "m33mu-pka-test") */
    static const byte digest[32] = {
        0x6d, 0x33, 0x6d, 0x75, 0x2d, 0x70, 0x6b, 0x61,
        0x2d, 0x74, 0x65, 0x73, 0x74, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    byte sig[80];
    word32 sig_len = sizeof(sig);

    printf("Initialising RNG...\r\n");
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("wc_InitRng failed: %d\r\n", ret);
        return ret;
    }

    printf("Initialising ECC key...\r\n");
    ret = wc_ecc_init(&key);
    if (ret != 0) {
        printf("wc_ecc_init failed: %d\r\n", ret);
        wc_FreeRng(&rng);
        return ret;
    }

    printf("Generating P-256 key pair via PKA...\r\n");
    ret = wc_ecc_make_key_ex(&rng, 32, &key, ECC_SECP256R1);
    if (ret != 0) {
        printf("wc_ecc_make_key_ex failed: %d\r\n", ret);
        wc_ecc_free(&key);
        wc_FreeRng(&rng);
        return ret;
    }
    printf("Key generation OK.\r\n");

    printf("Signing digest via PKA...\r\n");
    ret = wc_ecc_sign_hash(digest, sizeof(digest), sig, &sig_len, &rng, &key);
    if (ret != 0) {
        printf("wc_ecc_sign_hash failed: %d\r\n", ret);
        wc_ecc_free(&key);
        wc_FreeRng(&rng);
        return ret;
    }
    printf("Sign OK (sig_len=%lu)\r\n", (unsigned long)sig_len);

    printf("Verifying signature via PKA...\r\n");
    ret = wc_ecc_verify_hash(sig, sig_len, digest, sizeof(digest), &verified, &key);
    if (ret != 0) {
        printf("wc_ecc_verify_hash failed: %d\r\n", ret);
        wc_ecc_free(&key);
        wc_FreeRng(&rng);
        return ret;
    }

    wc_ecc_free(&key);
    wc_FreeRng(&rng);

    if (verified != 1) {
        printf("Signature verification FAILED (verified=%d)\r\n", verified);
        return -1;
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * main
 * --------------------------------------------------------------------- */
int main(void)
{
    int ret;

    gpio_config_usart1_pa9_pa10();
    usart1_init();
    systick_init();
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("STM32U585 wolfSSL PKA test\r\n");

    /* Enable PKA peripheral clock */
    pka_clock_enable();

    ret = pka_ecdsa_selftest();
    if (ret == 0) {
        printf("PKA TEST SUCCESSFUL\n");
        __asm__ volatile("bkpt #0x42");
    } else {
        printf("PKA TEST FAILED: %d\r\n", ret);
        __asm__ volatile("bkpt #0x77");
    }

    for (;;) {
        __asm__ volatile("wfi");
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * Reset handler
 * --------------------------------------------------------------------- */
void Reset_Handler(void)
{
    uint32_t *src;
    uint32_t *dst;

    src = &_sidata;
    for (dst = &_sdata; dst < &_edata; ) {
        *dst++ = *src++;
    }
    for (dst = &_sbss; dst < &_ebss; ) {
        *dst++ = 0U;
    }

    __libc_init_array();
    (void)main();
    for (;;) {
    }
}

/* -----------------------------------------------------------------------
 * Fault handlers
 * --------------------------------------------------------------------- */
void HardFault_Handler(void)
{
    printf("HARDFAULT\r\n");
    __asm__ volatile("bkpt #0x77");
    for (;;) {
    }
}

void UsageFault_Handler(void)
{
    printf("USAGEFAULT\r\n");
    __asm__ volatile("bkpt #0x77");
    for (;;) {
    }
}
