#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include "iotsafe_test_certs.h"
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/port/iotsafe/iotsafe.h>

extern uint32_t _sidata;
extern uint32_t _sdata;
extern uint32_t _edata;
extern uint32_t _sbss;
extern uint32_t _ebss;
extern void __libc_init_array(void);

#define SYSCLK_HZ           64000000u
#define CONSOLE_USART_BASE  0x40013800u
#define MODEM_USART_BASE    0x40004800u

#define RCC_BASE            0x44020C00u
#define RCC_AHB2ENR         (*(volatile uint32_t *)(RCC_BASE + 0x8Cu))
#define RCC_APB1LENR        (*(volatile uint32_t *)(RCC_BASE + 0x9Cu))
#define RCC_APB2ENR         (*(volatile uint32_t *)(RCC_BASE + 0xA4u))

#define GPIOA_BASE          0x42020000u
#define GPIOD_BASE          0x42020C00u
#define GPIO_MODER(x)       (*(volatile uint32_t *)((x) + 0x00u))
#define GPIO_OTYPER(x)      (*(volatile uint32_t *)((x) + 0x04u))
#define GPIO_OSPEEDR(x)     (*(volatile uint32_t *)((x) + 0x08u))
#define GPIO_PUPDR(x)       (*(volatile uint32_t *)((x) + 0x0Cu))
#define GPIO_AFRL(x)        (*(volatile uint32_t *)((x) + 0x20u))
#define GPIO_AFRH(x)        (*(volatile uint32_t *)((x) + 0x24u))

#define USART_CR1(b)        (*(volatile uint32_t *)((b) + 0x00u))
#define USART_CR2(b)        (*(volatile uint32_t *)((b) + 0x04u))
#define USART_CR3(b)        (*(volatile uint32_t *)((b) + 0x08u))
#define USART_BRR(b)        (*(volatile uint32_t *)((b) + 0x0Cu))
#define USART_ISR(b)        (*(volatile uint32_t *)((b) + 0x1Cu))
#define USART_ICR(b)        (*(volatile uint32_t *)((b) + 0x20u))
#define USART_RDR(b)        (*(volatile uint32_t *)((b) + 0x24u))
#define USART_TDR(b)        (*(volatile uint32_t *)((b) + 0x28u))

#define USART_CR1_UE        (1u << 0)
#define USART_CR1_RE        (1u << 2)
#define USART_CR1_TE        (1u << 3)
#define USART_ISR_RXNE      (1u << 5)
#define USART_ISR_TXE       (1u << 7)

#define SYST_CSR            (*(volatile uint32_t *)0xE000E010u)
#define SYST_RVR            (*(volatile uint32_t *)0xE000E014u)
#define SYST_CVR            (*(volatile uint32_t *)0xE000E018u)

volatile uint32_t systick_ms;
volatile unsigned long jiffies;

static void gpio_config_usart1_pa9_pa10(void)
{
    uint32_t v;

    RCC_AHB2ENR |= (1u << 0);

    v = GPIO_MODER(GPIOA_BASE);
    v &= ~((3u << (9u * 2u)) | (3u << (10u * 2u)));
    v |= (2u << (9u * 2u)) | (2u << (10u * 2u));
    GPIO_MODER(GPIOA_BASE) = v;

    v = GPIO_OTYPER(GPIOA_BASE);
    v &= ~((1u << 9) | (1u << 10));
    GPIO_OTYPER(GPIOA_BASE) = v;

    v = GPIO_OSPEEDR(GPIOA_BASE);
    v &= ~((3u << (9u * 2u)) | (3u << (10u * 2u)));
    v |= (2u << (9u * 2u)) | (2u << (10u * 2u));
    GPIO_OSPEEDR(GPIOA_BASE) = v;

    v = GPIO_PUPDR(GPIOA_BASE);
    v &= ~((3u << (9u * 2u)) | (3u << (10u * 2u)));
    v |= (1u << (10u * 2u));
    GPIO_PUPDR(GPIOA_BASE) = v;

    v = GPIO_AFRH(GPIOA_BASE);
    v &= ~((0xFu << ((9u - 8u) * 4u)) | (0xFu << ((10u - 8u) * 4u)));
    v |= (7u << ((9u - 8u) * 4u)) | (7u << ((10u - 8u) * 4u));
    GPIO_AFRH(GPIOA_BASE) = v;
}

static void gpio_config_usart3_pd8_pd9(void)
{
    uint32_t v;

    RCC_AHB2ENR |= (1u << 3);

    v = GPIO_MODER(GPIOD_BASE);
    v &= ~((3u << (8u * 2u)) | (3u << (9u * 2u)));
    v |= (2u << (8u * 2u)) | (2u << (9u * 2u));
    GPIO_MODER(GPIOD_BASE) = v;

    v = GPIO_OTYPER(GPIOD_BASE);
    v &= ~((1u << 8) | (1u << 9));
    GPIO_OTYPER(GPIOD_BASE) = v;

    v = GPIO_OSPEEDR(GPIOD_BASE);
    v &= ~((3u << (8u * 2u)) | (3u << (9u * 2u)));
    v |= (2u << (8u * 2u)) | (2u << (9u * 2u));
    GPIO_OSPEEDR(GPIOD_BASE) = v;

    v = GPIO_PUPDR(GPIOD_BASE);
    v &= ~((3u << (8u * 2u)) | (3u << (9u * 2u)));
    v |= (1u << (9u * 2u));
    GPIO_PUPDR(GPIOD_BASE) = v;

    v = GPIO_AFRH(GPIOD_BASE);
    v &= ~((0xFu << ((8u - 8u) * 4u)) | (0xFu << ((9u - 8u) * 4u)));
    v |= (7u << ((8u - 8u) * 4u)) | (7u << ((9u - 8u) * 4u));
    GPIO_AFRH(GPIOD_BASE) = v;
}

static void usart_init(uint32_t base, uint32_t apb_enr_mask, volatile uint32_t *enr)
{
    *enr |= apb_enr_mask;
    USART_CR1(base) = 0;
    USART_CR2(base) = 0;
    USART_CR3(base) = 0;
    USART_BRR(base) = SYSCLK_HZ / 115200u;
    USART_CR1(base) = USART_CR1_UE | USART_CR1_RE | USART_CR1_TE;
}

static void uart_putc(uint32_t base, char c)
{
    while ((USART_ISR(base) & USART_ISR_TXE) == 0u) {
    }
    USART_TDR(base) = (uint32_t)(uint8_t)c;
}

void console_putc(char c)
{
    if (c == '\n') {
        uart_putc(CONSOLE_USART_BASE, '\r');
    }
    uart_putc(CONSOLE_USART_BASE, c);
}

static int modem_rx(char *buf, int len)
{
    int i = 0;
    uint32_t start = systick_ms;
    uint32_t last_rx;

    memset(buf, 0, (size_t)len);
    while ((USART_ISR(MODEM_USART_BASE) & USART_ISR_RXNE) == 0u) {
        if ((systick_ms - start) >= 10u) {
            return 0;
        }
    }
    last_rx = systick_ms;
    while (i < len) {
        if ((USART_ISR(MODEM_USART_BASE) & USART_ISR_RXNE) != 0u) {
            char c = (char)(USART_RDR(MODEM_USART_BASE) & 0xffu);
            buf[i++] = c;
            last_rx = systick_ms;
            if (c == '\n') {
                break;
            }
            continue;
        }
        if ((systick_ms - last_rx) >= 2u) {
            break;
        }
    }
    return i;
}

static int modem_tx(const char *buf, int len)
{
    int i;
    for (i = 0; i < len; ++i) {
        uart_putc(MODEM_USART_BASE, buf[i]);
    }
    return len;
}

static void systick_init(void)
{
    SYST_RVR = (SYSCLK_HZ / 1000u) - 1u;
    SYST_CVR = 0u;
    SYST_CSR = 7u;
}

void SysTick_Handler(void)
{
    systick_ms++;
    jiffies++;
}

static void delay_ms(uint32_t ms)
{
    uint32_t start = systick_ms;
    while ((systick_ms - start) < ms) {
    }
}

static void test_breakpoint(void)
{
    __asm volatile("bkpt #0x42");
}

int memory_tls_test(void);

static int iotsafe_sign_selftest(void)
{
    static const byte msg[] = "m33mu-iotsafe-sign";
    uint16_t privkey_id = PRIVKEY_ID;
    byte digest[WC_SHA256_DIGEST_SIZE];
    byte sig[80];
    word32 sig_len = sizeof(sig);
    ecc_key pub;
    word32 idx = 0;
    int verified = 0;
    int ret;

    ret = wc_Sha256Hash(msg, (word32)(sizeof(msg) - 1u), digest);
    if (ret != 0) {
        return ret;
    }

    ret = wc_iotsafe_ecc_sign_hash_ex(digest, sizeof(digest), sig, &sig_len,
                                      (byte *)&privkey_id, IOTSAFE_ID_SIZE);
    if (ret != 0) {
        return ret;
    }

    memset(&pub, 0, sizeof(pub));
    ret = wc_ecc_init(&pub);
    if (ret != 0) {
        return ret;
    }
    ret = wc_EccPublicKeyDecode(ecc_clikeypub_der_256, &idx, &pub,
                                sizeof_ecc_clikeypub_der_256);
    if (ret == 0) {
        ret = wc_ecc_verify_hash(sig, sig_len, digest, sizeof(digest), &verified, &pub);
    }
    wc_ecc_free(&pub);
    if (ret != 0) {
        return ret;
    }
    return verified ? 0 : -1;
}

int main(void)
{
    WC_RNG rng;
    uint8_t randombytes[16];
    int i;
    int ret;

    gpio_config_usart1_pa9_pa10();
    gpio_config_usart3_pd8_pd9();
    usart_init(CONSOLE_USART_BASE, (1u << 14), &RCC_APB2ENR);
    usart_init(MODEM_USART_BASE, (1u << 18), &RCC_APB1LENR);
    systick_init();
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("wolfSSL IoTSAFE stm32h563 demo\r\n");
    printf("console=USART1 modem=USART3\r\n");
    delay_ms(50u);

    wolfSSL_Init();
    wolfSSL_Debugging_ON();

    wolfIoTSafe_SetCSIM_read_cb(modem_rx);
    wolfIoTSafe_SetCSIM_write_cb(modem_tx);

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("rng init failed: %d\r\n", ret);
        test_breakpoint();
        for (;;) {
        }
    }

    ret = wc_RNG_GenerateBlock(&rng, randombytes, sizeof(randombytes));
    if (ret == 0) {
        printf("rng:");
        for (i = 0; i < (int)sizeof(randombytes); ++i) {
            printf(" %02x", randombytes[i]);
        }
        printf("\r\n");
    } else {
        printf("rng failed: %d\r\n", ret);
    }
    wc_FreeRng(&rng);

    ret = iotsafe_sign_selftest();
    if (ret == 0) {
        printf("sign selftest ok\r\n");
    } else {
        printf("sign selftest failed: %d\r\n", ret);
    }

    ret = memory_tls_test();
    if (ret == 0) {
        printf("IOTSAFE TEST SUCCESSFUL\r\n");
    } else {
        printf("IOTSAFE TEST FAILED\r\n");
    }

    test_breakpoint();
    for (;;) {
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
    (void)main();
    for (;;) {
    }
}
