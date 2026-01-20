/* TA-100 Emulation Test Firmware for STM32U585
 *
 * Tests all TA-100 SPI commands with printf output
 * SPI2: CS=PB5, SCK=PB13, MISO=PB14, MOSI=PB15
 * USART1: TX=PA9, RX=PA10 (AF7)
 * Success: BKPT #0x7F | Failure: infinite loop
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>

extern uint32_t _sidata, _sdata, _edata, _sbss, _ebss, _estack;
extern void __libc_init_array(void);

volatile uint32_t systick_ms = 0;

/* RCC */
#define RCC_BASE          0x46020C00u
#define RCC_AHB2ENR1      (*(volatile uint32_t *)(RCC_BASE + 0x8Cu))
#define RCC_APB1ENR1      (*(volatile uint32_t *)(RCC_BASE + 0x98u))
#define RCC_APB2ENR       (*(volatile uint32_t *)(RCC_BASE + 0xA4u))

/* GPIO */
#define GPIOA_BASE        0x42020000u
#define GPIOB_BASE        0x42020400u
#define GPIO_MODER(x)     (*(volatile uint32_t *)((x) + 0x00u))
#define GPIO_OTYPER(x)    (*(volatile uint32_t *)((x) + 0x04u))
#define GPIO_OSPEEDR(x)   (*(volatile uint32_t *)((x) + 0x08u))
#define GPIO_PUPDR(x)     (*(volatile uint32_t *)((x) + 0x0Cu))
#define GPIO_ODR(x)       (*(volatile uint32_t *)((x) + 0x14u))
#define GPIO_BSRR(x)      (*(volatile uint32_t *)((x) + 0x18u))
#define GPIO_AFRL(x)      (*(volatile uint32_t *)((x) + 0x20u))
#define GPIO_AFRH(x)      (*(volatile uint32_t *)((x) + 0x24u))

/* USART1 */
#define USART1_BASE       0x40013800u
#define USART_CR1(b)      (*(volatile uint32_t *)((b) + 0x00u))
#define USART_BRR(b)      (*(volatile uint32_t *)((b) + 0x0Cu))
#define USART_ISR(b)      (*(volatile uint32_t *)((b) + 0x1Cu))
#define USART_TDR(b)      (*(volatile uint32_t *)((b) + 0x28u))
#define USART_CR1_UE      (1u << 0)
#define USART_CR1_TE      (1u << 3)
#define USART_ISR_TXE     (1u << 7)

/* SPI2 */
#define SPI2_BASE         0x40003800u
#define SPI_CR1(b)        (*(volatile uint32_t *)((b) + 0x00u))
#define SPI_CR2(b)        (*(volatile uint32_t *)((b) + 0x04u))
#define SPI_CFG1(b)       (*(volatile uint32_t *)((b) + 0x08u))
#define SPI_CFG2(b)       (*(volatile uint32_t *)((b) + 0x0Cu))
#define SPI_SR(b)         (*(volatile uint32_t *)((b) + 0x14u))
#define SPI_IFCR(b)       (*(volatile uint32_t *)((b) + 0x18u))
#define SPI_TXDR(b)       (*(volatile uint32_t *)((b) + 0x20u))
#define SPI_RXDR(b)       (*(volatile uint32_t *)((b) + 0x30u))
#define SPI_CR1_SPE       (1u << 0)
#define SPI_CR1_CSTART    (1u << 9)
#define SPI_SR_TXP        (1u << 1)
#define SPI_SR_RXP        (1u << 0)
#define SPI_SR_EOT        (1u << 3)

/* TA-100 Commands */
#define CMD_INFO          0x30
#define CMD_READ          0x02
#define CMD_WRITE         0x12
#define CMD_LOCK          0x17
#define CMD_RANDOM        0x1B
#define CMD_NONCE         0x16
#define CMD_GENKEY        0x40
#define CMD_SIGN          0x41
#define CMD_SHA256        0x47

/* CS control (PB5) */
static void cs_assert(void) {
    GPIO_BSRR(GPIOB_BASE) = (1u << (5 + 16));
}
static void cs_deassert(void) {
    GPIO_BSRR(GPIOB_BASE) = (1u << 5);
}

/* CRC-16 (polynomial 0x8005) */
static uint16_t crc16(const uint8_t *data, uint16_t len) {
    uint16_t crc = 0;
    for (uint16_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (uint8_t j = 0; j < 8; j++) {
            crc = (crc & 0x8000) ? (crc << 1) ^ 0x8005 : crc << 1;
        }
    }
    return crc;
}

/* TA-100 command/response */
static void spi_transfer(const uint8_t *tx_buf, uint8_t *rx_buf, uint16_t len) {
    /* Set TSIZE for entire transaction */
    SPI_CR2(SPI2_BASE) = len;
    /* Start transfer */
    SPI_CR1(SPI2_BASE) = SPI_CR1_SPE | SPI_CR1_CSTART;
    
    /* Transfer all bytes */
    for (uint16_t i = 0; i < len; i++) {
        while (!(SPI_SR(SPI2_BASE) & SPI_SR_TXP));
        *(volatile uint8_t *)&SPI_TXDR(SPI2_BASE) = tx_buf[i];
        while (!(SPI_SR(SPI2_BASE) & SPI_SR_RXP));
        rx_buf[i] = *(volatile uint8_t *)&SPI_RXDR(SPI2_BASE);
    }
    
    /* Wait for EOT and clear it */
    while (!(SPI_SR(SPI2_BASE) & SPI_SR_EOT));
    SPI_IFCR(SPI2_BASE) = (1u << 3);
}

static int ta100_cmd(const uint8_t *cmd, uint16_t cmd_len, uint8_t *resp, uint16_t resp_len) {
    uint16_t crc_tx = crc16(cmd, cmd_len);
    uint8_t cmd_with_crc[128];
    uint8_t dummy_rx[128];
    if (cmd_len + 2 > sizeof(cmd_with_crc)) return -1;
    memcpy(cmd_with_crc, cmd, cmd_len);
    cmd_with_crc[cmd_len] = (crc_tx >> 8) & 0xFF;
    cmd_with_crc[cmd_len + 1] = crc_tx & 0xFF;

    /* Send command as single SPI transaction */
    cs_assert();
    for (volatile int i = 0; i < 1000; i++);
    spi_transfer(cmd_with_crc, dummy_rx, cmd_len + 2);
    for (volatile int i = 0; i < 10000; i++);
    cs_deassert();

    /* Receive response as single SPI transaction */
    for (volatile int i = 0; i < 500000; i++);
    cs_assert();
    for (volatile int i = 0; i < 10000; i++);
    uint8_t resp_with_crc[128];
    uint8_t dummy_tx[128];
    if (resp_len + 2 > sizeof(resp_with_crc)) return -1;
    memset(dummy_tx, 0xFF, resp_len + 2);
    spi_transfer(dummy_tx, resp_with_crc, resp_len + 2);
    cs_deassert();

    /* Validate CRC */
    uint16_t crc_rx_calc = crc16(resp_with_crc, resp_len);
    uint16_t crc_rx = (resp_with_crc[resp_len] << 8) | resp_with_crc[resp_len + 1];
    if (crc_rx != crc_rx_calc) return -1;
    memcpy(resp, resp_with_crc, resp_len);
    return 0;
}

/* Test functions */
static int test_info(void) {
    printf("[TEST] INFO...\n");
    uint8_t cmd[] = {CMD_INFO, 0x00};
    uint8_t resp[5];
    if (ta100_cmd(cmd, 2, resp, 5) < 0) return -1;
    if (resp[0] != 0x00) return -1;
    printf("  Version: %02X%02X%02X%02X\n", resp[1], resp[2], resp[3], resp[4]);
    return 0;
}

static int test_read_config(void) {
    printf("[TEST] READ config zone...\n");
    uint8_t cmd[] = {CMD_READ, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04};
    uint8_t resp[5];
    if (ta100_cmd(cmd, 7, resp, 5) < 0) return -1;
    if (resp[0] != 0x00) return -1;
    printf("  Serial: %02X%02X%02X%02X\n", resp[1], resp[2], resp[3], resp[4]);
    return 0;
}

static int test_random(void) {
    printf("[TEST] RANDOM...\n");
    uint8_t cmd[] = {CMD_RANDOM, 0x00, 0x00};
    uint8_t resp[33];
    int ret = ta100_cmd(cmd, 3, resp, 33);
    printf("[DEBUG] ta100_cmd returned %d\n", ret);
    if (ret < 0) return -1;
    if (resp[0] != 0x00) return -1;
    printf("  RNG: %02X%02X...%02X%02X\n", resp[1], resp[2], resp[31], resp[32]);
    return 0;
}

static int test_nonce(void) {
    printf("[TEST] NONCE (random)...\n");
    uint8_t cmd[] = {CMD_NONCE, 0x03, 0x00};
    uint8_t resp[1];
    if (ta100_cmd(cmd, 3, resp, 1) < 0) return -1;
    if (resp[0] != 0x00) return -1;
    printf("  OK\n");
    return 0;
}

static int test_genkey(void) {
    printf("[TEST] GENKEY slot 0...\n");
    uint8_t cmd[] = {CMD_GENKEY, 0x04, 0x00, 0x00};
    uint8_t resp[65];
    if (ta100_cmd(cmd, 4, resp, 65) < 0) return -1;
    if (resp[0] != 0x00) return -1;
    printf("  Pubkey: %02X%02X...%02X%02X\n", resp[1], resp[2], resp[63], resp[64]);
    return 0;
}

static int test_sign(void) {
    printf("[TEST] SIGN with slot 0...\n");
    uint8_t cmd[] = {CMD_SIGN, 0x80, 0x00, 0x00};
    uint8_t resp[65];
    if (ta100_cmd(cmd, 4, resp, 65) < 0) return -1;
    if (resp[0] != 0x00) return -1;
    printf("  Signature: %02X%02X...%02X%02X\n", resp[1], resp[2], resp[63], resp[64]);
    return 0;
}

static int test_sha256(void) {
    printf("[TEST] SHA256...\n");
    uint8_t data[32];
    memset(data, 0xAA, sizeof(data));
    uint8_t cmd[36] = {CMD_SHA256, 0x00, 0x00, 0x00, 0x20};
    memcpy(cmd + 5, data, 32);
    uint8_t resp[33];
    if (ta100_cmd(cmd, 37, resp, 33) < 0) return -1;
    if (resp[0] != 0x00) return -1;
    printf("  Hash: %02X%02X...%02X%02X\n", resp[1], resp[2], resp[31], resp[32]);
    return 0;
}

/* USART1 low-level output */
void usart1_putc(char c) {
    while (!(USART_ISR(USART1_BASE) & USART_ISR_TXE));
    USART_TDR(USART1_BASE) = (uint32_t)c;
}

/* Initialize USART1 (PA9=TX, PA10=RX, AF7) */
static void init_uart(void) {
    RCC_AHB2ENR1 |= (1u << 0); /* GPIOA clock */
    RCC_APB2ENR |= (1u << 14); /* USART1 clock */

    uint32_t v = GPIO_MODER(GPIOA_BASE);
    v &= ~((3u << (9 * 2)) | (3u << (10 * 2)));
    v |= (2u << (9 * 2)) | (2u << (10 * 2)); /* AF mode */
    GPIO_MODER(GPIOA_BASE) = v;

    v = GPIO_OSPEEDR(GPIOA_BASE);
    v &= ~((3u << (9 * 2)) | (3u << (10 * 2)));
    v |= (2u << (9 * 2)) | (2u << (10 * 2)); /* High speed */
    GPIO_OSPEEDR(GPIOA_BASE) = v;

    v = GPIO_AFRH(GPIOA_BASE);
    v &= ~((0xFu << ((9 - 8) * 4)) | (0xFu << ((10 - 8) * 4)));
    v |= (7u << ((9 - 8) * 4)) | (7u << ((10 - 8) * 4)); /* AF7 */
    GPIO_AFRH(GPIOA_BASE) = v;

    USART_BRR(USART1_BASE) = 64000000u / 115200u;
    USART_CR1(USART1_BASE) = USART_CR1_UE | USART_CR1_TE;
}

/* Initialize SPI2 (PB13=SCK, PB14=MISO, PB15=MOSI, PB5=CS) */
static void init_spi(void) {
    RCC_AHB2ENR1 |= (1u << 1); /* GPIOB clock */
    RCC_APB1ENR1 |= (1u << 14); /* SPI2 clock */

    /* CS: PB5 as GPIO output */
    uint32_t v = GPIO_MODER(GPIOB_BASE);
    v &= ~(3u << (5 * 2));
    v |= (1u << (5 * 2)); /* Output */
    GPIO_MODER(GPIOB_BASE) = v;
    cs_deassert();

    /* SPI pins: PB13/14/15 as AF5 */
    v = GPIO_MODER(GPIOB_BASE);
    v &= ~((3u << (13 * 2)) | (3u << (14 * 2)) | (3u << (15 * 2)));
    v |= (2u << (13 * 2)) | (2u << (14 * 2)) | (2u << (15 * 2));
    GPIO_MODER(GPIOB_BASE) = v;

    v = GPIO_AFRH(GPIOB_BASE);
    v &= ~((0xFu << ((13 - 8) * 4)) | (0xFu << ((14 - 8) * 4)) | (0xFu << ((15 - 8) * 4)));
    v |= (5u << ((13 - 8) * 4)) | (5u << ((14 - 8) * 4)) | (5u << ((15 - 8) * 4)); /* AF5 */
    GPIO_AFRH(GPIOB_BASE) = v;

    /* SPI2 config: master, 8-bit, software CS */
    SPI_CFG1(SPI2_BASE) = (7u << 28); /* MBR=7 (div 256) */
    SPI_CFG2(SPI2_BASE) = (1u << 22) | (1u << 26); /* Master mode, SSI=1 (software CS) */
    SPI_CR2(SPI2_BASE) = 1; /* TSIZE=1 (will update per transfer) */
    SPI_CR1(SPI2_BASE) = SPI_CR1_SPE;
}

void Reset_Handler(void) {
    uint32_t *src = &_sidata, *dst = &_sdata;
    while (dst < &_edata) *dst++ = *src++;
    for (dst = &_sbss; dst < &_ebss;) *dst++ = 0;
    __libc_init_array();

    init_uart();
    init_spi();

    printf("\n=== TA-100 Test Firmware ===\n");

    if (test_info() < 0) goto fail;
    if (test_read_config() < 0) goto fail;
    if (test_random() < 0) goto fail;
    if (test_nonce() < 0) goto fail;
    if (test_genkey() < 0) goto fail;
    if (test_sign() < 0) goto fail;
    if (test_sha256() < 0) goto fail;

    printf("\n[PASS] All tests passed!\n");
    __asm volatile("bkpt #0x7F");
    while (1);

fail:
    printf("\n[FAIL] Test failed\n");
    while (1);
}
