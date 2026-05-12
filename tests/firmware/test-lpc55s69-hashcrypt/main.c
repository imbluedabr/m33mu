/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * LPC55S69 HashCrypt test firmware.
 *
 * Tests:
 * 1. SHA-256("abc") — drives the full SHA-256 padded block through INDATA/ALIAS,
 *    reads DIGEST0..7 and compares to the known answer.
 *    Expected: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
 *
 * 2. AES-128-ECB encrypt — FIPS-197 Appendix B test vector.
 *    Key: 000102030405060708090a0b0c0d0e0f
 *    Plaintext: 00112233445566778899aabbccddeeff
 *    Expected ciphertext: 69c4e0d86a7b0430d8cdb78070b4c55a
 *
 * On pass: "HASHCRYPT TEST SUCCESSFUL\n" followed by bkpt #0x42.
 * On fail: failure detail then bkpt #0x77.
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
 * SYSCON — clock/reset for HashCrypt
 * AHBCLKCTRL2 (0x40000208): bit 18 = HashCrypt clock
 * PRESETCTRL2 (0x40000108): bit 18 = HashCrypt reset (0 = released)
 * Use SET/CLR register pairs.
 * ------------------------------------------------------------------------- */
#define SYSCON_BASE             0x40000000u
#define AHBCLKCTRLSET2          (*(volatile uint32_t *)(SYSCON_BASE + 0x228u))
#define PRESETCTRLCLR2          (*(volatile uint32_t *)(SYSCON_BASE + 0x148u))
#define HASHCRYPT_CLK_BIT       18u

/* -------------------------------------------------------------------------
 * FLEXCOMM0 USART — for printf output (same as test-lpc55s69)
 * ------------------------------------------------------------------------- */
#define AHBCLKCTRLSET1          (*(volatile uint32_t *)(SYSCON_BASE + 0x224u))
#define PRESETCTRLCLR1          (*(volatile uint32_t *)(SYSCON_BASE + 0x144u))
#define FC0_BASE                0x40086000u
#define FC0_PSELID              (*(volatile uint32_t *)(FC0_BASE + 0xFF8u))
#define FC0_CFG                 (*(volatile uint32_t *)(FC0_BASE + 0x000u))
#define FC0_FIFOCFG             (*(volatile uint32_t *)(FC0_BASE + 0xE00u))
#define FC0_FIFOSTAT            (*(volatile uint32_t *)(FC0_BASE + 0xE04u))
#define FC0_FIFOWR              (*(volatile uint32_t *)(FC0_BASE + 0xE20u))
#define FIFOSTAT_TXNOTFULL      (1u << 5)
#define CFG_ENABLE              (1u << 0)
#define CFG_DATALEN_8BIT        (1u << 2)
#define FIFOCFG_ENABLETX        (1u << 0)
#define FIFOCFG_ENABLERX        (1u << 1)
#define PSELID_PERSEL_USART     1u

/* -------------------------------------------------------------------------
 * HashCrypt — 0x400A4000 NS
 * ------------------------------------------------------------------------- */
#define HC_BASE                 0x400A4000u
#define HC_CTRL                 (*(volatile uint32_t *)(HC_BASE + 0x00u))
#define HC_STATUS               (*(volatile uint32_t *)(HC_BASE + 0x04u))
#define HC_INTENSET             (*(volatile uint32_t *)(HC_BASE + 0x08u))
#define HC_INDATA               (*(volatile uint32_t *)(HC_BASE + 0x20u))
#define HC_ALIAS0               (*(volatile uint32_t *)(HC_BASE + 0x24u))
#define HC_ALIAS1               (*(volatile uint32_t *)(HC_BASE + 0x28u))
#define HC_ALIAS2               (*(volatile uint32_t *)(HC_BASE + 0x2Cu))
#define HC_ALIAS3               (*(volatile uint32_t *)(HC_BASE + 0x30u))
#define HC_ALIAS4               (*(volatile uint32_t *)(HC_BASE + 0x34u))
#define HC_ALIAS5               (*(volatile uint32_t *)(HC_BASE + 0x38u))
#define HC_ALIAS6               (*(volatile uint32_t *)(HC_BASE + 0x3Cu))
#define HC_DIGEST0              (*(volatile uint32_t *)(HC_BASE + 0x40u))
#define HC_DIGEST1              (*(volatile uint32_t *)(HC_BASE + 0x44u))
#define HC_DIGEST2              (*(volatile uint32_t *)(HC_BASE + 0x48u))
#define HC_DIGEST3              (*(volatile uint32_t *)(HC_BASE + 0x4Cu))
#define HC_DIGEST4              (*(volatile uint32_t *)(HC_BASE + 0x50u))
#define HC_DIGEST5              (*(volatile uint32_t *)(HC_BASE + 0x54u))
#define HC_DIGEST6              (*(volatile uint32_t *)(HC_BASE + 0x58u))
#define HC_DIGEST7              (*(volatile uint32_t *)(HC_BASE + 0x5Cu))
#define HC_CRYPTCFG             (*(volatile uint32_t *)(HC_BASE + 0x80u))

/* CTRL bits */
#define CTRL_MODE_SHA256        (2u << 0)
#define CTRL_MODE_AES           (4u << 0)
#define CTRL_NEW_HASH           (1u << 4)

/* STATUS bits */
#define STATUS_WAITING          (1u << 0)
#define STATUS_DIGEST           (1u << 1)
#define STATUS_NEEDKEY          (1u << 4)
#define STATUS_NEEDIV           (1u << 5)

/* CRYPTCFG bits */
#define CRYPTCFG_AESMODE_ECB    (0u << 4)  /* ECB */
#define CRYPTCFG_AESMODE_CBC    (1u << 4)  /* CBC */
#define CRYPTCFG_AESMODE_CTR    (2u << 4)  /* CTR */
#define CRYPTCFG_AESDECRYPT     (1u << 6)
#define CRYPTCFG_AESKEYSZ_128   (0u << 8)
#define CRYPTCFG_AESKEYSZ_192   (1u << 8)
#define CRYPTCFG_AESKEYSZ_256   (2u << 8)

/* -------------------------------------------------------------------------
 * UART
 * ------------------------------------------------------------------------- */
static void uart_init(void)
{
    AHBCLKCTRLSET1 = (1u << 11u);   /* FC0 clock */
    PRESETCTRLCLR1 = (1u << 11u);   /* FC0 reset release */
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
 * HashCrypt clock enable
 * ------------------------------------------------------------------------- */
static void hashcrypt_clock_enable(void)
{
    AHBCLKCTRLSET2 = (1u << HASHCRYPT_CLK_BIT);
    PRESETCTRLCLR2 = (1u << HASHCRYPT_CLK_BIT);
}

/* -------------------------------------------------------------------------
 * Wait for STATUS bit
 * ------------------------------------------------------------------------- */
static void hc_wait_status(uint32_t bit)
{
    uint32_t timeout = 0xFFFFu;
    while (((HC_STATUS & bit) == 0u) && (--timeout != 0u)) { }
}

/* -------------------------------------------------------------------------
 * Write 16 words (one SHA block) via INDATA + ALIAS[0..6].
 * The HashCrypt accepts 8-word bursts (INDATA + 7 ALIAS).
 * After the first 8 words, we wait for WAITING before sending the next 8.
 * ------------------------------------------------------------------------- */
static void hc_write_sha_block(const uint32_t *words)
{
    /* First 8 words */
    HC_INDATA  = words[0];
    HC_ALIAS0  = words[1];
    HC_ALIAS1  = words[2];
    HC_ALIAS2  = words[3];
    HC_ALIAS3  = words[4];
    HC_ALIAS4  = words[5];
    HC_ALIAS5  = words[6];
    HC_ALIAS6  = words[7];
    /* Second 8 words */
    HC_INDATA  = words[8];
    HC_ALIAS0  = words[9];
    HC_ALIAS1  = words[10];
    HC_ALIAS2  = words[11];
    HC_ALIAS3  = words[12];
    HC_ALIAS4  = words[13];
    HC_ALIAS5  = words[14];
    HC_ALIAS6  = words[15];
}

/* -------------------------------------------------------------------------
 * SHA-256 test
 *
 * Input: "abc" (3 bytes).
 * The SHA-256 padded block (64 bytes = 16 words) for "abc":
 *   Bytes: 61 62 63 80 00 ... 00 00 00 00 00 00 00 18
 *   As 16 big-endian 32-bit words: 0x61626380 0x00 ... 0x00 0x18
 *
 * For ARM LE, each word is written in little-endian:
 *   Word0 (BE 0x61626380) = ARM writes 0x80636261
 *   The hardware byte-swaps internally for SHA.
 * ------------------------------------------------------------------------- */
static int test_sha256(void)
{
    /* SHA-256 padded block for "abc" — words in LE format for ARM.
     * Each word is the byte-reversal of the corresponding SHA-256 spec word.
     * Spec word 0: 0x61626380 → ARM LE word: 0x80636261
     * Spec word 15 (length, big-endian): 0x00000018 → ARM LE word: 0x18000000 */
    static const uint32_t block[16] = {
        0x80636261u,  /* "abc\x80" in LE */
        0x00000000u, 0x00000000u, 0x00000000u,
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
        0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
        0x00000000u, 0x00000000u, 0x00000000u,
        0x18000000u   /* bit-length = 24, big-endian in spec → LE 0x18000000 */
    };

    /* Expected SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
     * As 8 big-endian 32-bit words: */
    static const uint32_t expected[8] = {
        0xba7816bfu, 0x8f01cfeau, 0x414140deu, 0x5dae2223u,
        0xb00361a3u, 0x96177a9cu, 0xb410ff61u, 0xf20015adu
    };

    uint32_t digest[8];
    int ok = 1;
    int i;

    /* Start SHA-256 */
    HC_CTRL = CTRL_MODE_SHA256 | CTRL_NEW_HASH;

    /* Wait for WAITING (ready to accept data) */
    hc_wait_status(STATUS_WAITING);

    /* Write the padded block */
    hc_write_sha_block(block);

    /* Read DIGEST0 to trigger finalization */
    digest[0] = HC_DIGEST0;
    digest[1] = HC_DIGEST1;
    digest[2] = HC_DIGEST2;
    digest[3] = HC_DIGEST3;
    digest[4] = HC_DIGEST4;
    digest[5] = HC_DIGEST5;
    digest[6] = HC_DIGEST6;
    digest[7] = HC_DIGEST7;

    /* Compare */
    for (i = 0; i < 8; ++i) {
        if (digest[i] != expected[i]) {
            ok = 0;
        }
    }

    if (!ok) {
        printf("SHA-256 FAIL\n  got:      ");
        for (i = 0; i < 8; ++i) printf("%08lx", (unsigned long)digest[i]);
        printf("\n  expected: ");
        for (i = 0; i < 8; ++i) printf("%08lx", (unsigned long)expected[i]);
        printf("\n");
    } else {
        printf("SHA-256(abc): PASS\n");
    }
    return ok;
}

/* -------------------------------------------------------------------------
 * AES-128-ECB encrypt test (FIPS-197 Appendix B)
 *
 * Key:       000102030405060708090a0b0c0d0e0f
 * Plaintext: 00112233445566778899aabbccddeeff
 * Expected:  69c4e0d86a7b0430d8cdb78070b4c55a
 *
 * Firmware writes key then plaintext via INDATA/ALIAS.
 * Key words (LE from bytes): word0=0x03020100, word1=0x07060504,
 *                             word2=0x0b0a0908, word3=0x0f0e0d0c
 * Plaintext words (LE):      word0=0x33221100, word1=0x77665544,
 *                             word2=0xbbaa9988, word3=0xffeeddcc
 * Expected ciphertext (LE):  word0=0xd8e0c469, word1=0x307b4a6b... wait
 * Let's compute: expected bytes: 69 c4 e0 d8 6a 7b 04 30 d8 cd b7 80 70 b4 c5 5a
 * As LE 32-bit words: 0xd8e0c469, 0x30047b6a, 0x80b7cdd8, 0x5ac5b470
 * ------------------------------------------------------------------------- */
static int test_aes128_ecb(void)
{
    /* Key words in LE (bytes 00,01,02,03 → word 0x03020100) */
    static const uint32_t key[4] = {
        0x03020100u, 0x07060504u, 0x0b0a0908u, 0x0f0e0d0cu
    };
    /* Plaintext words in LE */
    static const uint32_t plaintext[4] = {
        0x33221100u, 0x77665544u, 0xbbaa9988u, 0xffeeddccu
    };
    /* Expected ciphertext words in LE */
    static const uint32_t expected[4] = {
        0xd8e0c469u, 0x30047b6au, 0x80b7cdd8u, 0x5ac5b470u
    };
    uint32_t ciphertext[4];
    int ok = 1;
    int i;

    /* Configure AES-128-ECB encrypt */
    HC_CRYPTCFG = CRYPTCFG_AESMODE_ECB | CRYPTCFG_AESKEYSZ_128;
    /* Start AES */
    HC_CTRL = CTRL_MODE_AES | CTRL_NEW_HASH;

    /* Wait for NEEDKEY */
    hc_wait_status(STATUS_NEEDKEY);

    /* Write key (4 words via INDATA + ALIAS[0..2]) */
    HC_INDATA = key[0];
    HC_ALIAS0 = key[1];
    HC_ALIAS1 = key[2];
    HC_ALIAS2 = key[3];

    /* Wait for WAITING (key accepted, ready for data) */
    hc_wait_status(STATUS_WAITING);

    /* Write plaintext (4 words) */
    HC_INDATA = plaintext[0];
    HC_ALIAS0 = plaintext[1];
    HC_ALIAS1 = plaintext[2];
    HC_ALIAS2 = plaintext[3];

    /* Wait for DIGEST (output ready) */
    hc_wait_status(STATUS_DIGEST);

    /* Read ciphertext from DIGEST0..3 */
    ciphertext[0] = HC_DIGEST0;
    ciphertext[1] = HC_DIGEST1;
    ciphertext[2] = HC_DIGEST2;
    ciphertext[3] = HC_DIGEST3;

    /* Compare */
    for (i = 0; i < 4; ++i) {
        if (ciphertext[i] != expected[i]) {
            ok = 0;
        }
    }

    if (!ok) {
        printf("AES-128-ECB FAIL\n  got:      ");
        for (i = 0; i < 4; ++i) printf("%08lx", (unsigned long)ciphertext[i]);
        printf("\n  expected: ");
        for (i = 0; i < 4; ++i) printf("%08lx", (unsigned long)expected[i]);
        printf("\n");
    } else {
        printf("AES-128-ECB: PASS\n");
    }
    return ok;
}

/* -------------------------------------------------------------------------
 * Main
 * ------------------------------------------------------------------------- */
int main(void)
{
    int all_pass = 1;

    uart_init();
    hashcrypt_clock_enable();

    printf("=== LPC55S69 HashCrypt test ===\n");

    all_pass &= test_sha256();
    all_pass &= test_aes128_ecb();

    if (all_pass) {
        printf("HASHCRYPT TEST SUCCESSFUL\n");
        __asm volatile("bkpt #0x42");
    } else {
        printf("HASHCRYPT TEST FAILED\n");
        __asm volatile("bkpt #0x77");
    }
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
    printf("HARDFAULT\n");
    __asm volatile("bkpt #0x7e");
    while (1) { }
}
