/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * nRF5340 CryptoCell-312 direct-register firmware test.
 *
 * This test uses the simplified register interface implemented by the m33mu
 * CC-312 peripheral model. The register layout follows nrf5340_application.h
 * but the triggering mechanism (SRC_MEM_SIZE write = DMA trigger) is a
 * simplified version of the real CC-312 flow.
 *
 * TODO: align with real CC-312 nrfx driver for complete silicon fidelity.
 *       This test exercises the emulator model only.
 *
 * Two operations:
 *  1. SHA-256 of "abc" (3 bytes) -> expected digest ba7816bf...
 *  2. AES-128-CBC encrypt of FIPS-197 test vector -> expected ciphertext
 *
 * Register bases (all secure addresses — firmware runs in Secure state):
 *   CRYPTOCELL:  0x50844000 (ENABLE @ +0x500)
 *   CC engine:   0x50845000 (AES, HASH, DIN, DOUT, CTL, HOST_RGF)
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>

/* -------------------------------------------------------------------------
 * UARTE1 (for printf via syscalls.c)
 * ------------------------------------------------------------------------- */
#define UARTE1_BASE             0x40009000u
#define UARTE_TASKS_STARTTX(b)  (*(volatile uint32_t *)((b) + 0x008u))
#define UARTE_EVENTS_ENDTX(b)   (*(volatile uint32_t *)((b) + 0x120u))
#define UARTE_ENABLE(b)         (*(volatile uint32_t *)((b) + 0x500u))
#define UARTE_TXD_PTR(b)        (*(volatile uint32_t *)((b) + 0x544u))
#define UARTE_TXD_MAXCNT(b)     (*(volatile uint32_t *)((b) + 0x548u))

static volatile uint8_t uarte1_txbuf;

void uarte1_putc(char c)
{
    uarte1_txbuf = (uint8_t)c;
    UARTE_TXD_PTR(UARTE1_BASE) = (uint32_t)&uarte1_txbuf;
    UARTE_TXD_MAXCNT(UARTE1_BASE) = 1u;
    UARTE_EVENTS_ENDTX(UARTE1_BASE) = 0u;
    UARTE_TASKS_STARTTX(UARTE1_BASE) = 1u;
    while (UARTE_EVENTS_ENDTX(UARTE1_BASE) == 0u) {
    }
}

static void uarte1_init(void)
{
    UARTE_ENABLE(UARTE1_BASE) = 8u;
}

/* -------------------------------------------------------------------------
 * CryptoCell-312 register map
 * Base 0x50844000: CRYPTOCELL control (ENABLE @ 0x500)
 * Base 0x50845000: CC engine registers
 * ------------------------------------------------------------------------- */
#define CC_CTRL_BASE    0x50844000u
#define CC_ENGINE_BASE  0x50845000u

/* CRYPTOCELL control region */
#define CC_ENABLE       (*(volatile uint32_t *)(CC_CTRL_BASE + 0x500u))

/* AES engine (all at CC_ENGINE_BASE + offset) */
#define AES_KEY_0(n)    (*(volatile uint32_t *)(CC_ENGINE_BASE + 0x400u + (n)*4u))
#define AES_IV_0(n)     (*(volatile uint32_t *)(CC_ENGINE_BASE + 0x440u + (n)*4u))
#define AES_REMAINING   (*(volatile uint32_t *)(CC_ENGINE_BASE + 0x4BCu))
#define AES_CONTROL     (*(volatile uint32_t *)(CC_ENGINE_BASE + 0x4C0u))
#define AES_BUSY        (*(volatile uint32_t *)(CC_ENGINE_BASE + 0x470u))

/* AES_CONTROL bits */
#define AES_CTRL_CBC        1u      /* [2:0] mode: CBC */
#define AES_CTRL_DECRYPT    (1u<<3) /* direction: decrypt */
#define AES_CTRL_KEY128     (0u<<4) /* [5:4] key size: 128 */

/* HASH engine */
#define HASH_H(n)       (*(volatile uint32_t *)(CC_ENGINE_BASE + 0x640u + (n)*4u))
#define HASH_PAD_AUTO   (*(volatile uint32_t *)(CC_ENGINE_BASE + 0x684u))
#define HASH_INIT_STATE (*(volatile uint32_t *)(CC_ENGINE_BASE + 0x694u))
#define HASH_CONTROL    (*(volatile uint32_t *)(CC_ENGINE_BASE + 0x7C0u))
#define HASH_PAD        (*(volatile uint32_t *)(CC_ENGINE_BASE + 0x7C4u))
#define HASH_CUR_LEN_0  (*(volatile uint32_t *)(CC_ENGINE_BASE + 0x7CCu))
#define HASH_CUR_LEN_1  (*(volatile uint32_t *)(CC_ENGINE_BASE + 0x7D0u))
#define HASH_SW_RESET   (*(volatile uint32_t *)(CC_ENGINE_BASE + 0x7E4u))

/* HASH_CONTROL mode values */
#define HASH_MODE_SHA256    3u

/* CTL */
#define CRYPTO_CTL      (*(volatile uint32_t *)(CC_ENGINE_BASE + 0x900u))

/* DIN DMA */
#define DIN_SRC_MEM_ADDR (*(volatile uint32_t *)(CC_ENGINE_BASE + 0xC28u))
#define DIN_SRC_MEM_SIZE (*(volatile uint32_t *)(CC_ENGINE_BASE + 0xC2Cu))  /* write triggers */
#define DIN_SW_RESET     (*(volatile uint32_t *)(CC_ENGINE_BASE + 0xC44u))

/* DOUT DMA */
#define DOUT_DST_MEM_ADDR (*(volatile uint32_t *)(CC_ENGINE_BASE + 0xD28u))
#define DOUT_DST_MEM_SIZE (*(volatile uint32_t *)(CC_ENGINE_BASE + 0xD2Cu))
#define DOUT_SW_RESET     (*(volatile uint32_t *)(CC_ENGINE_BASE + 0xD58u))

/* HOST_RGF */
#define HOST_IRR        (*(volatile uint32_t *)(CC_ENGINE_BASE + 0xA00u))
#define HOST_IMR        (*(volatile uint32_t *)(CC_ENGINE_BASE + 0xA04u))
#define HOST_ICR        (*(volatile uint32_t *)(CC_ENGINE_BASE + 0xA08u))
#define HOST_SIGNATURE  (*(volatile uint32_t *)(CC_ENGINE_BASE + 0xA24u))
#define HOST_CC_IS_IDLE (*(volatile uint32_t *)(CC_ENGINE_BASE + 0xA7Cu))

/* IRR bits */
#define IRR_AXIM_COMP       (1u << 0)
#define IRR_AES_COMPLETE    (1u << 1)
#define IRR_HASH_COMPLETE   (1u << 2)
#define IRR_ERROR           (1u << 9)
#define IRR_DONE_MASK       (IRR_AXIM_COMP | IRR_AES_COMPLETE | IRR_HASH_COMPLETE | IRR_ERROR)

/* -------------------------------------------------------------------------
 * Wait for operation completion (poll IRR)
 * Returns 1 on success, 0 on error or timeout.
 * ------------------------------------------------------------------------- */
static int cc312_wait_done(void)
{
    volatile int limit = 1000000;
    uint32_t irr;
    while (limit-- > 0) {
        irr = HOST_IRR;
        if ((irr & IRR_ERROR) != 0u) {
            printf("[CC312] ERROR: IRR=0x%08lx\n", (unsigned long)irr);
            HOST_ICR = irr; /* clear */
            return 0;
        }
        if ((irr & IRR_DONE_MASK) != 0u) {
            HOST_ICR = irr; /* clear */
            return 1;
        }
    }
    printf("[CC312] TIMEOUT: IRR=0x%08lx\n", (unsigned long)HOST_IRR);
    return 0;
}

/* -------------------------------------------------------------------------
 * Test 1: SHA-256("abc") = ba7816bf 8f01cfea 414140de 5dae2ec7
 *                          3b338c13 7a9dd80c 08ec99b8 f66af7f0
 * ------------------------------------------------------------------------- */
static const uint8_t sha256_input[] = { 'a', 'b', 'c' };
/* SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
 * Verified with: python3 -c "import hashlib; print(hashlib.sha256(b'abc').hexdigest())" */
static const uint8_t sha256_expected[32] = {
    0xba, 0x78, 0x16, 0xbf,
    0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde,
    0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3,
    0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61,
    0xf2, 0x00, 0x15, 0xad
};

/* Output buffer in RAM (aligned) */
static uint8_t sha256_output[32] __attribute__((aligned(4)));

static int test_sha256(void)
{
    uint8_t digest[32];
    uint32_t w;
    int i;

    printf("SHA-256 test: input=\"abc\" (3 bytes)\n");

    /* Reset HASH engine */
    HASH_SW_RESET = 1u;

    /* Configure HASH mode: SHA-256 */
    HASH_CONTROL = HASH_MODE_SHA256;

    /* Enable hardware padding */
    HASH_PAD = 1u;
    HASH_PAD_AUTO = 1u;

    /* Set message length */
    HASH_CUR_LEN_0 = (uint32_t)sizeof(sha256_input);
    HASH_CUR_LEN_1 = 0u;

    /* Initialize state */
    HASH_INIT_STATE = 1u;

    /* Set up DIN DMA: source = sha256_input, trigger on size write */
    DIN_SRC_MEM_ADDR = (uint32_t)sha256_input;

    /* Point DST to our output buffer so result is also written to RAM */
    DOUT_DST_MEM_ADDR = (uint32_t)sha256_output;
    DOUT_DST_MEM_SIZE = 32u;

    /* Unmask HASH_COMPLETE + AXIM_COMP in IMR (0 = unmasked) */
    HOST_IMR = ~(uint32_t)(IRR_HASH_COMPLETE | IRR_AXIM_COMP | IRR_ERROR);

    /* Clear any stale IRR */
    HOST_ICR = 0xFFFFFFFFu;

    /* Write SRC_MEM_SIZE to trigger the operation */
    DIN_SRC_MEM_SIZE = (uint32_t)sizeof(sha256_input);

    if (!cc312_wait_done()) {
        printf("FAIL: SHA-256 did not complete\n");
        return 0;
    }

    /* Read HASH_H[0..7] (big-endian words) */
    for (i = 0; i < 8; ++i) {
        w = HASH_H(i);
        digest[i * 4 + 0] = (uint8_t)((w >> 24) & 0xffu);
        digest[i * 4 + 1] = (uint8_t)((w >> 16) & 0xffu);
        digest[i * 4 + 2] = (uint8_t)((w >>  8) & 0xffu);
        digest[i * 4 + 3] = (uint8_t)((w      ) & 0xffu);
    }

    printf("SHA-256 result: ");
    for (i = 0; i < 32; ++i) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    if (memcmp(digest, sha256_expected, 32) != 0) {
        printf("FAIL: SHA-256 mismatch\n");
        return 0;
    }

    printf("SHA-256 PASS\n");
    return 1;
}

/* -------------------------------------------------------------------------
 * Test 2: AES-128-CBC encrypt
 * FIPS-197 Appendix B example (AES-128-ECB: key=2b7e..., plain=3243...).
 * We adapt to CBC mode with IV=0.
 *
 * Key:       2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
 * IV:        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 * Plaintext: 32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34
 * Expected ciphertext (CBC with zero IV = ECB for single block):
 *            39 25 84 1d 02 dc 09 fb dc 11 85 97 19 6a 0b 32
 * ------------------------------------------------------------------------- */
static const uint8_t aes_key[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};
static const uint8_t aes_iv[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const uint8_t aes_plaintext[16] = {
    0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
    0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
};
static const uint8_t aes_expected[16] = {
    0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
    0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32
};

/* AES output buffer */
static uint8_t aes_output[16] __attribute__((aligned(4)));

static int test_aes_cbc(void)
{
    uint32_t w;
    int i;

    printf("AES-128-CBC test: encrypt 16 bytes with zero IV\n");

    /* Write key words (little-endian: each 4-byte word with LSB first) */
    for (i = 0; i < 4; ++i) {
        w = (uint32_t)aes_key[i*4 + 0] |
            ((uint32_t)aes_key[i*4 + 1] << 8) |
            ((uint32_t)aes_key[i*4 + 2] << 16) |
            ((uint32_t)aes_key[i*4 + 3] << 24);
        AES_KEY_0(i) = w;
    }

    /* Write IV words */
    for (i = 0; i < 4; ++i) {
        w = (uint32_t)aes_iv[i*4 + 0] |
            ((uint32_t)aes_iv[i*4 + 1] << 8) |
            ((uint32_t)aes_iv[i*4 + 2] << 16) |
            ((uint32_t)aes_iv[i*4 + 3] << 24);
        AES_IV_0(i) = w;
    }

    /* Configure AES: CBC mode, encrypt, 128-bit key */
    AES_CONTROL = AES_CTRL_CBC | AES_CTRL_KEY128;
    AES_REMAINING = 16u;

    /* HASH_CONTROL = 0 to select AES path */
    HASH_CONTROL = 0u;

    /* Set up DMA */
    DIN_SRC_MEM_ADDR = (uint32_t)aes_plaintext;
    DOUT_DST_MEM_ADDR = (uint32_t)aes_output;
    DOUT_DST_MEM_SIZE = 16u;

    /* Unmask AES_COMPLETE + AXIM_COMP */
    HOST_IMR = ~(uint32_t)(IRR_AES_COMPLETE | IRR_AXIM_COMP | IRR_ERROR);

    /* Clear stale IRR */
    HOST_ICR = 0xFFFFFFFFu;

    /* Trigger */
    DIN_SRC_MEM_SIZE = 16u;

    if (!cc312_wait_done()) {
        printf("FAIL: AES-128-CBC did not complete\n");
        return 0;
    }

    printf("AES-128-CBC ciphertext: ");
    for (i = 0; i < 16; ++i) {
        printf("%02x", aes_output[i]);
    }
    printf("\n");

    if (memcmp(aes_output, aes_expected, 16) != 0) {
        printf("FAIL: AES-128-CBC mismatch\n");
        printf("Expected:               ");
        for (i = 0; i < 16; ++i) {
            printf("%02x", aes_expected[i]);
        }
        printf("\n");
        return 0;
    }

    printf("AES-128-CBC PASS\n");
    return 1;
}

/* -------------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------------- */
int main(void)
{
    int ok = 1;

    uarte1_init();

    printf("nRF5340 CryptoCell-312 test start\n");

    /* Enable CryptoCell subsystem */
    CC_ENABLE = 1u;

    /* Verify signature */
    {
        uint32_t sig = HOST_SIGNATURE;
        printf("CC-312 signature: 0x%08lx\n", (unsigned long)sig);
        if (sig != 0xDCC63116u) {
            printf("FAIL: unexpected CC-312 signature\n");
            ok = 0;
        }
    }

    if (ok) {
        ok = test_sha256();
    }

    if (ok) {
        /* Reset state between tests */
        HOST_ICR = 0xFFFFFFFFu;
        DIN_SW_RESET = 1u;
        DOUT_SW_RESET = 1u;
        ok = test_aes_cbc();
    }

    if (ok) {
        printf("CRYPTOCELL TEST SUCCESSFUL\n");
        __asm volatile("bkpt #0x42");
    } else {
        printf("CRYPTOCELL TEST FAILED\n");
        __asm volatile("bkpt #0x01");
    }

    while (1) {
        __asm volatile("wfi");
    }
}

extern uint32_t _sidata;
extern uint32_t _sdata;
extern uint32_t _edata;
extern uint32_t _sbss;
extern uint32_t _ebss;
extern uint32_t _estack;
extern void __libc_init_array(void);

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
    printf("HardFault!\n");
    __asm volatile("bkpt #0x7e");
    while (1) {
    }
}
