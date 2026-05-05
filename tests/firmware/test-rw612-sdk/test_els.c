/* m33mu -- RW612 ELS test (AES-CBC, SHA-256, HMAC-SHA256, RNG).
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * All inputs/outputs flow through the 4 KB PKA scratch RAM at 0x22040000.
 * Test firmware writes operands at chosen offsets, programs ELS source /
 * destination registers, writes CMD, polls STATUS, reads results.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* ---- ELS / PKA RAM register map (matches cpu/rw612/rw612_secure.c) ---- */
#define ELS_BASE          0x4002F000u
#define PKA_RAM_BASE      0x22040000u

#define ELS_REG(o)        (*(volatile uint32_t *)(ELS_BASE + (o)))
#define ELS_CMD           ELS_REG(0x000u)
#define ELS_STATUS        ELS_REG(0x004u)
#define ELS_INPUT_OFF     ELS_REG(0x010u)
#define ELS_INPUT_LEN     ELS_REG(0x014u)
#define ELS_OUTPUT_OFF    ELS_REG(0x018u)
#define ELS_OUTPUT_LEN    ELS_REG(0x01Cu)
#define ELS_KEY_OFF       ELS_REG(0x020u)
#define ELS_KEY_LEN       ELS_REG(0x024u)
#define ELS_IV_OFF        ELS_REG(0x028u)
#define ELS_IV_LEN        ELS_REG(0x02Cu)
#define ELS_RESULT(i)     ELS_REG(0x040u + (i) * 4u)

#define ELS_STATUS_BUSY   (1u << 0)
#define ELS_STATUS_DONE   (1u << 1)
#define ELS_STATUS_ERROR  (1u << 2)

#define CMD_AES_CBC_ENC   0x03u
#define CMD_AES_CBC_DEC   0x04u
#define CMD_SHA256        0x10u
#define CMD_HMAC_SHA256   0x11u
#define CMD_RNG           0x20u

#define PKA_OFF_IN        0x000u   /* input message buffer */
#define PKA_OFF_OUT       0x100u   /* output buffer        */
#define PKA_OFF_KEY       0x200u   /* key                  */
#define PKA_OFF_IV        0x240u   /* IV / nonce           */

static volatile uint8_t * const pka_ram = (volatile uint8_t *)PKA_RAM_BASE;

static int els_run(uint32_t cmd)
{
    /* Clear DONE/ERROR latch from any previous op. */
    ELS_STATUS = ELS_STATUS_DONE | ELS_STATUS_ERROR;
    ELS_CMD = cmd;
    /* Engine completes synchronously in the emulator; the BUSY bit is
     * asserted then immediately replaced by DONE/ERROR.  Spin until DONE
     * with a generous bound. */
    for (int i = 0; i < 100000; ++i) {
        uint32_t s = ELS_STATUS;
        if (s & ELS_STATUS_ERROR) return 0;
        if (s & ELS_STATUS_DONE) return 1;
    }
    return 0;
}

static void pka_write(uint32_t off, const void *src, uint32_t len)
{
    const uint8_t *p = (const uint8_t *)src;
    for (uint32_t i = 0; i < len; ++i) pka_ram[off + i] = p[i];
}

static void pka_read(uint32_t off, void *dst, uint32_t len)
{
    uint8_t *p = (uint8_t *)dst;
    for (uint32_t i = 0; i < len; ++i) p[i] = pka_ram[off + i];
}

static int hex_eq(const uint8_t *a, const uint8_t *b, uint32_t len, const char *name)
{
    int ok = (memcmp(a, b, len) == 0);
    printf("%s: %s\n", name, ok ? "PASS" : "FAIL");
    if (!ok) {
        printf("  got: ");
        for (uint32_t i = 0; i < len && i < 32u; ++i) printf("%02x", a[i]);
        printf("\n  exp: ");
        for (uint32_t i = 0; i < len && i < 32u; ++i) printf("%02x", b[i]);
        printf("\n");
    }
    return ok;
}

/* NIST SP 800-38A AES-128-CBC test vector */
static const uint8_t aes_key[16] = {
    0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
    0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
};
static const uint8_t aes_iv[16] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};
static const uint8_t aes_pt[16] = {
    0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
    0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
};
static const uint8_t aes_ct[16] = {
    0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,
    0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d
};

/* FIPS-180 SHA-256("abc") */
static const uint8_t sha_in[]    = "abc";
static const uint8_t sha_expect[32] = {
    0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
    0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
    0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
    0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
};

/* RFC 4231 HMAC-SHA256 test case 1 */
static const uint8_t hmac_key[20] = {
    0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
    0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
    0x0b,0x0b,0x0b,0x0b
};
static const uint8_t hmac_msg[]  = "Hi There";
static const uint8_t hmac_expect[32] = {
    0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,
    0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b,
    0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,
    0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7
};

static int test_aes_cbc(void)
{
    uint8_t out_ct[16];
    uint8_t out_pt[16];
    int pass = 1;

    pka_write(PKA_OFF_KEY, aes_key, 16);
    pka_write(PKA_OFF_IV,  aes_iv,  16);
    pka_write(PKA_OFF_IN,  aes_pt,  16);
    ELS_KEY_OFF    = PKA_OFF_KEY;
    ELS_KEY_LEN    = 16u;
    ELS_IV_OFF     = PKA_OFF_IV;
    ELS_IV_LEN     = 16u;
    ELS_INPUT_OFF  = PKA_OFF_IN;
    ELS_INPUT_LEN  = 16u;
    ELS_OUTPUT_OFF = PKA_OFF_OUT;
    ELS_OUTPUT_LEN = 16u;
    if (!els_run(CMD_AES_CBC_ENC)) {
        printf("aes-cbc-enc: FAIL (status=0x%lx)\n", (unsigned long)ELS_STATUS);
        return 0;
    }
    pka_read(PKA_OFF_OUT, out_ct, 16);
    pass &= hex_eq(out_ct, aes_ct, 16, "aes-cbc-enc");

    /* Decrypt back: reload key/iv (CBC state is per-call) */
    pka_write(PKA_OFF_KEY, aes_key, 16);
    pka_write(PKA_OFF_IV,  aes_iv,  16);
    pka_write(PKA_OFF_IN,  aes_ct, 16);
    ELS_KEY_OFF    = PKA_OFF_KEY;
    ELS_KEY_LEN    = 16u;
    ELS_IV_OFF     = PKA_OFF_IV;
    ELS_IV_LEN     = 16u;
    ELS_INPUT_OFF  = PKA_OFF_IN;
    ELS_INPUT_LEN  = 16u;
    ELS_OUTPUT_OFF = PKA_OFF_OUT;
    ELS_OUTPUT_LEN = 16u;
    if (!els_run(CMD_AES_CBC_DEC)) {
        printf("aes-cbc-dec: FAIL (status=0x%lx)\n", (unsigned long)ELS_STATUS);
        return 0;
    }
    pka_read(PKA_OFF_OUT, out_pt, 16);
    pass &= hex_eq(out_pt, aes_pt, 16, "aes-cbc-dec");
    return pass;
}

static int test_sha256(void)
{
    uint8_t out[32];
    pka_write(PKA_OFF_IN, sha_in, 3);
    ELS_INPUT_OFF  = PKA_OFF_IN;
    ELS_INPUT_LEN  = 3u;
    ELS_OUTPUT_OFF = PKA_OFF_OUT;
    ELS_OUTPUT_LEN = 32u;
    if (!els_run(CMD_SHA256)) {
        printf("sha256(abc): FAIL (status=0x%lx)\n", (unsigned long)ELS_STATUS);
        return 0;
    }
    pka_read(PKA_OFF_OUT, out, 32);
    return hex_eq(out, sha_expect, 32, "sha256(abc)");
}

static int test_hmac_sha256(void)
{
    uint8_t out[32];
    pka_write(PKA_OFF_KEY, hmac_key, 20);
    pka_write(PKA_OFF_IN,  hmac_msg, 8);
    ELS_KEY_OFF    = PKA_OFF_KEY;
    ELS_KEY_LEN    = 20u;
    ELS_INPUT_OFF  = PKA_OFF_IN;
    ELS_INPUT_LEN  = 8u;
    ELS_OUTPUT_OFF = PKA_OFF_OUT;
    ELS_OUTPUT_LEN = 32u;
    if (!els_run(CMD_HMAC_SHA256)) {
        printf("hmac-sha256: FAIL (status=0x%lx)\n", (unsigned long)ELS_STATUS);
        return 0;
    }
    pka_read(PKA_OFF_OUT, out, 32);
    return hex_eq(out, hmac_expect, 32, "hmac-sha256");
}

static int test_rng(void)
{
    uint8_t out[32];
    int nonzero = 0;
    ELS_OUTPUT_OFF = PKA_OFF_OUT;
    ELS_OUTPUT_LEN = 32u;
    if (!els_run(CMD_RNG)) {
        printf("rng: FAIL (status=0x%lx)\n", (unsigned long)ELS_STATUS);
        return 0;
    }
    pka_read(PKA_OFF_OUT, out, 32);
    for (int i = 0; i < 32; ++i) if (out[i] != 0u) ++nonzero;
    printf("rng: %s (%d/32 non-zero)\n", nonzero >= 16 ? "PASS" : "FAIL", nonzero);
    return nonzero >= 16;
}

int main(void)
{
    int all = 1;
    printf("=== RW612 ELS test ===\n");
    all &= test_aes_cbc();
    all &= test_sha256();
    all &= test_hmac_sha256();
    all &= test_rng();
    printf("=== %s ===\n", all ? "ALL PASS" : "SOME FAIL");
    return all ? 0 : 1;
}
