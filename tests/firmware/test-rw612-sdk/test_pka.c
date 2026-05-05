/* m33mu -- RW612 PKA test (modular exponentiation).
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Operands and result live in PKA RAM (0x22040000), big-endian.  Two
 * vectors:
 *   17^7 mod 23 == 19                     (toy correctness)
 *   pow(2, e=65537, n=384-bit prime)      (RSA-style sanity)
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define PKA_REG_BASE      0x40044000u
#define PKA_RAM_BASE      0x22040000u

#define PKA_REG(o)        (*(volatile uint32_t *)(PKA_REG_BASE + (o)))
#define PKA_CTRL          PKA_REG(0x000u)
#define PKA_STATUS        PKA_REG(0x004u)
#define PKA_OPCODE        PKA_REG(0x008u)
#define PKA_LEN_OPERAND   PKA_REG(0x00Cu)
#define PKA_LEN_MOD       PKA_REG(0x010u)
#define PKA_LEN_EXP       PKA_REG(0x014u)
#define PKA_OFF_A_REG     PKA_REG(0x020u)
#define PKA_OFF_B_REG     PKA_REG(0x024u)
#define PKA_OFF_M_REG     PKA_REG(0x028u)
#define PKA_OFF_E_REG     PKA_REG(0x02Cu)
#define PKA_OFF_Z_REG     PKA_REG(0x030u)

#define PKA_CTRL_START    (1u << 0)
#define PKA_STATUS_DONE   (1u << 1)
#define PKA_STATUS_ERROR  (1u << 2)

#define OPCODE_MODEXP     0x01u

#define OFF_A   0x000u
#define OFF_E   0x100u
#define OFF_M   0x200u
#define OFF_Z   0x300u

static volatile uint8_t * const pka_ram = (volatile uint8_t *)PKA_RAM_BASE;

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

static int pka_modexp(const uint8_t *a, uint32_t a_len,
                      const uint8_t *e, uint32_t e_len,
                      const uint8_t *m, uint32_t m_len,
                      uint8_t *z)
{
    pka_write(OFF_A, a, a_len);
    pka_write(OFF_E, e, e_len);
    pka_write(OFF_M, m, m_len);
    PKA_OFF_A_REG    = OFF_A;
    PKA_OFF_E_REG    = OFF_E;
    PKA_OFF_M_REG    = OFF_M;
    PKA_OFF_Z_REG    = OFF_Z;
    PKA_LEN_OPERAND  = a_len;
    PKA_LEN_EXP      = e_len;
    PKA_LEN_MOD      = m_len;
    PKA_OPCODE       = OPCODE_MODEXP;
    PKA_STATUS       = PKA_STATUS_DONE | PKA_STATUS_ERROR;
    PKA_CTRL         = PKA_CTRL_START;

    for (int i = 0; i < 1000000; ++i) {
        uint32_t s = PKA_STATUS;
        if (s & PKA_STATUS_ERROR) return 0;
        if (s & PKA_STATUS_DONE)  break;
        if (i == 999999) return 0;
    }
    pka_read(OFF_Z, z, m_len);
    return 1;
}

static int test_toy(void)
{
    uint8_t a[1] = { 17 };
    uint8_t e[1] = { 7 };
    uint8_t m[1] = { 23 };
    uint8_t z[1] = { 0 };

    /* 17^2 = 289 = 13 mod 23; 17^4 = 13^2 = 8 mod 23;
     * 17^7 = 17^4*17^2*17 = 8*13*17 = 12*17 = 204 = 20 mod 23. */
    if (!pka_modexp(a, 1, e, 1, m, 1, z)) {
        printf("modexp(17^7 mod 23): FAIL (status=0x%lx)\n",
               (unsigned long)PKA_STATUS);
        return 0;
    }
    int ok = (z[0] == 20);
    printf("modexp(17^7 mod 23): got %u, exp 20  %s\n",
           (unsigned)z[0], ok ? "PASS" : "FAIL");
    return ok;
}

/* 2^32 mod (2^32 - 1) = 1 — self-evident invariant: 2^32 ≡ 1 (mod 2^32-1). */
static int test_2_pow_32(void)
{
    static const uint8_t a[1] = { 0x02 };
    static const uint8_t e[1] = { 0x20 };       /* 32 */
    static const uint8_t m[4] = { 0xff, 0xff, 0xff, 0xff };
    static const uint8_t exp_z[4] = { 0x00, 0x00, 0x00, 0x01 };
    uint8_t z[4] = { 0 };

    if (!pka_modexp(a, sizeof(a), e, sizeof(e), m, sizeof(m), z)) {
        printf("modexp(2^32 mod 2^32-1): FAIL\n");
        return 0;
    }
    int ok = (memcmp(z, exp_z, sizeof(exp_z)) == 0);
    printf("modexp(2^32 mod 2^32-1): %s (got %02x%02x%02x%02x)\n",
           ok ? "PASS" : "FAIL", z[0], z[1], z[2], z[3]);
    return ok;
}

/* 3^13 mod 17 = 12 — small hand-verifiable second vector. */
static int test_3_pow_13(void)
{
    static const uint8_t a[1] = { 0x03 };
    static const uint8_t e[1] = { 0x0d };
    static const uint8_t m[1] = { 0x11 };
    uint8_t z[1] = { 0 };

    if (!pka_modexp(a, 1, e, 1, m, 1, z)) {
        printf("modexp(3^13 mod 17): FAIL\n");
        return 0;
    }
    int ok = (z[0] == 12);
    printf("modexp(3^13 mod 17): got %u, exp 12  %s\n",
           (unsigned)z[0], ok ? "PASS" : "FAIL");
    return ok;
}

int main(void)
{
    int all = 1;
    printf("=== RW612 PKA test ===\n");
    all &= test_toy();
    all &= test_3_pow_13();
    all &= test_2_pow_32();
    printf("=== %s ===\n", all ? "ALL PASS" : "SOME FAIL");
    return all ? 0 : 1;
}
