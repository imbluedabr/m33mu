/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * RW612 ELS (EdgeLock Secure Subsystem) + PKA (Public Key Accelerator) stubs
 * with wolfcrypt offload.
 *
 * The two engines share a 4 KB scratch buffer mapped at 0x22040000 (the PKA
 * data RAM as it appears on real RW612 silicon).  Test firmware loads
 * operands and message bytes into this buffer at chosen offsets, programs
 * the engine's source/destination offset+length registers, and writes the
 * CMD register to start the operation.  When the engine finishes, the
 * CPU reads the result back from the same buffer (or, for hashes, from
 * inline RESULT registers).
 *
 * This is a deliberate emulator simplification: real ELS uses mailbox
 * descriptors that point into system memory.  For our test surface (driver
 * smoke tests + crypto correctness vs known answers) the unified-scratch
 * layout is sufficient and avoids needing the memmap pointer in MMIO write
 * handlers.
 */

#include <string.h>
#include <stdlib.h>
#include "rw612/rw612_secure.h"
#include "rw612/cpu_config.h"
#include "m33mu/mmio.h"
#include "m33mu/cpu.h"

#ifdef M33MU_HAS_WOLFSSL
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/integer.h>
#endif

/* -------------------------------------------------------------------------
 * Address layout
 * ------------------------------------------------------------------------- */
#define RW612_ELS_BASE        0x4002F000u
#define RW612_PKA_REG_BASE    0x40044000u
#define RW612_SEC_ALIAS       0x10000000u
#define RW612_SEC_REG_SIZE    0x100u

#define PKA_RAM_BASE          RW612_PKA_RAM_BASE
#define PKA_RAM_SIZE          RW612_PKA_RAM_SIZE   /* 4 KB */

/* -------------------------------------------------------------------------
 * ELS register map (engineering choice — matches what test_els.c writes).
 * ------------------------------------------------------------------------- */
#define ELS_OFF_CMD           0x000u
#define ELS_OFF_STATUS        0x004u
#define ELS_OFF_INTR          0x008u
#define ELS_OFF_INPUT_OFF     0x010u   /* offset into PKA RAM */
#define ELS_OFF_INPUT_LEN     0x014u
#define ELS_OFF_OUTPUT_OFF    0x018u
#define ELS_OFF_OUTPUT_LEN    0x01Cu
#define ELS_OFF_KEY_OFF       0x020u
#define ELS_OFF_KEY_LEN       0x024u   /* 16/24/32 for AES */
#define ELS_OFF_IV_OFF        0x028u
#define ELS_OFF_IV_LEN        0x02Cu
#define ELS_OFF_RESULT0       0x040u   /* 8 words = 32 bytes */
#define ELS_OFF_RESULT7       0x05Cu

#define ELS_STATUS_BUSY       (1u << 0)
#define ELS_STATUS_DONE       (1u << 1)
#define ELS_STATUS_ERROR      (1u << 2)
#define ELS_STATUS_SECURE     (1u << 3)

/* ELS command codes */
#define ELS_CMD_NOP           0x00u
#define ELS_CMD_AES_ECB_ENC   0x01u
#define ELS_CMD_AES_ECB_DEC   0x02u
#define ELS_CMD_AES_CBC_ENC   0x03u
#define ELS_CMD_AES_CBC_DEC   0x04u
#define ELS_CMD_AES_CTR       0x05u
#define ELS_CMD_SHA256        0x10u
#define ELS_CMD_HMAC_SHA256   0x11u
#define ELS_CMD_RNG           0x20u

/* -------------------------------------------------------------------------
 * PKA register map.  Operands and result live in PKA RAM (0x22040000)
 * encoded big-endian (matches wolfcrypt mp_read_unsigned_bin).
 * ------------------------------------------------------------------------- */
#define PKA_OFF_CTRL          0x000u
#define PKA_OFF_STATUS        0x004u
#define PKA_OFF_OPCODE        0x008u
#define PKA_OFF_LEN_OPERAND   0x00Cu
#define PKA_OFF_LEN_MOD       0x010u
#define PKA_OFF_LEN_EXP       0x014u
#define PKA_OFF_OFF_A         0x020u
#define PKA_OFF_OFF_B         0x024u
#define PKA_OFF_OFF_M         0x028u
#define PKA_OFF_OFF_E         0x02Cu
#define PKA_OFF_OFF_Z         0x030u

#define PKA_CTRL_START        (1u << 0)
#define PKA_STATUS_BUSY       (1u << 0)
#define PKA_STATUS_DONE       (1u << 1)
#define PKA_STATUS_ERROR      (1u << 2)
#define PKA_STATUS_READY      (1u << 3)

#define PKA_OPCODE_NOP        0x00u
#define PKA_OPCODE_MODEXP     0x01u
#define PKA_OPCODE_MODMUL     0x02u
#define PKA_OPCODE_MODADD     0x03u
#define PKA_OPCODE_MODSUB     0x04u

/* -------------------------------------------------------------------------
 * State
 * ------------------------------------------------------------------------- */
struct els_regs {
    mm_u32 cmd;
    mm_u32 status;
    mm_u32 intr;
    mm_u32 input_off, input_len;
    mm_u32 output_off, output_len;
    mm_u32 key_off, key_len;
    mm_u32 iv_off, iv_len;
    mm_u32 result[8];
};

struct pka_regs {
    mm_u32 ctrl;
    mm_u32 status;
    mm_u32 opcode;
    mm_u32 len_operand;
    mm_u32 len_mod;
    mm_u32 len_exp;
    mm_u32 off_a, off_b, off_m, off_e, off_z;
};

struct rw612_secure_state {
    struct els_regs els;
    struct pka_regs pka;
    mm_u8 pka_ram[PKA_RAM_SIZE];
    mm_u32 rng_ctr;
};

static struct rw612_secure_state g_sec;

/* -------------------------------------------------------------------------
 * Endianness helpers
 * ------------------------------------------------------------------------- */
static mm_u32 read32le(const mm_u8 *p)
{
    return (mm_u32)p[0]
         | ((mm_u32)p[1] << 8)
         | ((mm_u32)p[2] << 16)
         | ((mm_u32)p[3] << 24);
}

#ifndef M33MU_HAS_WOLFSSL
static void write32le(mm_u8 *p, mm_u32 v)
{
    p[0] = (mm_u8)(v & 0xFFu);
    p[1] = (mm_u8)((v >>  8) & 0xFFu);
    p[2] = (mm_u8)((v >> 16) & 0xFFu);
    p[3] = (mm_u8)((v >> 24) & 0xFFu);
}
#endif

/* -------------------------------------------------------------------------
 * RNG (deterministic — testable but not cryptographically meaningful)
 * ------------------------------------------------------------------------- */
void mm_rw612_secure_rng_fill(mm_u8 *out, mm_u32 len)
{
    mm_u32 i;
    if (out == 0) return;
    for (i = 0; i < len; ++i) {
        g_sec.rng_ctr = g_sec.rng_ctr * 1103515245u + 12345u;
        out[i] = (mm_u8)((g_sec.rng_ctr >> 16) & 0xFFu);
    }
}

/* -------------------------------------------------------------------------
 * PKA RAM bus region (0x22040000, 4 KB).
 * Word reads / writes against pka_ram[]; no side effects.
 * ------------------------------------------------------------------------- */
static mm_bool pka_ram_read(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                            mm_u32 *value_out)
{
    (void)opaque;
    if (value_out == 0 || size_bytes == 0 || size_bytes > 4u) return MM_FALSE;
    if ((offset + size_bytes) > PKA_RAM_SIZE) return MM_FALSE;
    *value_out = 0u;
    memcpy(value_out, &g_sec.pka_ram[offset], size_bytes);
    return MM_TRUE;
}

static mm_bool pka_ram_write(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                             mm_u32 value)
{
    (void)opaque;
    if (size_bytes == 0 || size_bytes > 4u) return MM_FALSE;
    if ((offset + size_bytes) > PKA_RAM_SIZE) return MM_FALSE;
    memcpy(&g_sec.pka_ram[offset], &value, size_bytes);
    return MM_TRUE;
}

/* -------------------------------------------------------------------------
 * Slice helpers — bounded read/write of pka_ram[]
 * ------------------------------------------------------------------------- */
static mm_bool sec_buf_read(mm_u32 off, mm_u32 len, mm_u8 *out)
{
    if (off >= PKA_RAM_SIZE) return MM_FALSE;
    if (len > PKA_RAM_SIZE - off) return MM_FALSE;
    memcpy(out, &g_sec.pka_ram[off], len);
    return MM_TRUE;
}

static mm_bool sec_buf_write(mm_u32 off, mm_u32 len, const mm_u8 *in)
{
    if (off >= PKA_RAM_SIZE) return MM_FALSE;
    if (len > PKA_RAM_SIZE - off) return MM_FALSE;
    memcpy(&g_sec.pka_ram[off], in, len);
    return MM_TRUE;
}

/* -------------------------------------------------------------------------
 * Crypto primitives — wolfcrypt-backed when available, deterministic
 * fallback otherwise (lets the build link; tests that depend on real
 * crypto are skipped via the compile-time guard in their assertions).
 * ------------------------------------------------------------------------- */
#ifdef M33MU_HAS_WOLFSSL

static mm_bool sec_aes_block(int enc, int mode, const mm_u8 *key, mm_u32 key_len,
                             const mm_u8 *iv, const mm_u8 *in, mm_u8 *out, mm_u32 len)
{
    Aes aes;
    int rc;
    if (key_len != 16u && key_len != 24u && key_len != 32u) return MM_FALSE;
    rc = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (rc != 0) return MM_FALSE;
    rc = wc_AesSetKey(&aes, key, key_len, iv,
                      enc ? AES_ENCRYPTION : AES_DECRYPTION);
    if (rc != 0) { wc_AesFree(&aes); return MM_FALSE; }

    if (mode == 0) {        /* ECB */
        rc = enc ? wc_AesEcbEncrypt(&aes, out, in, len)
                 : wc_AesEcbDecrypt(&aes, out, in, len);
    } else if (mode == 1) { /* CBC */
        rc = enc ? wc_AesCbcEncrypt(&aes, out, in, len)
                 : wc_AesCbcDecrypt(&aes, out, in, len);
    } else if (mode == 2) { /* CTR */
        rc = wc_AesCtrEncrypt(&aes, out, in, len);
    } else {
        rc = -1;
    }
    wc_AesFree(&aes);
    return (rc == 0) ? MM_TRUE : MM_FALSE;
}

static mm_bool sec_sha256(const mm_u8 *in, mm_u32 len, mm_u8 out[32])
{
    wc_Sha256 h;
    if (wc_InitSha256(&h) != 0) return MM_FALSE;
    if (wc_Sha256Update(&h, in, len) != 0) { wc_Sha256Free(&h); return MM_FALSE; }
    if (wc_Sha256Final(&h, out) != 0)      { wc_Sha256Free(&h); return MM_FALSE; }
    wc_Sha256Free(&h);
    return MM_TRUE;
}

static mm_bool sec_hmac_sha256(const mm_u8 *key, mm_u32 key_len,
                               const mm_u8 *in, mm_u32 in_len, mm_u8 out[32])
{
    Hmac h;
    int rc;
    if (wc_HmacInit(&h, NULL, INVALID_DEVID) != 0) return MM_FALSE;
    rc = wc_HmacSetKey(&h, WC_SHA256, key, key_len);
    if (rc == 0) rc = wc_HmacUpdate(&h, in, in_len);
    if (rc == 0) rc = wc_HmacFinal(&h, out);
    wc_HmacFree(&h);
    return (rc == 0) ? MM_TRUE : MM_FALSE;
}

static mm_bool sec_modop(int opcode, const mm_u8 *a_buf, mm_u32 a_len,
                         const mm_u8 *b_buf, mm_u32 b_len,
                         const mm_u8 *m_buf, mm_u32 m_len,
                         mm_u8 *z_buf, mm_u32 *z_len_out, mm_u32 z_buf_size)
{
    mp_int A, B, M, Z;
    int rc = -1;
    int written;

    if (mp_init_multi(&A, &B, &M, &Z, NULL, NULL) != 0) return MM_FALSE;
    if (mp_read_unsigned_bin(&A, a_buf, (int)a_len) != 0) goto out;
    if (mp_read_unsigned_bin(&B, b_buf, (int)b_len) != 0) goto out;
    if (mp_read_unsigned_bin(&M, m_buf, (int)m_len) != 0) goto out;

    switch (opcode) {
    case PKA_OPCODE_MODEXP: rc = mp_exptmod(&A, &B, &M, &Z); break;
    case PKA_OPCODE_MODMUL: rc = mp_mulmod(&A, &B, &M, &Z);  break;
    case PKA_OPCODE_MODADD: rc = mp_addmod(&A, &B, &M, &Z);  break;
    case PKA_OPCODE_MODSUB: rc = mp_submod(&A, &B, &M, &Z);  break;
    default: rc = -1; break;
    }
    if (rc != 0) goto out;

    written = mp_unsigned_bin_size(&Z);
    if (written < 0 || (mm_u32)written > z_buf_size) { rc = -1; goto out; }
    if (mp_to_unsigned_bin(&Z, z_buf) != 0) { rc = -1; goto out; }
    /* Right-justify to full m_len width by zero-padding on the left. */
    if ((mm_u32)written < m_len && m_len <= z_buf_size) {
        mm_u32 shift = m_len - (mm_u32)written;
        memmove(z_buf + shift, z_buf, (mm_u32)written);
        memset(z_buf, 0, shift);
        written = (int)m_len;
    }
    *z_len_out = (mm_u32)written;
out:
    mp_clear(&A); mp_clear(&B); mp_clear(&M); mp_clear(&Z);
    return (rc == 0) ? MM_TRUE : MM_FALSE;
}

#else  /* M33MU_HAS_WOLFSSL */

static mm_bool sec_aes_block(int enc, int mode, const mm_u8 *key, mm_u32 key_len,
                             const mm_u8 *iv, const mm_u8 *in, mm_u8 *out, mm_u32 len)
{
    (void)enc; (void)mode; (void)key; (void)key_len; (void)iv;
    if (out != in) memcpy(out, in, len);
    return MM_TRUE;
}

static mm_bool sec_sha256(const mm_u8 *in, mm_u32 len, mm_u8 out[32])
{
    mm_u32 acc = 0x811C9DC5u, i, j;
    for (i = 0; i < len; ++i) {
        acc ^= in[i];
        acc *= 16777619u;
        acc = (acc << 5) | (acc >> 27);
    }
    for (j = 0; j < 32u; j += 4u) {
        acc ^= (0x9E3779B9u + j);
        acc *= 2246822519u;
        write32le(out + j, acc);
    }
    return MM_TRUE;
}

static mm_bool sec_hmac_sha256(const mm_u8 *key, mm_u32 key_len,
                               const mm_u8 *in, mm_u32 in_len, mm_u8 out[32])
{
    mm_u8 buf[160];
    mm_u32 take = key_len > 64u ? 64u : key_len;
    mm_u32 inn  = in_len  > 64u ? 64u : in_len;
    memset(buf, 0, sizeof(buf));
    memcpy(buf, key, take);
    memcpy(buf + 64u, in, inn);
    return sec_sha256(buf, 64u + inn, out);
}

static mm_bool sec_modop(int opcode, const mm_u8 *a_buf, mm_u32 a_len,
                         const mm_u8 *b_buf, mm_u32 b_len,
                         const mm_u8 *m_buf, mm_u32 m_len,
                         mm_u8 *z_buf, mm_u32 *z_len_out, mm_u32 z_buf_size)
{
    (void)opcode; (void)a_buf; (void)a_len; (void)b_buf; (void)b_len;
    (void)m_buf; (void)m_len; (void)z_buf_size;
    if (z_buf != 0 && z_buf_size > 0) {
        memset(z_buf, 0, z_buf_size);
    }
    *z_len_out = 0u;
    return MM_FALSE;
}

#endif /* M33MU_HAS_WOLFSSL */

/* -------------------------------------------------------------------------
 * ELS command dispatch
 * ------------------------------------------------------------------------- */
static void els_finish(mm_bool ok)
{
    g_sec.els.status &= ~ELS_STATUS_BUSY;
    g_sec.els.status &= ~(ELS_STATUS_DONE | ELS_STATUS_ERROR);
    g_sec.els.status |= ok ? ELS_STATUS_DONE : ELS_STATUS_ERROR;
}

static void els_writeback_digest(const mm_u8 d[32])
{
    int i;
    for (i = 0; i < 8; ++i) g_sec.els.result[i] = read32le(d + i * 4);
}

static void els_exec(mm_u32 cmd)
{
    mm_u8 key[32];
    mm_u8 iv[16];
    mm_u8 *in_buf;
    mm_u8 *out_buf;
    mm_u32 in_len;
    mm_u32 key_len;
    mm_u32 iv_len;
    mm_u8 digest[32];

    g_sec.els.status |= ELS_STATUS_BUSY;
    g_sec.els.status &= ~(ELS_STATUS_DONE | ELS_STATUS_ERROR);

    in_len  = g_sec.els.input_len;
    key_len = g_sec.els.key_len;
    iv_len  = g_sec.els.iv_len;
    if (g_sec.els.input_off  >= PKA_RAM_SIZE) { els_finish(MM_FALSE); return; }
    if (g_sec.els.output_off >= PKA_RAM_SIZE) { els_finish(MM_FALSE); return; }
    if (in_len > PKA_RAM_SIZE - g_sec.els.input_off)  { els_finish(MM_FALSE); return; }
    if (in_len > PKA_RAM_SIZE - g_sec.els.output_off) { els_finish(MM_FALSE); return; }

    switch (cmd) {
    case ELS_CMD_AES_ECB_ENC:
    case ELS_CMD_AES_ECB_DEC:
    case ELS_CMD_AES_CBC_ENC:
    case ELS_CMD_AES_CBC_DEC:
    case ELS_CMD_AES_CTR: {
        int enc, mode;
        if (key_len > sizeof(key)) { els_finish(MM_FALSE); return; }
        if (!sec_buf_read(g_sec.els.key_off, key_len, key)) { els_finish(MM_FALSE); return; }
        memset(iv, 0, sizeof(iv));
        if (iv_len > 0u) {
            if (iv_len > sizeof(iv)) { els_finish(MM_FALSE); return; }
            if (!sec_buf_read(g_sec.els.iv_off, iv_len, iv)) { els_finish(MM_FALSE); return; }
        }
        in_buf  = &g_sec.pka_ram[g_sec.els.input_off];
        out_buf = &g_sec.pka_ram[g_sec.els.output_off];
        if (cmd == ELS_CMD_AES_ECB_ENC || cmd == ELS_CMD_AES_ECB_DEC) {
            mode = 0;
            enc = (cmd == ELS_CMD_AES_ECB_ENC) ? 1 : 0;
        } else if (cmd == ELS_CMD_AES_CBC_ENC || cmd == ELS_CMD_AES_CBC_DEC) {
            mode = 1;
            enc = (cmd == ELS_CMD_AES_CBC_ENC) ? 1 : 0;
        } else {
            mode = 2; enc = 1;
        }
        els_finish(sec_aes_block(enc, mode, key, key_len, iv, in_buf, out_buf, in_len));
        return;
    }
    case ELS_CMD_SHA256:
        in_buf = &g_sec.pka_ram[g_sec.els.input_off];
        if (!sec_sha256(in_buf, in_len, digest)) { els_finish(MM_FALSE); return; }
        (void)sec_buf_write(g_sec.els.output_off, 32u, digest);
        els_writeback_digest(digest);
        els_finish(MM_TRUE);
        return;
    case ELS_CMD_HMAC_SHA256:
        if (key_len > sizeof(key)) { els_finish(MM_FALSE); return; }
        if (!sec_buf_read(g_sec.els.key_off, key_len, key)) { els_finish(MM_FALSE); return; }
        in_buf = &g_sec.pka_ram[g_sec.els.input_off];
        if (!sec_hmac_sha256(key, key_len, in_buf, in_len, digest)) { els_finish(MM_FALSE); return; }
        (void)sec_buf_write(g_sec.els.output_off, 32u, digest);
        els_writeback_digest(digest);
        els_finish(MM_TRUE);
        return;
    case ELS_CMD_RNG: {
        mm_u32 take = g_sec.els.output_len;
        if (take == 0u) take = 32u;
        if (take > 256u) take = 256u;
        {
            mm_u8 tmp[256];
            mm_rw612_secure_rng_fill(tmp, take);
            if (!sec_buf_write(g_sec.els.output_off, take, tmp)) {
                els_finish(MM_FALSE); return;
            }
        }
        els_finish(MM_TRUE);
        return;
    }
    default:
        break;
    }
    els_finish(MM_FALSE);
}

/* -------------------------------------------------------------------------
 * PKA command dispatch
 * ------------------------------------------------------------------------- */
static void pka_finish(mm_bool ok)
{
    g_sec.pka.status &= ~PKA_STATUS_BUSY;
    g_sec.pka.status &= ~(PKA_STATUS_DONE | PKA_STATUS_ERROR);
    g_sec.pka.status |= PKA_STATUS_READY;
    g_sec.pka.status |= ok ? PKA_STATUS_DONE : PKA_STATUS_ERROR;
}

static void pka_start(void)
{
    mm_u8 a[256], b[256], m[256], z[256];
    mm_u32 a_len, b_len, z_len;
    mm_u32 mod_len = g_sec.pka.len_mod;

    g_sec.pka.status |= PKA_STATUS_BUSY;
    g_sec.pka.status &= ~(PKA_STATUS_DONE | PKA_STATUS_ERROR | PKA_STATUS_READY);

    if (mod_len == 0u || mod_len > sizeof(m)) { pka_finish(MM_FALSE); return; }

    /* Operand A: full operand width */
    a_len = g_sec.pka.len_operand ? g_sec.pka.len_operand : mod_len;
    if (a_len > sizeof(a)) { pka_finish(MM_FALSE); return; }
    if (!sec_buf_read(g_sec.pka.off_a, a_len, a)) { pka_finish(MM_FALSE); return; }

    /* Operand B / E (interpreted by opcode) */
    if (g_sec.pka.opcode == PKA_OPCODE_MODEXP) {
        b_len = g_sec.pka.len_exp ? g_sec.pka.len_exp : mod_len;
        if (b_len > sizeof(b)) { pka_finish(MM_FALSE); return; }
        if (!sec_buf_read(g_sec.pka.off_e, b_len, b)) { pka_finish(MM_FALSE); return; }
    } else {
        b_len = g_sec.pka.len_operand ? g_sec.pka.len_operand : mod_len;
        if (b_len > sizeof(b)) { pka_finish(MM_FALSE); return; }
        if (!sec_buf_read(g_sec.pka.off_b, b_len, b)) { pka_finish(MM_FALSE); return; }
    }
    if (!sec_buf_read(g_sec.pka.off_m, mod_len, m)) { pka_finish(MM_FALSE); return; }

    if (!sec_modop((int)g_sec.pka.opcode, a, a_len, b, b_len, m, mod_len,
                   z, &z_len, sizeof(z))) {
        pka_finish(MM_FALSE);
        return;
    }
    (void)z_len;
    if (!sec_buf_write(g_sec.pka.off_z, mod_len, z)) {
        pka_finish(MM_FALSE);
        return;
    }
    pka_finish(MM_TRUE);
}

/* -------------------------------------------------------------------------
 * MMIO handlers
 * ------------------------------------------------------------------------- */
static mm_bool sec_access_ok(void)
{
    /* On real silicon ELS/PKA are secure-only.  In the emulator the test
     * harness boots NS (initial SP in NS RAM), so for v1 we accept any
     * security state — a SAU-aware test could tighten this later. */
    return MM_TRUE;
}

static mm_bool els_read(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                        mm_u32 *value_out)
{
    (void)opaque;
    if (!sec_access_ok()) return MM_FALSE;
    if (size_bytes != 4u || value_out == 0) return MM_FALSE;
    switch (offset) {
    case ELS_OFF_CMD:        *value_out = g_sec.els.cmd;        return MM_TRUE;
    case ELS_OFF_STATUS:     *value_out = g_sec.els.status;     return MM_TRUE;
    case ELS_OFF_INTR:       *value_out = g_sec.els.intr;       return MM_TRUE;
    case ELS_OFF_INPUT_OFF:  *value_out = g_sec.els.input_off;  return MM_TRUE;
    case ELS_OFF_INPUT_LEN:  *value_out = g_sec.els.input_len;  return MM_TRUE;
    case ELS_OFF_OUTPUT_OFF: *value_out = g_sec.els.output_off; return MM_TRUE;
    case ELS_OFF_OUTPUT_LEN: *value_out = g_sec.els.output_len; return MM_TRUE;
    case ELS_OFF_KEY_OFF:    *value_out = g_sec.els.key_off;    return MM_TRUE;
    case ELS_OFF_KEY_LEN:    *value_out = g_sec.els.key_len;    return MM_TRUE;
    case ELS_OFF_IV_OFF:     *value_out = g_sec.els.iv_off;     return MM_TRUE;
    case ELS_OFF_IV_LEN:     *value_out = g_sec.els.iv_len;     return MM_TRUE;
    default:
        if (offset >= ELS_OFF_RESULT0 && offset <= ELS_OFF_RESULT7) {
            mm_u32 idx = (offset - ELS_OFF_RESULT0) / 4u;
            *value_out = g_sec.els.result[idx];
            return MM_TRUE;
        }
        break;
    }
    *value_out = 0u;
    return MM_TRUE;
}

static mm_bool els_write(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                         mm_u32 value)
{
    (void)opaque;
    if (!sec_access_ok()) return MM_FALSE;
    if (size_bytes != 4u) return MM_FALSE;
    switch (offset) {
    case ELS_OFF_CMD:        g_sec.els.cmd = value; els_exec(value); return MM_TRUE;
    case ELS_OFF_STATUS:     g_sec.els.status &= ~value; return MM_TRUE;
    case ELS_OFF_INTR:       g_sec.els.intr = value; return MM_TRUE;
    case ELS_OFF_INPUT_OFF:  g_sec.els.input_off  = value; return MM_TRUE;
    case ELS_OFF_INPUT_LEN:  g_sec.els.input_len  = value; return MM_TRUE;
    case ELS_OFF_OUTPUT_OFF: g_sec.els.output_off = value; return MM_TRUE;
    case ELS_OFF_OUTPUT_LEN: g_sec.els.output_len = value; return MM_TRUE;
    case ELS_OFF_KEY_OFF:    g_sec.els.key_off = value; return MM_TRUE;
    case ELS_OFF_KEY_LEN:    g_sec.els.key_len = value; return MM_TRUE;
    case ELS_OFF_IV_OFF:     g_sec.els.iv_off = value; return MM_TRUE;
    case ELS_OFF_IV_LEN:     g_sec.els.iv_len = value; return MM_TRUE;
    default:
        if (offset >= ELS_OFF_RESULT0 && offset <= ELS_OFF_RESULT7) {
            mm_u32 idx = (offset - ELS_OFF_RESULT0) / 4u;
            g_sec.els.result[idx] = value;
            return MM_TRUE;
        }
        break;
    }
    return MM_TRUE;
}

static mm_bool pka_read(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                        mm_u32 *value_out)
{
    (void)opaque;
    if (!sec_access_ok()) return MM_FALSE;
    if (size_bytes != 4u || value_out == 0) return MM_FALSE;
    switch (offset) {
    case PKA_OFF_CTRL:        *value_out = g_sec.pka.ctrl; return MM_TRUE;
    case PKA_OFF_STATUS:      *value_out = g_sec.pka.status; return MM_TRUE;
    case PKA_OFF_OPCODE:      *value_out = g_sec.pka.opcode; return MM_TRUE;
    case PKA_OFF_LEN_OPERAND: *value_out = g_sec.pka.len_operand; return MM_TRUE;
    case PKA_OFF_LEN_MOD:     *value_out = g_sec.pka.len_mod; return MM_TRUE;
    case PKA_OFF_LEN_EXP:     *value_out = g_sec.pka.len_exp; return MM_TRUE;
    case PKA_OFF_OFF_A:       *value_out = g_sec.pka.off_a; return MM_TRUE;
    case PKA_OFF_OFF_B:       *value_out = g_sec.pka.off_b; return MM_TRUE;
    case PKA_OFF_OFF_M:       *value_out = g_sec.pka.off_m; return MM_TRUE;
    case PKA_OFF_OFF_E:       *value_out = g_sec.pka.off_e; return MM_TRUE;
    case PKA_OFF_OFF_Z:       *value_out = g_sec.pka.off_z; return MM_TRUE;
    default: break;
    }
    *value_out = 0u;
    return MM_TRUE;
}

static mm_bool pka_write(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                         mm_u32 value)
{
    (void)opaque;
    if (!sec_access_ok()) return MM_FALSE;
    if (size_bytes != 4u) return MM_FALSE;
    switch (offset) {
    case PKA_OFF_CTRL:
        g_sec.pka.ctrl = value;
        if ((value & PKA_CTRL_START) != 0u) pka_start();
        return MM_TRUE;
    case PKA_OFF_STATUS:      g_sec.pka.status &= ~value; return MM_TRUE;
    case PKA_OFF_OPCODE:      g_sec.pka.opcode = value; return MM_TRUE;
    case PKA_OFF_LEN_OPERAND: g_sec.pka.len_operand = value; return MM_TRUE;
    case PKA_OFF_LEN_MOD:     g_sec.pka.len_mod = value; return MM_TRUE;
    case PKA_OFF_LEN_EXP:     g_sec.pka.len_exp = value; return MM_TRUE;
    case PKA_OFF_OFF_A:       g_sec.pka.off_a = value; return MM_TRUE;
    case PKA_OFF_OFF_B:       g_sec.pka.off_b = value; return MM_TRUE;
    case PKA_OFF_OFF_M:       g_sec.pka.off_m = value; return MM_TRUE;
    case PKA_OFF_OFF_E:       g_sec.pka.off_e = value; return MM_TRUE;
    case PKA_OFF_OFF_Z:       g_sec.pka.off_z = value; return MM_TRUE;
    default: break;
    }
    return MM_TRUE;
}

/* -------------------------------------------------------------------------
 * Public registration
 * ------------------------------------------------------------------------- */
void mm_rw612_secure_reset(void)
{
    memset(&g_sec, 0, sizeof(g_sec));
    g_sec.els.status = ELS_STATUS_SECURE | ELS_STATUS_DONE;
    g_sec.pka.status = PKA_STATUS_READY  | PKA_STATUS_DONE;
    /* Seed RNG with something stable but distinct from zero so the first
     * test_els.bin RNG run produces non-zero output. */
    g_sec.rng_ctr = 0xA1B2C3D4u;
}

mm_bool mm_rw612_secure_register_mmio(struct mmio_bus *bus)
{
    struct mmio_region reg;
    if (bus == 0) return MM_FALSE;

    /* ELS register block (S + S-alias) */
    memset(&reg, 0, sizeof(reg));
    reg.size  = RW612_SEC_REG_SIZE;
    reg.read  = els_read;
    reg.write = els_write;
    reg.base  = RW612_ELS_BASE;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;
    reg.base  = RW612_ELS_BASE | RW612_SEC_ALIAS;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;

    /* PKA register block */
    reg.read  = pka_read;
    reg.write = pka_write;
    reg.base  = RW612_PKA_REG_BASE;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;
    reg.base  = RW612_PKA_REG_BASE | RW612_SEC_ALIAS;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;

    /* PKA scratch RAM (4 KB, byte-addressable) */
    reg.size  = PKA_RAM_SIZE;
    reg.read  = pka_ram_read;
    reg.write = pka_ram_write;
    reg.base  = PKA_RAM_BASE;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;
    reg.base  = PKA_RAM_BASE | RW612_SEC_ALIAS;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;

    return MM_TRUE;
}
