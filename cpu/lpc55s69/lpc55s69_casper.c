/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * LPC55S69 CASPER RSA/ECC accelerator peripheral model.
 *
 * Supported operations:
 *   - RSA mod-exp (all key sizes): base^exp mod n via mp_exptmod.
 *   - ECC scalar-mul: NOT implemented (no public wolfSSL API).
 *     These opcodes set STATUS.ERROR and emit a one-shot warning.
 *
 * No-wolfSSL path: mod-exp returns STATUS.ERROR and MM_FALSE.
 *
 * Reference: NXP LPC55S69 UM11126 Chapter 46 (CASPER);
 *            MCUXpresso SDK fsl_casper.c for opcode values.
 *
 * CASPER IRQ: 57 (LPC55S69_cm33_core0.h CASPER_IRQn)
 */

#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include "lpc55s69_casper.h"
#include "m33mu/nvic.h"
#include "m33mu/memmap.h"

#ifdef M33MU_HAS_WOLFSSL
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
/* Use sp_int.h directly: mp_int is typedef'd to sp_int there,
 * and sp_exptmod (== mp_exptmod) is exported from libwolfssl. */
#include <wolfssl/wolfcrypt/sp_int.h>
#endif

/* -------------------------------------------------------------------------
 * Register offsets
 * ------------------------------------------------------------------------- */
#define CAS_OFF_CTRL0       0x00u
#define CAS_OFF_CTRL1       0x04u
#define CAS_OFF_LOADER      0x08u
#define CAS_OFF_STATUS      0x0Cu
#define CAS_OFF_INTENSET    0x10u
#define CAS_OFF_INTENCLR    0x14u
/* 0x18..0x1F reserved */
#define CAS_OFF_AREG        0x20u
#define CAS_OFF_BREG        0x24u
#define CAS_OFF_CREG        0x28u
#define CAS_OFF_DREG        0x2Cu
#define CAS_OFF_RES0        0x30u
#define CAS_OFF_RES1        0x34u
#define CAS_OFF_RES2        0x38u
#define CAS_OFF_RES3        0x3Cu
/* 0x40..0x5F reserved */
#define CAS_OFF_MASK        0x60u
#define CAS_OFF_REMASK      0x64u
/* 0x68..0x7F reserved */
#define CAS_OFF_LOCK        0x80u

/* -------------------------------------------------------------------------
 * STATUS bits
 * ------------------------------------------------------------------------- */
#define STATUS_BUSY         (1u << 0)
#define STATUS_DONE         (1u << 2)
#define STATUS_ERROR        (1u << 3)

/* -------------------------------------------------------------------------
 * INTENSET / INTENCLR bits
 * ------------------------------------------------------------------------- */
#define INTEN_DONE          (1u << 0)
#define INTEN_ERROR         (1u << 1)

/* -------------------------------------------------------------------------
 * CASPER IRQ number
 * ------------------------------------------------------------------------- */
#define CASPER_IRQn         57u

/* -------------------------------------------------------------------------
 * CTRL0 opcode encoding (from fsl_casper.c kCASPER_* enums)
 * The opcode occupies CTRL0[7:0].
 * RSA mod-exp variants:
 *   0x08 = MODEXP_2048 / generic modexp (also used for other key sizes)
 *   0x09 = MODEXP_3072
 *   0x0A = MODEXP_4096
 * ECC variants (all result in ERROR in this model):
 *   0x10 = ECC_P256_PtMul
 *   0x11 = ECC_P384_PtMul
 *   0x12 = ECC_P521_PtMul
 *   0x13 = ECC_P256_MUL2ADD (Shamir)
 *   0x14 = ECC_P384_MUL2ADD
 *   0x15 = ECC_P521_MUL2ADD
 * Generic modexp (arbitrary operand size encoded via CTRL1):
 *   0x00 = generic mod-exp (operand length in CTRL1 or implicit from CREG size)
 *
 * For simplicity, we handle opcode 0x00 and 0x08..0x0A as mod-exp.
 * All 0x10..0x1F as ECC (unsupported).
 * ------------------------------------------------------------------------- */
#define CASPER_OP_MODEXP_GENERIC    0x00u
#define CASPER_OP_MODEXP_2048       0x08u
#define CASPER_OP_MODEXP_3072       0x09u
#define CASPER_OP_MODEXP_4096       0x0Au
#define CASPER_OP_ECC_FIRST         0x10u
#define CASPER_OP_ECC_LAST          0x1Fu

#ifdef M33MU_HAS_WOLFSSL
/* -------------------------------------------------------------------------
 * Word-lengths for each opcode (in 32-bit words = key_bits/32).
 * Only used when wolfSSL is available (casper_do_modexp).
 * For MODEXP_GENERIC we infer from the modulus length stored in RAM.
 * The CASPER uses a word-length encoded in CTRL0[15:8] for the generic case.
 * ------------------------------------------------------------------------- */
static mm_u32 casper_op_word_len(mm_u8 opcode)
{
    switch (opcode) {
    case CASPER_OP_MODEXP_2048: return 64u;   /* 2048 / 32 */
    case CASPER_OP_MODEXP_3072: return 96u;   /* 3072 / 32 */
    case CASPER_OP_MODEXP_4096: return 128u;  /* 4096 / 32 */
    default:                    return 0u;    /* generic: read from CTRL0[15:8] */
    }
}
#endif /* M33MU_HAS_WOLFSSL */

/* -------------------------------------------------------------------------
 * Global instance pointer (accessible from execute.c without exposing the
 * full struct definition in a shared header).
 * ------------------------------------------------------------------------- */
static struct mm_lpc55_casper *g_casper = NULL;

struct mm_lpc55_casper *mm_lpc55_casper_get_global(void)
{
    return g_casper;
}

void mm_lpc55_casper_set_global(struct mm_lpc55_casper *cas)
{
    g_casper = cas;
}

/* -------------------------------------------------------------------------
 * Reset
 * ------------------------------------------------------------------------- */
mm_bool mm_lpc55_casper_reset(struct mm_lpc55_casper *cas)
{
    struct mm_nvic   *nvic_save;
    struct mm_memmap *map_save;
    mm_bool           ecc_warned_save;

    if (cas == NULL) return MM_FALSE;
    nvic_save       = cas->nvic;
    map_save        = cas->map;
    ecc_warned_save = cas->ecc_warned;
    memset(cas, 0, sizeof(*cas));
    cas->nvic        = nvic_save;
    cas->map         = map_save;
    cas->ecc_warned  = ecc_warned_save; /* preserve one-shot warn across resets */
    return MM_TRUE;
}

/* -------------------------------------------------------------------------
 * Init
 * ------------------------------------------------------------------------- */
mm_bool mm_lpc55_casper_init(struct mm_lpc55_casper *cas,
                             struct mm_nvic *nvic,
                             struct mm_memmap *map)
{
    if (cas == NULL) return MM_FALSE;
    memset(cas, 0, sizeof(*cas));
    cas->nvic = nvic;
    cas->map  = map;
    return MM_TRUE;
}

/* -------------------------------------------------------------------------
 * IRQ helper
 * ------------------------------------------------------------------------- */
static void casper_pulse_irq(struct mm_lpc55_casper *cas, mm_u32 which)
{
    if (cas->nvic == NULL) return;
    if ((cas->intenset & which) != 0u) {
        mm_nvic_set_pending(cas->nvic, CASPER_IRQn, MM_TRUE);
    }
}

#ifdef M33MU_HAS_WOLFSSL
/* -------------------------------------------------------------------------
 * Read a byte-array from emulated RAM at addr, length bytes.
 * Returns MM_FALSE if any byte access fails.
 * mm_memmap_read signature: (map, sec, addr, size, value_out)
 * Only used when wolfSSL is available (casper_do_modexp).
 * ------------------------------------------------------------------------- */
static mm_bool casper_read_bytes(struct mm_lpc55_casper *cas,
                                 mm_u32 addr, mm_u8 *buf, mm_u32 len)
{
    mm_u32 i;
    mm_u32 val;
    if (cas->map == NULL) return MM_FALSE;
    for (i = 0u; i < len; i += 4u) {
        mm_u32 chunk = (len - i < 4u) ? (len - i) : 4u;
        val = 0u;
        if (!mm_memmap_read(cas->map, MM_NONSECURE, addr + i, chunk, &val)) {
            return MM_FALSE;
        }
        memcpy(buf + i, &val, chunk);
    }
    return MM_TRUE;
}

/* -------------------------------------------------------------------------
 * Write a byte-array to emulated RAM at addr, length bytes.
 * mm_memmap_write signature: (map, sec, addr, size, value)
 * Only used when wolfSSL is available (casper_do_modexp).
 * ------------------------------------------------------------------------- */
static mm_bool casper_write_bytes(struct mm_lpc55_casper *cas,
                                  mm_u32 addr, const mm_u8 *buf, mm_u32 len)
{
    mm_u32 i;
    mm_u32 val;
    if (cas->map == NULL) return MM_FALSE;
    for (i = 0u; i < len; i += 4u) {
        mm_u32 chunk = (len - i < 4u) ? (len - i) : 4u;
        val = 0u;
        memcpy(&val, buf + i, chunk);
        if (!mm_memmap_write(cas->map, MM_NONSECURE, addr + i, chunk, val)) {
            return MM_FALSE;
        }
    }
    return MM_TRUE;
}
#endif /* M33MU_HAS_WOLFSSL */

/* -------------------------------------------------------------------------
 * Core mod-exp dispatch.
 * Reads operands from emulated RAM (little-endian CASPER convention),
 * byte-reverses to big-endian for wolfMath, calls mp_exptmod, byte-reverses
 * result back and writes to RES0 in RAM.
 * Sets STATUS.DONE on success, STATUS.ERROR on failure.
 * ------------------------------------------------------------------------- */
/* Maximum supported operand size: RSA-4096 = 512 bytes */
#define CASPER_MAX_BYTE_LEN 512u

static void casper_do_modexp(struct mm_lpc55_casper *cas, mm_u8 opcode)
{
#ifdef M33MU_HAS_WOLFSSL
    mm_u32 word_len;
    mm_u32 byte_len;
    mm_u32 areg, breg, creg, res0;
    /* Static scratch buffers — only one CASPER in the system, never re-entrant */
    static mm_u8 base_le[CASPER_MAX_BYTE_LEN];
    static mm_u8 exp_le[CASPER_MAX_BYTE_LEN];
    static mm_u8 mod_le[CASPER_MAX_BYTE_LEN];
    static mm_u8 res_le[CASPER_MAX_BYTE_LEN];
    static mm_u8 base_be[CASPER_MAX_BYTE_LEN];
    static mm_u8 exp_be[CASPER_MAX_BYTE_LEN];
    static mm_u8 mod_be[CASPER_MAX_BYTE_LEN];
    static mm_u8 res_be[CASPER_MAX_BYTE_LEN];
    mp_int mp_base, mp_exp, mp_mod, mp_res;
    mm_bool mp_inited = MM_FALSE;
    int rc;
    mm_u32 i;

    /* Determine operand byte length.
     * CTRL0[15:8] contains the word count set by the driver.
     * If it's non-zero, it takes precedence over the opcode's default size.
     * This allows the generic opcode (0x08) to be used with any key size. */
    {
        mm_u32 ctrl0_word_cnt = (cas->regs[CAS_OFF_CTRL0 / 4u] >> 8) & 0xFFu;
        if (ctrl0_word_cnt != 0u) {
            word_len = ctrl0_word_cnt;
        } else {
            word_len = casper_op_word_len(opcode);
            if (word_len == 0u) {
                /* Last resort: 64 words (2048-bit) */
                word_len = 64u;
            }
        }
    }
    byte_len = word_len * 4u;

    if (byte_len > CASPER_MAX_BYTE_LEN || byte_len == 0u) {
        goto error;
    }

    areg = cas->regs[CAS_OFF_AREG / 4u];
    breg = cas->regs[CAS_OFF_BREG / 4u];
    creg = cas->regs[CAS_OFF_CREG / 4u];
    res0 = cas->regs[CAS_OFF_RES0 / 4u];

    /* Read operands (CASPER: little-endian byte arrays in RAM) */
    if (!casper_read_bytes(cas, areg, base_le, byte_len)) goto error;
    if (!casper_read_bytes(cas, breg, exp_le,  byte_len)) goto error;
    if (!casper_read_bytes(cas, creg, mod_le,  byte_len)) goto error;

    /* Byte-reverse: little-endian → big-endian for wolfMath */
    for (i = 0u; i < byte_len; ++i) {
        base_be[i] = base_le[byte_len - 1u - i];
        exp_be[i]  = exp_le[byte_len - 1u - i];
        mod_be[i]  = mod_le[byte_len - 1u - i];
    }

    /* Initialise wolfMath bignums */
    if (mp_init_multi(&mp_base, &mp_exp, &mp_mod, &mp_res, NULL, NULL) != MP_OKAY) {
        goto error;
    }
    mp_inited = MM_TRUE;

    if (mp_read_unsigned_bin(&mp_base, base_be, (int)byte_len) != MP_OKAY) goto error;
    if (mp_read_unsigned_bin(&mp_exp,  exp_be,  (int)byte_len) != MP_OKAY) goto error;
    if (mp_read_unsigned_bin(&mp_mod,  mod_be,  (int)byte_len) != MP_OKAY) goto error;

    /* Compute result = base^exp mod mod */
    rc = mp_exptmod(&mp_base, &mp_exp, &mp_mod, &mp_res);
    if (rc != MP_OKAY) goto error;

    /* Extract result as big-endian bytes */
    memset(res_be, 0, byte_len);
    {
        int res_sz = mp_unsigned_bin_size(&mp_res);
        if (res_sz > (int)byte_len) goto error;
        if (mp_to_unsigned_bin(&mp_res, res_be + (byte_len - (mm_u32)res_sz)) != MP_OKAY) {
            goto error;
        }
    }

    /* Byte-reverse result: big-endian → little-endian for CASPER */
    for (i = 0u; i < byte_len; ++i) {
        res_le[i] = res_be[byte_len - 1u - i];
    }

    /* Write result to RAM at RES0 */
    if (!casper_write_bytes(cas, res0, res_le, byte_len)) goto error;

    /* Success */
    mp_clear(&mp_base);
    mp_clear(&mp_exp);
    mp_clear(&mp_mod);
    mp_clear(&mp_res);
    cas->regs[CAS_OFF_STATUS / 4u] = STATUS_DONE;
    casper_pulse_irq(cas, INTEN_DONE);
    return;

error:
    if (mp_inited) {
        mp_clear(&mp_base);
        mp_clear(&mp_exp);
        mp_clear(&mp_mod);
        mp_clear(&mp_res);
    }
    cas->regs[CAS_OFF_STATUS / 4u] = STATUS_ERROR;
    casper_pulse_irq(cas, INTEN_ERROR);

#else /* !M33MU_HAS_WOLFSSL */
    /* No wolfSSL: accept the write, signal error so firmware doesn't hang */
    (void)cas;
    (void)opcode;
    cas->regs[CAS_OFF_STATUS / 4u] = STATUS_ERROR;
    casper_pulse_irq(cas, INTEN_ERROR);
#endif /* M33MU_HAS_WOLFSSL */
}

/* -------------------------------------------------------------------------
 * ECC opcode handler — always returns ERROR
 * ------------------------------------------------------------------------- */
static void casper_do_ecc_unsupported(struct mm_lpc55_casper *cas)
{
    if (!cas->ecc_warned) {
        fprintf(stderr,
            "[CASPER] ECC opcodes not implemented "
            "(public wolfSSL API limitation: no scalar-mul export)\n");
        cas->ecc_warned = MM_TRUE;
    }
    cas->regs[CAS_OFF_STATUS / 4u] = STATUS_ERROR;
    casper_pulse_irq(cas, INTEN_ERROR);
}

/* -------------------------------------------------------------------------
 * CTRL0 write — decode opcode and dispatch
 * ------------------------------------------------------------------------- */
static void casper_ctrl0_write(struct mm_lpc55_casper *cas, mm_u32 value)
{
    mm_u8 opcode;

    cas->regs[CAS_OFF_CTRL0 / 4u] = value;
    opcode = (mm_u8)(value & 0xFFu);

    /* Check if this is an ECC opcode */
    if (opcode >= CASPER_OP_ECC_FIRST && opcode <= CASPER_OP_ECC_LAST) {
        cas->regs[CAS_OFF_STATUS / 4u] = STATUS_BUSY;
        casper_do_ecc_unsupported(cas);
        return;
    }

    /* Mod-exp opcodes */
    if (opcode == CASPER_OP_MODEXP_GENERIC ||
        opcode == CASPER_OP_MODEXP_2048    ||
        opcode == CASPER_OP_MODEXP_3072    ||
        opcode == CASPER_OP_MODEXP_4096) {
        cas->regs[CAS_OFF_STATUS / 4u] = STATUS_BUSY;
        casper_do_modexp(cas, opcode);
        return;
    }

    /* Unknown opcode: set error, don't hang firmware */
    cas->regs[CAS_OFF_STATUS / 4u] = STATUS_ERROR;
    casper_pulse_irq(cas, INTEN_ERROR);
}

/* -------------------------------------------------------------------------
 * Coprocessor offset mapping.
 * MCUXpresso fsl_casper.c uses MCR/MRC p1,<op1>,<Rt>,<CRn>,<CRm>,<op2>
 * to access CASPER operand registers.  The register encoding maps as:
 *   op1=0, CRn = register_word_index, CRm=0, op2=0 → write to AREG/BREG/etc.
 * In practice, for fast writes the driver uses MCR with:
 *   op1=0, CRn=<reg_select>, CRm=0, op2=<sub>
 * We map CRn to the relevant MMIO offset for operand registers.
 * For STATUS reads (MRC), we return the STATUS register.
 *
 * This is a simplified model — we map the coprocessor interface to the
 * same MMIO offsets for symmetric behaviour.
 * ------------------------------------------------------------------------- */
static mm_u32 cp_crn_to_offset(mm_u8 crn)
{
    switch (crn) {
    case 0u: return CAS_OFF_CTRL0;
    case 1u: return CAS_OFF_CTRL1;
    case 2u: return CAS_OFF_LOADER;
    case 3u: return CAS_OFF_STATUS;
    case 4u: return CAS_OFF_INTENSET;
    case 5u: return CAS_OFF_INTENCLR;
    case 8u: return CAS_OFF_AREG;
    case 9u: return CAS_OFF_BREG;
    case 10u: return CAS_OFF_CREG;
    case 11u: return CAS_OFF_DREG;
    case 12u: return CAS_OFF_RES0;
    case 13u: return CAS_OFF_RES1;
    case 14u: return CAS_OFF_RES2;
    case 15u: return CAS_OFF_RES3;
    default:  return 0xFFFFFFFFu;  /* invalid */
    }
}

mm_bool mm_lpc55_casper_cp_mcr(struct mm_lpc55_casper *cas,
                               mm_u8 op1, mm_u8 crn, mm_u8 crm, mm_u8 op2,
                               mm_u32 value)
{
    mm_u32 offset;
    (void)op1; (void)crm; (void)op2;
    if (cas == NULL) return MM_FALSE;
    offset = cp_crn_to_offset(crn);
    if (offset == 0xFFFFFFFFu) return MM_TRUE; /* ignore unknown */
    return mm_lpc55_casper_write(cas, offset, 4u, value);
}

mm_bool mm_lpc55_casper_cp_mrc(struct mm_lpc55_casper *cas,
                               mm_u8 op1, mm_u8 crn, mm_u8 crm, mm_u8 op2,
                               mm_u32 *value_out)
{
    mm_u32 offset;
    (void)op1; (void)crm; (void)op2;
    if (cas == NULL || value_out == NULL) return MM_FALSE;
    offset = cp_crn_to_offset(crn);
    if (offset == 0xFFFFFFFFu) {
        *value_out = 0u;
        return MM_TRUE;
    }
    return mm_lpc55_casper_read(cas, offset, 4u, value_out);
}

/* -------------------------------------------------------------------------
 * Read callback
 * ------------------------------------------------------------------------- */
mm_bool mm_lpc55_casper_read(void *opaque, mm_u32 offset,
                             mm_u32 size_bytes, mm_u32 *value_out)
{
    struct mm_lpc55_casper *cas = (struct mm_lpc55_casper *)opaque;
    mm_u32 val;

    if (cas == NULL || value_out == NULL) return MM_FALSE;
    if (size_bytes == 0u || size_bytes > 4u) return MM_FALSE;
    if ((offset + size_bytes) > CASPER_SIZE) return MM_FALSE;

    /* STATUS is computed live */
    if (offset == CAS_OFF_STATUS) {
        val = cas->regs[CAS_OFF_STATUS / 4u];
        memcpy(value_out, &val, size_bytes);
        return MM_TRUE;
    }

    /* INTENSET: always returns current enable mask */
    if (offset == CAS_OFF_INTENSET) {
        val = cas->intenset;
        memcpy(value_out, &val, size_bytes);
        return MM_TRUE;
    }

    /* INTENCLR: read-as-zero (write-only semantic) */
    if (offset == CAS_OFF_INTENCLR) {
        *value_out = 0u;
        return MM_TRUE;
    }

    /* Default: register file */
    memcpy(value_out, (const mm_u8 *)cas->regs + offset, size_bytes);
    return MM_TRUE;
}

/* -------------------------------------------------------------------------
 * Write callback
 * ------------------------------------------------------------------------- */
mm_bool mm_lpc55_casper_write(void *opaque, mm_u32 offset,
                              mm_u32 size_bytes, mm_u32 value)
{
    struct mm_lpc55_casper *cas = (struct mm_lpc55_casper *)opaque;

    if (cas == NULL) return MM_FALSE;
    if (size_bytes == 0u || size_bytes > 4u) return MM_FALSE;
    if ((offset + size_bytes) > CASPER_SIZE) return MM_FALSE;

    switch (offset) {
    case CAS_OFF_CTRL0:
        /* Trigger computation on write */
        casper_ctrl0_write(cas, value);
        break;

    case CAS_OFF_CTRL1:
        cas->regs[CAS_OFF_CTRL1 / 4u] = value;
        break;

    case CAS_OFF_STATUS:
        /* W1C: clear done/error bits */
        cas->regs[CAS_OFF_STATUS / 4u] &= ~(value & (STATUS_DONE | STATUS_ERROR));
        break;

    case CAS_OFF_INTENSET:
        cas->intenset |= value;
        cas->regs[CAS_OFF_INTENSET / 4u] = cas->intenset;
        break;

    case CAS_OFF_INTENCLR:
        cas->intenset &= ~value;
        cas->regs[CAS_OFF_INTENSET / 4u] = cas->intenset;
        cas->regs[CAS_OFF_INTENCLR / 4u] = 0u;  /* write-only, reads 0 */
        break;

    default:
        /* All other registers: plain store (AREG, BREG, CREG, DREG, RES0..3, LOADER, MASK etc.) */
        if ((offset + size_bytes) <= CASPER_SIZE) {
            memcpy((mm_u8 *)cas->regs + offset, &value, size_bytes);
        }
        break;
    }

    return MM_TRUE;
}
