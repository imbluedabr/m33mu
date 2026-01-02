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
 *
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "m33mu/pka.h"

#ifdef M33MU_HAS_WOLFSSL
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/integer.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#endif

#define PKA_CR_OFFSET 0x000u
#define PKA_SR_OFFSET 0x004u
#define PKA_CLRFR_OFFSET 0x008u

#define PKA_CR_EN     (1u << 0)
#define PKA_CR_START  (1u << 1)
#define PKA_CR_MODE_SHIFT 8u
#define PKA_CR_MODE_MASK (0x3Fu << PKA_CR_MODE_SHIFT)
#define PKA_CR_PROCENDIE (1u << 17)
#define PKA_CR_RAMERRIE  (1u << 19)
#define PKA_CR_ADDRERRIE (1u << 20)
#define PKA_CR_OPERRIE   (1u << 21)

#define PKA_SR_INITOK  (1u << 0)
#define PKA_SR_BUSY    (1u << 16)
#define PKA_SR_PROCENDF (1u << 17)
#define PKA_SR_RAMERRF  (1u << 19)
#define PKA_SR_ADDRERRF (1u << 20)
#define PKA_SR_OPERRF   (1u << 21)

#define PKA_CLRFR_PROCENDFC (1u << 17)
#define PKA_CLRFR_RAMERRFC  (1u << 19)
#define PKA_CLRFR_ADDRERRFC (1u << 20)
#define PKA_CLRFR_OPERRFC   (1u << 21)

/* PKA RAM parameter offsets (from PKA base) */
#define PKA_RAM_EXP_LEN          0x400u
#define PKA_RAM_OP_LEN           0x408u
#define PKA_RAM_MOD_LEN          0x408u
#define PKA_RAM_MODRED_OP_LEN    0x400u
#define PKA_RAM_ECC_N_LEN        0x400u
#define PKA_RAM_ECC_P_LEN        0x408u
#define PKA_RAM_A_SIGN           0x410u
#define PKA_RAM_A_COEFF          0x418u
#define PKA_RAM_MONT_R2          0x620u

/* Modular ops */
#define PKA_RAM_MOD_A            0xA50u
#define PKA_RAM_MOD_B            0xC68u
#define PKA_RAM_MOD_N            0x1088u
#define PKA_RAM_MOD_RES          0xE78u
#define PKA_RAM_MOD_EXP_A        0xC68u
#define PKA_RAM_MOD_EXP_E        0xE78u
#define PKA_RAM_MOD_EXP_N        0x1088u
#define PKA_RAM_MOD_EXP_RES      0x838u

/* Modular exp protected mode */
#define PKA_RAM_PROT_A           0x16C8u
#define PKA_RAM_PROT_E           0x14B8u
#define PKA_RAM_PROT_N           0x0838u
#define PKA_RAM_PROT_PHI         0x0C68u
#define PKA_RAM_PROT_RES         0x838u
#define PKA_RAM_PROT_ERR         0x1298u

/* RSA CRT */
#define PKA_RAM_RSA_DP           0x730u
#define PKA_RAM_RSA_DQ           0xE78u
#define PKA_RAM_RSA_QINV         0x948u
#define PKA_RAM_RSA_P            0xB60u
#define PKA_RAM_RSA_Q            0x1088u
#define PKA_RAM_RSA_A            0x12A0u
#define PKA_RAM_RSA_RES          0x838u

/* ECC point check */
#define PKA_RAM_PC_P             0x470u
#define PKA_RAM_PC_B             0x520u
#define PKA_RAM_PC_X             0x578u
#define PKA_RAM_PC_Y             0x5D0u
#define PKA_RAM_PC_ERR           0x680u

/* ECC scalar mul */
#define PKA_RAM_ECC_P            0x1088u
#define PKA_RAM_ECC_K            0x12A0u
#define PKA_RAM_ECC_X            0x578u
#define PKA_RAM_ECC_Y            0x470u
#define PKA_RAM_ECC_N            0xF88u
#define PKA_RAM_ECC_RES_X        0x578u
#define PKA_RAM_ECC_RES_Y        0x5D0u
#define PKA_RAM_ECC_ERR          0x680u

/* ECDSA sign */
#define PKA_RAM_SIGN_P           0x1088u
#define PKA_RAM_SIGN_K           0x12A0u
#define PKA_RAM_SIGN_GX          0x578u
#define PKA_RAM_SIGN_GY          0x470u
#define PKA_RAM_SIGN_HASH        0xFE8u
#define PKA_RAM_SIGN_D           0xF28u
#define PKA_RAM_SIGN_N           0xF88u
#define PKA_RAM_SIGN_R           0x730u
#define PKA_RAM_SIGN_S           0x788u
#define PKA_RAM_SIGN_ERR         0xFE0u
#define PKA_RAM_SIGN_KGX         0x1400u
#define PKA_RAM_SIGN_KGY         0x1458u

/* ECDSA verify */
#define PKA_RAM_VERIF_N_LEN      0x408u
#define PKA_RAM_VERIF_P_LEN      0x4C8u
#define PKA_RAM_VERIF_A_SIGN     0x468u
#define PKA_RAM_VERIF_A          0x470u
#define PKA_RAM_VERIF_P          0x4D0u
#define PKA_RAM_VERIF_GX         0x678u
#define PKA_RAM_VERIF_GY         0x6D0u
#define PKA_RAM_VERIF_QX         0x12F8u
#define PKA_RAM_VERIF_QY         0x1350u
#define PKA_RAM_VERIF_R          0x10E0u
#define PKA_RAM_VERIF_S          0xC68u
#define PKA_RAM_VERIF_HASH       0x13A8u
#define PKA_RAM_VERIF_N          0x1088u
#define PKA_RAM_VERIF_RES        0x5D0u
#define PKA_RAM_VERIF_RCALC      0x578u

/* ECC complete add */
#define PKA_RAM_ADD_P            0x470u
#define PKA_RAM_ADD_P1X          0x628u
#define PKA_RAM_ADD_P1Y          0x680u
#define PKA_RAM_ADD_P1Z          0x6D8u
#define PKA_RAM_ADD_P2X          0x730u
#define PKA_RAM_ADD_P2Y          0x788u
#define PKA_RAM_ADD_P2Z          0x7E0u
#define PKA_RAM_ADD_RX           0xD60u
#define PKA_RAM_ADD_RY           0xDB8u
#define PKA_RAM_ADD_RZ           0xE10u

/* ECC double base ladder */
#define PKA_RAM_DBL_K            0x520u
#define PKA_RAM_DBL_M            0x578u
#define PKA_RAM_DBL_P1X          0x628u
#define PKA_RAM_DBL_P1Y          0x680u
#define PKA_RAM_DBL_P1Z          0x6D8u
#define PKA_RAM_DBL_P2X          0x730u
#define PKA_RAM_DBL_P2Y          0x788u
#define PKA_RAM_DBL_P2Z          0x7E0u
#define PKA_RAM_DBL_RX           0x578u
#define PKA_RAM_DBL_RY           0x5D0u
#define PKA_RAM_DBL_ERR          0x520u

/* ECC projective to affine */
#define PKA_RAM_PROJ_P           0x470u
#define PKA_RAM_PROJ_X           0xD60u
#define PKA_RAM_PROJ_Y           0xDB8u
#define PKA_RAM_PROJ_Z           0xE10u
#define PKA_RAM_PROJ_RX          0x578u
#define PKA_RAM_PROJ_RY          0x5D0u
#define PKA_RAM_PROJ_ERR         0x680u

#define PKA_STATUS_OK 0xD60Dul
#define PKA_STATUS_FAIL 0xCBC9ul
#define PKA_STATUS_POINT_OFF 0xA3B7ul
#define PKA_STATUS_SIG_S_ZERO 0xF946ul

#define M33MU_PKA_DISABLED 1

#if !defined(M33MU_PKA_DISABLED)
static mm_bool pka_ram_in_range(mm_u32 offset, mm_u32 size_bytes)
{
    if (offset < M33MU_PKA_RAM_OFFSET) return MM_FALSE;
    if (offset + size_bytes > (M33MU_PKA_RAM_OFFSET + M33MU_PKA_RAM_BYTES)) return MM_FALSE;
    if ((offset & 3u) != 0u) return MM_FALSE;
    if (size_bytes != 4u) return MM_FALSE;
    return MM_TRUE;
}

static mm_u32 pka_ram_index(mm_u32 offset)
{
    return (offset - M33MU_PKA_RAM_OFFSET) / 4u;
}

static mm_u32 pka_read_u32(const struct pka_state *pka, mm_u32 offset)
{
    return pka->ram[pka_ram_index(offset)];
}

static void pka_write_u64(struct pka_state *pka, mm_u32 offset, mm_u64 value)
{
    mm_u32 idx = pka_ram_index(offset);
    pka->ram[idx] = (mm_u32)(value & 0xffffffffu);
    pka->ram[idx + 1u] = (mm_u32)((value >> 32) & 0xffffffffu);
}

static void pka_read_bytes_be(const struct pka_state *pka, mm_u32 offset, mm_u8 *dst, mm_u32 size)
{
    mm_u32 idx = pka_ram_index(offset);
    mm_u32 word;
    mm_u32 i = 0u;
    mm_u32 pos;
    for (; i < (size / 4u); ++i) {
        word = pka->ram[idx + i];
        pos = size - 4u - (i * 4u);
        dst[pos + 3u] = (mm_u8)(word & 0xffu);
        dst[pos + 2u] = (mm_u8)((word >> 8) & 0xffu);
        dst[pos + 1u] = (mm_u8)((word >> 16) & 0xffu);
        dst[pos + 0u] = (mm_u8)((word >> 24) & 0xffu);
    }
    if ((size % 4u) != 0u) {
        word = pka->ram[idx + i];
        if ((size % 4u) == 1u) {
            dst[0u] = (mm_u8)(word & 0xffu);
        } else if ((size % 4u) == 2u) {
            dst[1u] = (mm_u8)(word & 0xffu);
            dst[0u] = (mm_u8)((word >> 8) & 0xffu);
        } else {
            dst[2u] = (mm_u8)(word & 0xffu);
            dst[1u] = (mm_u8)((word >> 8) & 0xffu);
            dst[0u] = (mm_u8)((word >> 16) & 0xffu);
        }
    }
}

static void pka_write_bytes_be(struct pka_state *pka, mm_u32 offset, const mm_u8 *src, mm_u32 size)
{
    mm_u32 idx = pka_ram_index(offset);
    mm_u32 i = 0u;
    for (; i < (size / 4u); ++i) {
        pka->ram[idx + i] = ((mm_u32)src[(size - (i * 4u) - 1u)]) |
                            ((mm_u32)src[(size - (i * 4u) - 2u)] << 8u) |
                            ((mm_u32)src[(size - (i * 4u) - 3u)] << 16u) |
                            ((mm_u32)src[(size - (i * 4u) - 4u)] << 24u);
    }
    if ((size % 4u) != 0u) {
        if ((size % 4u) == 1u) {
            pka->ram[idx + i] = src[0u];
        } else if ((size % 4u) == 2u) {
            pka->ram[idx + i] = ((mm_u32)src[0u] << 8u) | src[1u];
        } else {
            pka->ram[idx + i] = ((mm_u32)src[0u] << 16u) | ((mm_u32)src[1u] << 8u) | src[2u];
        }
    }
}

#ifdef M33MU_HAS_WOLFSSL
static mm_bool pka_read_mp(const struct pka_state *pka, mm_u32 offset, mm_u32 size_bytes, mp_int *out)
{
    mm_u8 *buf;
    if (size_bytes == 0u) {
        mp_zero(out);
        return MM_TRUE;
    }
    buf = (mm_u8 *)malloc(size_bytes);
    if (buf == 0) return MM_FALSE;
    pka_read_bytes_be(pka, offset, buf, size_bytes);
    mp_read_unsigned_bin(out, buf, (word32)size_bytes);
    free(buf);
    return MM_TRUE;
}

static mm_bool pka_ecc_curve_supported(const mp_int *p, const mp_int *a,
                                       const mp_int *b, const mp_int *n)
{
    static const char *const curves[][4] = {
        /* secp256r1 / P-256 */
        {
            "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
            "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
            "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        },
    };
    size_t i;
    mm_bool ok = MM_FALSE;

    for (i = 0; i < (sizeof(curves) / sizeof(curves[0])); ++i) {
        mp_int tp;
        mp_int ta;
        mp_int tb;
        mp_int tn;
        int ret;
        ret = mp_init(&tp);
        if (ret != MP_OKAY) continue;
        ret = mp_init(&ta);
        if (ret != MP_OKAY) {
            mp_clear(&tp);
            continue;
        }
        ret = mp_init(&tb);
        if (ret != MP_OKAY) {
            mp_clear(&ta);
            mp_clear(&tp);
            continue;
        }
        ret = mp_init(&tn);
        if (ret != MP_OKAY) {
            mp_clear(&tb);
            mp_clear(&ta);
            mp_clear(&tp);
            continue;
        }
        ret = mp_read_radix(&tp, curves[i][0], MP_RADIX_HEX);
        if (ret == MP_OKAY) ret = mp_read_radix(&ta, curves[i][1], MP_RADIX_HEX);
        if (ret == MP_OKAY) ret = mp_read_radix(&tb, curves[i][2], MP_RADIX_HEX);
        if (ret == MP_OKAY) ret = mp_read_radix(&tn, curves[i][3], MP_RADIX_HEX);
        if (ret == MP_OKAY &&
            mp_cmp(p, &tp) == MP_EQ &&
            mp_cmp(a, &ta) == MP_EQ &&
            mp_cmp(b, &tb) == MP_EQ &&
            mp_cmp(n, &tn) == MP_EQ) {
            ok = MM_TRUE;
        }
        mp_clear(&tn);
        mp_clear(&tb);
        mp_clear(&ta);
        mp_clear(&tp);
        if (ok) break;
    }

    return ok;
}

static mm_bool pka_write_mp(struct pka_state *pka, mm_u32 offset, mm_u32 size_bytes, const mp_int *in)
{
    mm_u8 *buf;
    int bin_size;
    if (size_bytes == 0u) return MM_TRUE;
    buf = (mm_u8 *)calloc(1u, size_bytes);
    if (buf == 0) return MM_FALSE;
    bin_size = mp_unsigned_bin_size(in);
    if (bin_size > (int)size_bytes) {
        bin_size = (int)size_bytes;
    }
    if (bin_size > 0) {
        mp_to_unsigned_bin(in, buf + (size_bytes - (mm_u32)bin_size));
    }
    pka_write_bytes_be(pka, offset, buf, size_bytes);
    free(buf);
    return MM_TRUE;
}

static void pka_ecc_point_from_ram(ecc_point *pt, const struct pka_state *pka,
                                   mm_u32 x_off, mm_u32 y_off, mm_u32 z_off,
                                   mm_u32 size_bytes)
{
    mp_int tmp;
    if (mp_init(&tmp) != MP_OKAY) return;
    if (pka_read_mp(pka, x_off, size_bytes, &tmp)) {
        (void)mp_copy(&tmp, pt->x);
    }
    if (z_off != 0u) {
        if (pka_read_mp(pka, z_off, size_bytes, &tmp)) {
            (void)mp_copy(&tmp, pt->z);
        }
    } else {
        pt->z->dp[0] = 1u;
        pt->z->used = 1;
        pt->z->sign = MP_ZPOS;
    }
    if (pka_read_mp(pka, y_off, size_bytes, &tmp)) {
        (void)mp_copy(&tmp, pt->y);
    }
    mp_clear(&tmp);
}

static void pka_ecc_point_to_ram(const ecc_point *pt, struct pka_state *pka,
                                 mm_u32 x_off, mm_u32 y_off, mm_u32 z_off,
                                 mm_u32 size_bytes)
{
    pka_write_mp(pka, x_off, size_bytes, pt->x);
    pka_write_mp(pka, y_off, size_bytes, pt->y);
    if (z_off != 0u) {
        pka_write_mp(pka, z_off, size_bytes, pt->z);
    }
}
#endif

static mm_bool pka_mode_supported(mm_u32 mode)
{
    switch (mode) {
    case 0x00u:
    case 0x01u:
    case 0x02u:
    case 0x03u:
    case 0x07u:
    case 0x08u:
    case 0x09u:
    case 0x0Au:
    case 0x0Bu:
    case 0x0Cu:
    case 0x0Du:
    case 0x0Eu:
    case 0x0Fu:
    case 0x10u:
    case 0x20u:
    case 0x23u:
    case 0x24u:
    case 0x26u:
    case 0x27u:
    case 0x28u:
    case 0x2Fu:
        return MM_TRUE;
    default:
        return MM_FALSE;
    }
}

static void pka_set_flag(struct pka_state *pka, mm_u32 flag)
{
    pka->sr |= flag;
}

static void pka_clear_flag(struct pka_state *pka, mm_u32 flag)
{
    pka->sr &= ~flag;
}

static void pka_write_status_code(struct pka_state *pka, mm_u32 offset, mm_u32 code)
{
    pka_write_u64(pka, offset, (mm_u64)code);
}

static void pka_execute(struct pka_state *pka, mm_u32 mode)
{
#ifdef M33MU_HAS_WOLFSSL
    int ret = 0;
    mp_int a;
    mp_int b;
    mp_int n;
    mp_int tmp1;
    mp_int tmp2;
    mp_int tmp3;
    mp_int tmp4;
    mm_u64 bits64;
    mm_u32 bits;
    mm_u32 bytes;
    mm_u32 words;
    mm_u32 extra;
    mp_init(&a);
    mp_init(&b);
    mp_init(&n);
    mp_init(&tmp1);
    mp_init(&tmp2);
    mp_init(&tmp3);
    mp_init(&tmp4);
    (void)mode;

    switch (mode) {
    case 0x01u: /* Montgomery parameter */
        bits64 = pka_read_u32(pka, PKA_RAM_MOD_LEN);
        bits = (mm_u32)bits64;
        bytes = (bits + 7u) / 8u;
        pka_read_mp(pka, PKA_RAM_MOD_N, bytes, &n);
        mp_2expt(&tmp1, (int)(bits * 2u));
        mp_mod(&tmp1, &n, &tmp2);
        pka_write_mp(pka, PKA_RAM_MONT_R2, (bits + 31u) / 32u * 4u, &tmp2);
        break;
    case 0x0Eu: /* Modular add */
    case 0x0Fu: /* Modular sub */
    case 0x10u: /* Montgomery mul */
        bits64 = pka_read_u32(pka, PKA_RAM_OP_LEN);
        bits = (mm_u32)bits64;
        bytes = (bits + 7u) / 8u;
        pka_read_mp(pka, PKA_RAM_MOD_A, bytes, &a);
        pka_read_mp(pka, PKA_RAM_MOD_B, bytes, &b);
        pka_read_mp(pka, PKA_RAM_MOD_N, bytes, &n);
        if (mode == 0x0Eu) {
            mp_addmod(&a, &b, &n, &tmp1);
        } else if (mode == 0x0Fu) {
            mp_submod(&a, &b, &n, &tmp1);
        } else {
            mp_mulmod(&a, &b, &n, &tmp1);
        }
        pka_write_mp(pka, PKA_RAM_MOD_RES, (bits + 31u) / 32u * 4u, &tmp1);
        break;
    case 0x00u: /* Modular exponentiation */
    case 0x02u: /* Fast mode */
        bits64 = pka_read_u32(pka, PKA_RAM_OP_LEN);
        bits = (mm_u32)bits64;
        bytes = (bits + 7u) / 8u;
        pka_read_mp(pka, PKA_RAM_MOD_EXP_A, bytes, &a);
        pka_read_mp(pka, PKA_RAM_MOD_EXP_E, (mm_u32)((pka_read_u32(pka, PKA_RAM_EXP_LEN) + 7u) / 8u), &b);
        pka_read_mp(pka, PKA_RAM_MOD_EXP_N, bytes, &n);
        mp_exptmod(&a, &b, &n, &tmp1);
        pka_write_mp(pka, PKA_RAM_MOD_EXP_RES, (bits + 31u) / 32u * 4u, &tmp1);
        break;
    case 0x03u: /* Modular exponentiation protected */
        bits64 = pka_read_u32(pka, PKA_RAM_OP_LEN);
        bits = (mm_u32)bits64;
        bytes = (bits + 7u) / 8u;
        pka_read_mp(pka, PKA_RAM_PROT_A, bytes, &a);
        pka_read_mp(pka, PKA_RAM_PROT_E, (mm_u32)((pka_read_u32(pka, PKA_RAM_EXP_LEN) + 7u) / 8u), &b);
        pka_read_mp(pka, PKA_RAM_PROT_N, bytes, &n);
        ret = mp_exptmod(&a, &b, &n, &tmp1);
        if (ret == MP_OKAY) {
            pka_write_mp(pka, PKA_RAM_PROT_RES, (bits + 31u) / 32u * 4u, &tmp1);
            pka_write_status_code(pka, PKA_RAM_PROT_ERR, PKA_STATUS_OK);
        } else {
            pka_write_status_code(pka, PKA_RAM_PROT_ERR, PKA_STATUS_FAIL);
        }
        break;
    case 0x08u: /* Modular inversion */
        bits64 = pka_read_u32(pka, PKA_RAM_OP_LEN);
        bits = (mm_u32)bits64;
        bytes = (bits + 7u) / 8u;
        pka_read_mp(pka, PKA_RAM_MOD_A, bytes, &a);
        pka_read_mp(pka, PKA_RAM_MOD_B, bytes, &n);
        mp_invmod(&a, &n, &tmp1);
        pka_write_mp(pka, PKA_RAM_MOD_RES, (bits + 31u) / 32u * 4u, &tmp1);
        break;
    case 0x0Du: /* Modular reduction */
        bits64 = pka_read_u32(pka, PKA_RAM_MODRED_OP_LEN);
        bits = (mm_u32)bits64;
        bytes = (bits + 7u) / 8u;
        pka_read_mp(pka, PKA_RAM_MOD_A, bytes, &a);
        bits64 = pka_read_u32(pka, PKA_RAM_MOD_LEN);
        bits = (mm_u32)bits64;
        bytes = (bits + 7u) / 8u;
        pka_read_mp(pka, PKA_RAM_MOD_B, bytes, &n);
        mp_mod(&a, &n, &tmp1);
        pka_write_mp(pka, PKA_RAM_MOD_RES, (bits + 31u) / 32u * 4u, &tmp1);
        break;
    case 0x09u: /* Arithmetic add */
        bits64 = pka_read_u32(pka, PKA_RAM_OP_LEN);
        bits = (mm_u32)bits64;
        bytes = (bits + 7u) / 8u;
        words = (bits + 31u) / 32u;
        pka_read_mp(pka, PKA_RAM_MOD_A, bytes, &a);
        pka_read_mp(pka, PKA_RAM_MOD_B, bytes, &b);
        mp_add(&a, &b, &tmp1);
        extra = (mp_count_bits(&tmp1) > (int)(words * 32u)) ? 1u : 0u;
        pka_write_mp(pka, PKA_RAM_MOD_RES, (words + extra) * 4u, &tmp1);
        break;
    case 0x0Au: /* Arithmetic sub */
        bits64 = pka_read_u32(pka, PKA_RAM_OP_LEN);
        bits = (mm_u32)bits64;
        bytes = (bits + 7u) / 8u;
        words = (bits + 31u) / 32u;
        pka_read_mp(pka, PKA_RAM_MOD_A, bytes, &a);
        pka_read_mp(pka, PKA_RAM_MOD_B, bytes, &b);
        if (mp_cmp(&a, &b) >= 0) {
            mp_sub(&a, &b, &tmp1);
            pka_write_mp(pka, PKA_RAM_MOD_RES, words * 4u, &tmp1);
        } else {
            mp_2expt(&tmp2, (int)(words * 32u));
            mp_add(&a, &tmp2, &tmp3);
            mp_sub(&tmp3, &b, &tmp1);
            pka_write_mp(pka, PKA_RAM_MOD_RES, words * 4u, &tmp1);
            pka->ram[pka_ram_index(PKA_RAM_MOD_RES) + words] = 0xffffffffu;
        }
        break;
    case 0x0Bu: /* Arithmetic mul */
        bits64 = pka_read_u32(pka, PKA_RAM_OP_LEN);
        bits = (mm_u32)bits64;
        bytes = (bits + 7u) / 8u;
        words = (bits + 31u) / 32u;
        pka_read_mp(pka, PKA_RAM_MOD_A, bytes, &a);
        pka_read_mp(pka, PKA_RAM_MOD_B, bytes, &b);
        mp_mul(&a, &b, &tmp1);
        pka_write_mp(pka, PKA_RAM_MOD_RES, (words * 2u) * 4u, &tmp1);
        break;
    case 0x0Cu: /* Comparison */
        bits64 = pka_read_u32(pka, PKA_RAM_OP_LEN);
        bits = (mm_u32)bits64;
        bytes = (bits + 7u) / 8u;
        pka_read_mp(pka, PKA_RAM_MOD_A, bytes, &a);
        pka_read_mp(pka, PKA_RAM_MOD_B, bytes, &b);
        if (mp_cmp(&a, &b) == 0) {
            pka_write_u64(pka, PKA_RAM_MOD_RES, 0xED2Cul);
        } else if (mp_cmp(&a, &b) > 0) {
            pka_write_u64(pka, PKA_RAM_MOD_RES, 0x7AF8ul);
        } else {
            pka_write_u64(pka, PKA_RAM_MOD_RES, 0x916Aul);
        }
        break;
    case 0x07u: /* RSA CRT exponentiation */
        bits64 = pka_read_u32(pka, PKA_RAM_OP_LEN);
        bits = (mm_u32)bits64;
        bytes = (bits + 7u) / 8u;
        words = bytes / 2u;
        pka_read_mp(pka, PKA_RAM_RSA_DP, words, &a);
        pka_read_mp(pka, PKA_RAM_RSA_DQ, words, &b);
        pka_read_mp(pka, PKA_RAM_RSA_QINV, words, &tmp1);
        pka_read_mp(pka, PKA_RAM_RSA_P, words, &tmp2);
        pka_read_mp(pka, PKA_RAM_RSA_Q, words, &tmp3);
        pka_read_mp(pka, PKA_RAM_RSA_A, bytes, &tmp4);
        mp_exptmod(&tmp4, &a, &tmp2, &a);
        mp_exptmod(&tmp4, &b, &tmp3, &b);
        mp_sub(&a, &b, &tmp4);
        mp_mod(&tmp4, &tmp2, &tmp4);
        mp_mulmod(&tmp4, &tmp1, &tmp2, &tmp4);
        mp_mul(&tmp4, &tmp3, &tmp4);
        mp_add(&b, &tmp4, &tmp4);
        pka_write_mp(pka, PKA_RAM_RSA_RES, bytes, &tmp4);
        break;
    case 0x28u: /* Point check */
    {
        ecc_point *pt;
        mp_int aa;
        mp_int bb;
        mp_int pp;
        mp_int xx;
        mp_int yy;
        mp_int lhs;
        mp_int rhs;
        mp_int tmp;
        mm_u32 a_sign;
        bits64 = pka_read_u32(pka, PKA_RAM_OP_LEN);
        bits = (mm_u32)bits64;
        bytes = (bits + 7u) / 8u;
        a_sign = pka->ram[pka_ram_index(PKA_RAM_A_SIGN)];
        mp_init(&aa);
        mp_init(&bb);
        mp_init(&pp);
        mp_init(&xx);
        mp_init(&yy);
        mp_init(&lhs);
        mp_init(&rhs);
        mp_init(&tmp);
        pka_read_mp(pka, PKA_RAM_A_COEFF, bytes, &aa);
        pka_read_mp(pka, PKA_RAM_PC_B, bytes, &bb);
        pka_read_mp(pka, PKA_RAM_PC_P, bytes, &pp);
        pka_read_mp(pka, PKA_RAM_PC_X, bytes, &xx);
        pka_read_mp(pka, PKA_RAM_PC_Y, bytes, &yy);
        if (mp_cmp(&xx, &pp) >= 0 || mp_cmp(&yy, &pp) >= 0) {
            pka_write_status_code(pka, PKA_RAM_PC_ERR, PKA_STATUS_SIG_S_ZERO);
        } else {
            if (a_sign != 0u) {
                mp_sub(&pp, &aa, &aa);
                mp_mod(&aa, &pp, &aa);
            }
            mp_mulmod(&yy, &yy, &pp, &lhs);
            mp_mulmod(&xx, &xx, &pp, &tmp);
            mp_mulmod(&tmp, &xx, &pp, &rhs);
            mp_mulmod(&aa, &xx, &pp, &tmp);
            mp_addmod(&rhs, &tmp, &pp, &rhs);
            mp_addmod(&rhs, &bb, &pp, &rhs);
            if (mp_cmp(&lhs, &rhs) == 0) {
                pka_write_status_code(pka, PKA_RAM_PC_ERR, PKA_STATUS_OK);
            } else {
                pka_write_status_code(pka, PKA_RAM_PC_ERR, PKA_STATUS_POINT_OFF);
            }
        }
        mp_clear(&aa);
        mp_clear(&bb);
        mp_clear(&pp);
        mp_clear(&xx);
        mp_clear(&yy);
        mp_clear(&lhs);
        mp_clear(&rhs);
        mp_clear(&tmp);
        pt = 0;
        (void)pt;
        break;
    }
    case 0x20u: /* ECC scalar multiplication */
    {
        ecc_point *P;
        ecc_point *R;
        mp_int aa;
        mp_int bb;
        mp_int pp;
        mp_int nn;
        mp_int kk;
        mm_u32 a_sign;
        bits64 = pka_read_u32(pka, PKA_RAM_ECC_P_LEN);
        bits = (mm_u32)bits64;
        bytes = (bits + 7u) / 8u;
        a_sign = pka->ram[pka_ram_index(PKA_RAM_A_SIGN)];
        mp_init(&aa);
        mp_init(&bb);
        mp_init(&pp);
        mp_init(&nn);
        mp_init(&kk);
        pka_read_mp(pka, PKA_RAM_A_COEFF, bytes, &aa);
        pka_read_mp(pka, PKA_RAM_PC_B, bytes, &bb);
        pka_read_mp(pka, PKA_RAM_ECC_P, bytes, &pp);
        pka_read_mp(pka, PKA_RAM_ECC_N, (mm_u32)((pka_read_u32(pka, PKA_RAM_ECC_N_LEN) + 7u) / 8u), &nn);
        pka_read_mp(pka, PKA_RAM_ECC_K, bytes, &kk);
        if (a_sign != 0u) {
            mp_sub(&pp, &aa, &aa);
            mp_mod(&aa, &pp, &aa);
        }
        if (!pka_ecc_curve_supported(&pp, &aa, &bb, &nn)) {
            pka_write_status_code(pka, PKA_RAM_ECC_ERR, PKA_STATUS_FAIL);
            mp_clear(&kk);
            mp_clear(&nn);
            mp_clear(&pp);
            mp_clear(&bb);
            mp_clear(&aa);
            break;
        }
        P = wc_ecc_new_point();
        R = wc_ecc_new_point();
        if (P == 0 || R == 0) {
            pka_write_status_code(pka, PKA_RAM_ECC_ERR, PKA_STATUS_FAIL);
            break;
        }
        pka_ecc_point_from_ram(P, pka, PKA_RAM_ECC_X, PKA_RAM_ECC_Y, 0u, bytes);
        ret = wc_ecc_mulmod_ex(&kk, P, R, &aa, &pp, 1, NULL);
        if (ret == 0) {
            pka_ecc_point_to_ram(R, pka, PKA_RAM_ECC_RES_X, PKA_RAM_ECC_RES_Y, 0u, bytes);
            pka_write_status_code(pka, PKA_RAM_ECC_ERR, PKA_STATUS_OK);
        } else {
            pka_write_status_code(pka, PKA_RAM_ECC_ERR, PKA_STATUS_FAIL);
        }
        wc_ecc_del_point(P);
        wc_ecc_del_point(R);
        mp_clear(&aa);
        mp_clear(&bb);
        mp_clear(&pp);
        mp_clear(&nn);
        mp_clear(&kk);
        break;
    }
    case 0x24u: /* ECDSA sign */
    {
        ecc_point *G;
        ecc_point *R;
        mp_int aa;
        mp_int pp;
        mp_int nn;
        mp_int kk;
        mp_int dd;
        mp_int zz;
        mp_int rr;
        mp_int ss;
        mp_int kinv;
        mp_digit mp;
        mm_u32 a_sign;
        mm_u32 n_bits;
        bits64 = pka_read_u32(pka, PKA_RAM_ECC_P_LEN);
        bits = (mm_u32)bits64;
        bytes = (bits + 7u) / 8u;
        n_bits = pka_read_u32(pka, PKA_RAM_ECC_N_LEN);
        a_sign = pka->ram[pka_ram_index(PKA_RAM_A_SIGN)];
        mp_init(&aa);
        mp_init(&pp);
        mp_init(&nn);
        mp_init(&kk);
        mp_init(&dd);
        mp_init(&zz);
        mp_init(&rr);
        mp_init(&ss);
        mp_init(&kinv);
        pka_read_mp(pka, PKA_RAM_A_COEFF, bytes, &aa);
        pka_read_mp(pka, PKA_RAM_SIGN_P, bytes, &pp);
        pka_read_mp(pka, PKA_RAM_SIGN_N, (n_bits + 7u) / 8u, &nn);
        pka_read_mp(pka, PKA_RAM_SIGN_K, bytes, &kk);
        pka_read_mp(pka, PKA_RAM_SIGN_D, (n_bits + 7u) / 8u, &dd);
        pka_read_mp(pka, PKA_RAM_SIGN_HASH, (n_bits + 7u) / 8u, &zz);
        if (a_sign != 0u) {
            mp_sub(&pp, &aa, &aa);
            mp_mod(&aa, &pp, &aa);
        }
        G = wc_ecc_new_point();
        R = wc_ecc_new_point();
        if (G == 0 || R == 0) {
            pka_write_status_code(pka, PKA_RAM_SIGN_ERR, PKA_STATUS_FAIL);
            break;
        }
        pka_ecc_point_from_ram(G, pka, PKA_RAM_SIGN_GX, PKA_RAM_SIGN_GY, 0u, bytes);
        mp_montgomery_setup(&pp, &mp);
        ret = wc_ecc_mulmod_ex2(&kk, G, R, &aa, &pp, &nn, NULL, 1, NULL);
        if (ret != 0) {
            pka_write_status_code(pka, PKA_RAM_SIGN_ERR, PKA_STATUS_FAIL);
        } else {
            pka_write_mp(pka, PKA_RAM_SIGN_KGX, bytes, R->x);
            pka_write_mp(pka, PKA_RAM_SIGN_KGY, bytes, R->y);
            mp_mod(R->x, &nn, &rr);
            if (mp_iszero(&rr) == MP_YES) {
                pka_write_status_code(pka, PKA_RAM_SIGN_ERR, PKA_STATUS_POINT_OFF);
            } else {
                mp_invmod(&kk, &nn, &kinv);
                mp_mulmod(&rr, &dd, &nn, &tmp1);
                mp_addmod(&zz, &tmp1, &nn, &tmp2);
                mp_mulmod(&kinv, &tmp2, &nn, &ss);
                if (mp_iszero(&ss) == MP_YES) {
                    pka_write_status_code(pka, PKA_RAM_SIGN_ERR, PKA_STATUS_SIG_S_ZERO);
                } else {
                    pka_write_mp(pka, PKA_RAM_SIGN_R, (n_bits + 31u) / 32u * 4u, &rr);
                    pka_write_mp(pka, PKA_RAM_SIGN_S, (n_bits + 31u) / 32u * 4u, &ss);
                    pka_write_status_code(pka, PKA_RAM_SIGN_ERR, PKA_STATUS_OK);
                }
            }
        }
        wc_ecc_del_point(G);
        wc_ecc_del_point(R);
        mp_clear(&aa);
        mp_clear(&pp);
        mp_clear(&nn);
        mp_clear(&kk);
        mp_clear(&dd);
        mp_clear(&zz);
        mp_clear(&rr);
        mp_clear(&ss);
        mp_clear(&kinv);
        break;
    }
    case 0x26u: /* ECDSA verify */
    {
        ecc_point *G;
        ecc_point *Q;
        ecc_point *R;
        mp_int aa;
        mp_int pp;
        mp_int nn;
        mp_int rr;
        mp_int ss;
        mp_int zz;
        mp_int w;
        mp_int u1;
        mp_int u2;
        mp_int v;
        mm_u32 a_sign;
        mm_u32 n_bits;
        bits64 = pka_read_u32(pka, PKA_RAM_VERIF_P_LEN);
        bits = (mm_u32)bits64;
        bytes = (bits + 7u) / 8u;
        n_bits = pka_read_u32(pka, PKA_RAM_VERIF_N_LEN);
        a_sign = pka->ram[pka_ram_index(PKA_RAM_VERIF_A_SIGN)];
        mp_init(&aa);
        mp_init(&pp);
        mp_init(&nn);
        mp_init(&rr);
        mp_init(&ss);
        mp_init(&zz);
        mp_init(&w);
        mp_init(&u1);
        mp_init(&u2);
        mp_init(&v);
        pka_read_mp(pka, PKA_RAM_VERIF_A, bytes, &aa);
        pka_read_mp(pka, PKA_RAM_VERIF_P, bytes, &pp);
        pka_read_mp(pka, PKA_RAM_VERIF_N, (n_bits + 7u) / 8u, &nn);
        pka_read_mp(pka, PKA_RAM_VERIF_R, (n_bits + 7u) / 8u, &rr);
        pka_read_mp(pka, PKA_RAM_VERIF_S, (n_bits + 7u) / 8u, &ss);
        pka_read_mp(pka, PKA_RAM_VERIF_HASH, (n_bits + 7u) / 8u, &zz);
        if (a_sign != 0u) {
            mp_sub(&pp, &aa, &aa);
            mp_mod(&aa, &pp, &aa);
        }
        G = wc_ecc_new_point();
        Q = wc_ecc_new_point();
        R = wc_ecc_new_point();
        if (G == 0 || Q == 0 || R == 0) {
            pka_write_status_code(pka, PKA_RAM_VERIF_RES, PKA_STATUS_FAIL);
            break;
        }
        pka_ecc_point_from_ram(G, pka, PKA_RAM_VERIF_GX, PKA_RAM_VERIF_GY, 0u, bytes);
        pka_ecc_point_from_ram(Q, pka, PKA_RAM_VERIF_QX, PKA_RAM_VERIF_QY, 0u, bytes);
        mp_invmod(&ss, &nn, &w);
        mp_mulmod(&zz, &w, &nn, &u1);
        mp_mulmod(&rr, &w, &nn, &u2);
        ret = ecc_mul2add(G, &u1, Q, &u2, R, &aa, &pp, NULL);
        if (ret == 0) {
            mp_mod(R->x, &nn, &v);
            pka_write_mp(pka, PKA_RAM_VERIF_RCALC, (n_bits + 31u) / 32u * 4u, &v);
            if (mp_cmp(&v, &rr) == 0) {
                pka_write_status_code(pka, PKA_RAM_VERIF_RES, PKA_STATUS_OK);
            } else {
                pka_write_status_code(pka, PKA_RAM_VERIF_RES, PKA_STATUS_POINT_OFF);
            }
        } else {
            pka_write_status_code(pka, PKA_RAM_VERIF_RES, PKA_STATUS_FAIL);
        }
        wc_ecc_del_point(G);
        wc_ecc_del_point(Q);
        wc_ecc_del_point(R);
        mp_clear(&aa);
        mp_clear(&pp);
        mp_clear(&nn);
        mp_clear(&rr);
        mp_clear(&ss);
        mp_clear(&zz);
        mp_clear(&w);
        mp_clear(&u1);
        mp_clear(&u2);
        mp_clear(&v);
        break;
    }
    case 0x23u: /* ECC complete addition */
    {
        ecc_point *P;
        ecc_point *Q;
        ecc_point *R;
        mp_int aa;
        mp_int pp;
        mm_u32 a_sign;
        bits64 = pka_read_u32(pka, PKA_RAM_OP_LEN);
        bits = (mm_u32)bits64;
        bytes = (bits + 7u) / 8u;
        a_sign = pka->ram[pka_ram_index(PKA_RAM_A_SIGN)];
        mp_init(&aa);
        mp_init(&pp);
        pka_read_mp(pka, PKA_RAM_A_COEFF, bytes, &aa);
        pka_read_mp(pka, PKA_RAM_ADD_P, bytes, &pp);
        if (a_sign != 0u) {
            mp_sub(&pp, &aa, &aa);
            mp_mod(&aa, &pp, &aa);
        }
        P = wc_ecc_new_point();
        Q = wc_ecc_new_point();
        R = wc_ecc_new_point();
        if (P == 0 || Q == 0 || R == 0) {
            break;
        }
        pka_ecc_point_from_ram(P, pka, PKA_RAM_ADD_P1X, PKA_RAM_ADD_P1Y, PKA_RAM_ADD_P1Z, bytes);
        pka_ecc_point_from_ram(Q, pka, PKA_RAM_ADD_P2X, PKA_RAM_ADD_P2Y, PKA_RAM_ADD_P2Z, bytes);
        ret = ecc_projective_add_point(P, Q, R, &aa, &pp, 0);
        if (ret == 0) {
            pka_ecc_point_to_ram(R, pka, PKA_RAM_ADD_RX, PKA_RAM_ADD_RY, PKA_RAM_ADD_RZ, bytes);
        }
        wc_ecc_del_point(P);
        wc_ecc_del_point(Q);
        wc_ecc_del_point(R);
        mp_clear(&aa);
        mp_clear(&pp);
        break;
    }
    case 0x27u: /* ECC double base ladder */
    {
        ecc_point *P;
        ecc_point *Q;
        ecc_point *R;
        mp_int aa;
        mp_int pp;
        mp_int kk;
        mp_int mm;
        mm_u32 a_sign;
        bits64 = pka_read_u32(pka, PKA_RAM_ECC_N_LEN);
        bits = (mm_u32)bits64;
        bytes = (bits + 7u) / 8u;
        a_sign = pka->ram[pka_ram_index(PKA_RAM_A_SIGN)];
        mp_init(&aa);
        mp_init(&pp);
        mp_init(&kk);
        mp_init(&mm);
        pka_read_mp(pka, PKA_RAM_A_COEFF, bytes, &aa);
        pka_read_mp(pka, PKA_RAM_ADD_P, bytes, &pp);
        pka_read_mp(pka, PKA_RAM_DBL_K, bytes, &kk);
        pka_read_mp(pka, PKA_RAM_DBL_M, bytes, &mm);
        if (a_sign != 0u) {
            mp_sub(&pp, &aa, &aa);
            mp_mod(&aa, &pp, &aa);
        }
        P = wc_ecc_new_point();
        Q = wc_ecc_new_point();
        R = wc_ecc_new_point();
        if (P == 0 || Q == 0 || R == 0) {
            pka_write_status_code(pka, PKA_RAM_DBL_ERR, PKA_STATUS_FAIL);
            break;
        }
        pka_ecc_point_from_ram(P, pka, PKA_RAM_DBL_P1X, PKA_RAM_DBL_P1Y, PKA_RAM_DBL_P1Z, bytes);
        pka_ecc_point_from_ram(Q, pka, PKA_RAM_DBL_P2X, PKA_RAM_DBL_P2Y, PKA_RAM_DBL_P2Z, bytes);
        ret = ecc_mul2add(P, &kk, Q, &mm, R, &aa, &pp, NULL);
        if (ret == 0) {
            ret = ecc_map(R, &pp, 0);
        }
        if (ret == 0) {
            pka_ecc_point_to_ram(R, pka, PKA_RAM_DBL_RX, PKA_RAM_DBL_RY, 0u, bytes);
            pka_write_status_code(pka, PKA_RAM_DBL_ERR, PKA_STATUS_OK);
        } else {
            pka_write_status_code(pka, PKA_RAM_DBL_ERR, PKA_STATUS_POINT_OFF);
        }
        wc_ecc_del_point(P);
        wc_ecc_del_point(Q);
        wc_ecc_del_point(R);
        mp_clear(&aa);
        mp_clear(&pp);
        mp_clear(&kk);
        mp_clear(&mm);
        break;
    }
    case 0x2Fu: /* ECC projective to affine */
    {
        ecc_point *P;
        mp_int pp;
        mp_digit mp;
        bits64 = pka_read_u32(pka, PKA_RAM_OP_LEN);
        bits = (mm_u32)bits64;
        bytes = (bits + 7u) / 8u;
        mp_init(&pp);
        pka_read_mp(pka, PKA_RAM_PROJ_P, bytes, &pp);
        P = wc_ecc_new_point();
        if (P == 0) {
            pka_write_status_code(pka, PKA_RAM_PROJ_ERR, PKA_STATUS_FAIL);
            break;
        }
        pka_ecc_point_from_ram(P, pka, PKA_RAM_PROJ_X, PKA_RAM_PROJ_Y, PKA_RAM_PROJ_Z, bytes);
        mp_montgomery_setup(&pp, &mp);
        ret = ecc_map(P, &pp, mp);
        if (ret == 0) {
            pka_ecc_point_to_ram(P, pka, PKA_RAM_PROJ_RX, PKA_RAM_PROJ_RY, 0u, bytes);
            pka_write_status_code(pka, PKA_RAM_PROJ_ERR, PKA_STATUS_OK);
        } else {
            pka_write_status_code(pka, PKA_RAM_PROJ_ERR, PKA_STATUS_POINT_OFF);
        }
        wc_ecc_del_point(P);
        mp_clear(&pp);
        break;
    }
    default:
        break;
    }

    mp_clear(&a);
    mp_clear(&b);
    mp_clear(&n);
    mp_clear(&tmp1);
    mp_clear(&tmp2);
    mp_clear(&tmp3);
    mp_clear(&tmp4);
#else
    (void)pka;
    (void)mode;
#endif
}
#endif /* !M33MU_PKA_DISABLED */

void mm_pka_reset(struct pka_state *pka)
{
    if (pka == 0) return;
    memset(pka, 0, sizeof(*pka));
}

mm_bool mm_pka_read(struct pka_state *pka, mm_u32 offset, mm_u32 size_bytes, mm_u32 *value_out)
{
    (void)pka;
    (void)offset;
    if (value_out == 0) return MM_FALSE;
    if (size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    /* PKA emulation disabled. */
    *value_out = 0u;
    return MM_TRUE;
}

mm_bool mm_pka_write(struct pka_state *pka, mm_u32 offset, mm_u32 size_bytes, mm_u32 value)
{
    (void)pka;
    (void)offset;
    (void)value;
    if (size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    /* PKA emulation disabled. */
    return MM_TRUE;
}
