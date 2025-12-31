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
#include <sys/random.h>
#include <stdlib.h>
#include <stdio.h>
#include "m33mu/pka.h"
#ifdef M33MU_HAS_WOLFSSL
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#endif
#include "stm32l552/stm32l552_mmio.h"
#include "stm32l552/stm32l552_usb.h"
#include "m33mu/memmap.h"
#include "m33mu/flash_persist.h"
#include "m33mu/gpio.h"

extern void mm_system_request_reset(void);

/* RCC base addresses (system domain) */
#define RCC_BASE     0x40021000u
#define RCC_SEC_BASE 0x50021000u
#define RCC_SIZE     0x400u

#define RCC_CR       0x000u
#define RCC_CFGR     0x008u
#define RCC_PLLCFGR  0x00cu

/* PWR base (system domain) */
#define PWR_BASE     0x40007000u
#define PWR_SEC_BASE 0x50007000u
#define PWR_SIZE     0x400u
#define PWR_CR1      0x000u
#define PWR_SR2      0x014u

/* FLASH controller base */
#define FLASH_BASE   0x40022000u
#define FLASH_SEC_BASE 0x50022000u
#define FLASH_SIZE   0x400u

/* GTZC TZSC/TZIC (secure / non-secure aliases) */
#define GTZC_TZSC_S_BASE  0x50032400u
#define GTZC_TZSC_NS_BASE 0x40032400u
#define GTZC_TZIC_S_BASE  0x50032800u
#define GTZC_TZIC_NS_BASE 0x40032800u
#define GTZC_TZSC_SIZE 0x400u
#define GTZC_TZIC_SIZE 0x400u
#define GTZC_BLK_SIZE 0x1000u

/* RNG base addresses */
#define RNG_BASE     0x420c0800u
#define RNG_SEC_BASE 0x520c0800u
#define RNG_SIZE     0x400u

/* AES/HASH/PKA base addresses */
#define AES_BASE     0x420c0000u
#define AES_SEC_BASE 0x520c0000u
#define AES_SIZE     0x400u
#define HASH_BASE     0x420c0400u
#define HASH_SEC_BASE 0x520c0400u
#define HASH_SIZE     0x400u
#define PKA_BASE     0x420c2000u
#define PKA_SEC_BASE 0x520c2000u
#define PKA_SIZE     0x2000u

/* MPCBB base addresses */
#define MPCBB1_BASE     0x40032c00u
#define MPCBB1_SEC_BASE 0x50032c00u
#define MPCBB2_BASE     0x40033000u
#define MPCBB2_SEC_BASE 0x50033000u
#define MPCBB_SIZE      0x400u

/* EXTI base addresses */
#define EXTI_BASE     0x4002F400u
#define EXTI_SEC_BASE 0x5002F400u
#define EXTI_SIZE     0x400u

/* IWDG/WWDG base addresses */
#define IWDG_BASE     0x40003000u
#define IWDG_SEC_BASE 0x50003000u
#define IWDG_SIZE     0x400u
#define WWDG_BASE     0x40002C00u
#define WWDG_SEC_BASE 0x50002C00u
#define WWDG_SIZE     0x400u

/* UCPD1 base addresses */
#define UCPD1_BASE     0x4000DC00u
#define UCPD1_SEC_BASE 0x5000DC00u
#define UCPD1_SIZE     0x400u

/* CRS base addresses */
#define CRS_BASE     0x40006000u
#define CRS_SEC_BASE 0x50006000u
#define CRS_SIZE     0x400u

/* UCPD1 register offsets (subset) */
#define UCPD_CFGR1 0x000u
#define UCPD_CR    0x00Cu
#define UCPD_IMR   0x010u
#define UCPD_SR    0x014u
#define UCPD_ICR   0x018u

/* UCPD1 bits (subset) */
#define UCPD_CFGR1_UCPDEN (1u << 31)
#define UCPD_CR_ANAMODE   (1u << 9)
#define UCPD_CR_CCENABLE_0 (1u << 10)
#define UCPD_CR_CCENABLE_1 (1u << 11)
#define UCPD_CR_CCENABLE_BOTH (UCPD_CR_CCENABLE_0 | UCPD_CR_CCENABLE_1)
#define UCPD_SR_TYPECEVT1 (1u << 14)
#define UCPD_SR_TYPECEVT2 (1u << 15)
#define UCPD_SR_TYPEC_VSTATE_CC1_Pos 16u
#define UCPD_SR_TYPEC_VSTATE_CC2_Pos 18u
#define UCPD_SR_TYPEC_VSTATE_CC_Msk (0x3u << UCPD_SR_TYPEC_VSTATE_CC1_Pos)
#define UCPD_SR_TYPEC_VSTATE_CC2_Msk (0x3u << UCPD_SR_TYPEC_VSTATE_CC2_Pos)
#define UCPD_ICR_TYPECEVT1CF (1u << 14)
#define UCPD_ICR_TYPECEVT2CF (1u << 15)

#define RNG_CR_OFFSET   0x0u
#define RNG_SR_OFFSET   0x4u
#define RNG_DR_OFFSET   0x8u
#define RNG_NSCR_OFFSET 0xcu
#define RNG_HTCR_OFFSET 0x10u

/* AES register offsets (subset) */
#define AES_CR    0x000u
#define AES_SR    0x004u
#define AES_DINR  0x008u
#define AES_DOUTR 0x00cu
#define AES_KEYR0 0x010u
#define AES_KEYR1 0x014u
#define AES_KEYR2 0x018u
#define AES_KEYR3 0x01cu
#define AES_IVR0  0x020u
#define AES_IVR1  0x024u
#define AES_IVR2  0x028u
#define AES_IVR3  0x02cu
#define AES_KEYR4 0x030u
#define AES_KEYR5 0x034u
#define AES_KEYR6 0x038u
#define AES_KEYR7 0x03cu
#define AES_IER   0x300u
#define AES_ISR   0x304u
#define AES_ICR   0x308u

#define AES_CR_EN        (1u << 0)
#define AES_CR_DATATYPE_SHIFT 1u
#define AES_CR_MODE_SHIFT 3u
#define AES_CR_CHMOD_SHIFT 5u
#define AES_CR_CHMOD_MASK (0x3u << AES_CR_CHMOD_SHIFT)
#define AES_CR_DMAINEN  (1u << 11)
#define AES_CR_DMAOUTEN (1u << 12)
#define AES_CR_CHMOD2   (1u << 16)
#define AES_CR_KEYSIZE  (1u << 18)
#define AES_CR_GCMPH_SHIFT 13u
#define AES_CR_GCMPH_MASK (0x3u << AES_CR_GCMPH_SHIFT)
#define AES_CR_NPBLB_SHIFT 20u
#define AES_CR_IPRST    (1u << 31)

#define AES_SR_CCF      (1u << 0)
#define AES_SR_RDERR    (1u << 1)
#define AES_SR_WRERR    (1u << 2)
#define AES_SR_BUSY     (1u << 3)
#define AES_SR_KEYVALID (1u << 7)

/* HASH register offsets (subset) */
#define HASH_CR   0x000u
#define HASH_DIN  0x004u
#define HASH_STR  0x008u
#define HASH_HRA0 0x00cu
#define HASH_HRA1 0x010u
#define HASH_HRA2 0x014u
#define HASH_HRA3 0x018u
#define HASH_HRA4 0x01cu
#define HASH_IMR  0x020u
#define HASH_SR   0x024u
#define HASH_CSR0 0x0f8u
#define HASH_HR0  0x310u

#define HASH_CR_INIT      (1u << 2)
#define HASH_CR_DATATYPE_SHIFT 4u
#define HASH_CR_MODE      (1u << 6)
#define HASH_CR_ALGO_SHIFT 17u

#define HASH_STR_NBLW_MASK 0x1fu
#define HASH_STR_DCAL      (1u << 8)

#define HASH_SR_DINIS (1u << 0)
#define HASH_SR_DCIS  (1u << 1)
#define HASH_SR_DMAS  (1u << 2)
#define HASH_SR_BUSY  (1u << 3)
#define HASH_SR_NBWP_SHIFT 9u
#define HASH_SR_DINNE (1u << 15)
#define HASH_SR_NBWE_SHIFT 16u

#define TZSC_SECCFGR2_OFFSET 0x14u
#define TZSC_AESSEC_BIT 12u
#define TZSC_HASHSEC_BIT 13u
#define TZSC_RNGSEC_BIT 14u
#define TZSC_PKASEC_BIT 15u

/* EXTI offsets (subset) */
#define EXTI_RTSR1  0x000u
#define EXTI_FTSR1  0x004u
#define EXTI_SWIER1 0x008u
#define EXTI_RPR1   0x00Cu
#define EXTI_FPR1   0x010u
#define EXTI_EXTICR1 0x060u
#define EXTI_EXTICR2 0x064u
#define EXTI_EXTICR3 0x068u
#define EXTI_EXTICR4 0x06Cu
#define EXTI_IMR1   0x080u
#define EXTI_EMR1   0x084u

/* WWDG offsets */
#define WWDG_CR  0x000u
#define WWDG_CFR 0x004u
#define WWDG_SR  0x008u

/* IWDG offsets */
#define IWDG_KR   0x000u
#define IWDG_PR   0x004u
#define IWDG_RLR  0x008u
#define IWDG_SR   0x00Cu
#define IWDG_WINR 0x010u
#define IWDG_EWCR 0x014u

#define GPIO_IDR_OFFSET 0x10u
#define GPIO_ODR_OFFSET 0x14u

/* MPCBB offsets */
#define MPCBB_CR_OFFSET      0x000u
#define MPCBB_SECCFGR_OFFSET 0x100u
#define MPCBB_CR_INVSECSTATE (1u << 30)

/* FLASH register offsets */
#define FLASH_ACR      0x000u
#define FLASH_NSKEYR   0x004u
#define FLASH_SECKEYR  0x008u
#define FLASH_NSSR     0x020u
#define FLASH_SECSR    0x024u
#define FLASH_NSCR     0x028u
#define FLASH_SECCR    0x02cu
#define FLASH_NSCCR    0x030u
#define FLASH_SECCCR   0x034u

#define FLASH_KEY1 0x45670123u
#define FLASH_KEY2 0xCDEF89ABu

#define FLASH_FLAG_BSY (1u << 0)
#define FLASH_FLAG_EOP (1u << 16)

#define FLASH_CR_LOCK (1u << 0)
#define FLASH_CR_PG   (1u << 1)
#define FLASH_CR_SER  (1u << 2)
#define FLASH_CR_BER  (1u << 3)
#define FLASH_CR_STRT (1u << 5)
#define FLASH_CR_SNB_SHIFT 6
#define FLASH_CR_SNB_MASK (0x7fu << FLASH_CR_SNB_SHIFT)

#define FLASH_SECTOR_COUNT 128u
#define FLASH_BANK_COUNT   2u
#define FLASH_CR_BKSEL     (1u << 31)

struct rcc_state {
    mm_u32 regs[RCC_SIZE / 4];
    mm_u64 cpu_hz;
};

struct pwr_state {
    mm_u32 regs[PWR_SIZE / 4];
};

struct simple_blk {
    mm_u32 regs[GTZC_BLK_SIZE / 4];
};

struct mpcbb_state {
    mm_u32 regs[MPCBB_SIZE / 4];
};

struct rng_state {
    mm_u32 regs[RNG_SIZE / 4];
    mm_u32 dr;
    mm_bool dr_valid;
};

struct hash_state {
    mm_u32 regs[HASH_SIZE / 4];
    mm_u8 *msg;
    mm_u32 msg_len;
    mm_u32 msg_cap;
    mm_u32 nblw;
    mm_u32 nbwp;
    mm_u32 nbwe;
    mm_u8 digest[64];
    mm_u32 digest_len;
    mm_bool digest_ready;
    mm_bool busy;
    mm_bool dinne;
};

struct aes_state {
    mm_u32 regs[AES_SIZE / 4];
    mm_u32 key_words[8];
    mm_u32 key_written;
    mm_u32 iv_words[4];
    mm_u8 in_block[16];
    mm_u8 out_block[16];
    mm_u8 tag[16];
    mm_u8 in_words;
    mm_u8 out_word;
    mm_bool out_ready;
    mm_bool key_valid;
    mm_bool tag_ready;
    mm_u32 npblb;
    mm_u32 algo_mode;
    mm_u8 *aad;
    mm_u32 aad_len;
    mm_u32 aad_cap;
    mm_u8 *payload;
    mm_u32 payload_len;
    mm_u32 payload_cap;
    mm_bool gcm_inited;
    mm_bool ccm_inited;
    mm_u8 ccm_nonce[16];
    mm_u32 ccm_nonce_len;
    mm_u32 ccm_tag_len;
    mm_u8 ccm_ctr[16];
    mm_bool ccm_ctr_valid;
#ifdef M33MU_HAS_WOLFSSL
    Aes gcm_aes;
    Aes ccm_ctr_aes;
#endif
};

struct exti_state {
    mm_u32 regs[EXTI_SIZE / 4];
};

struct iwdg_state {
    mm_u32 regs[IWDG_SIZE / 4];
    mm_u32 counter;
    mm_u32 prescaler;
    mm_bool running;
    mm_bool write_access;
    mm_u64 accum;
};

struct wwdg_state {
    mm_u32 regs[WWDG_SIZE / 4];
    mm_u32 counter;
    mm_u64 accum;
};

struct flash_state {
    mm_u32 regs[FLASH_SIZE / 4];
    mm_u8 *flash;
    mm_u32 flash_size;
    mm_u32 base_s;
    mm_u32 base_ns;
    const struct mm_flash_persist *persist;
    mm_u32 flags;
    mm_u8 ns_key_stage;
    mm_u8 sec_key_stage;
};

struct gpio_state {
    mm_u32 regs[0x34 / 4]; /* up to SECCFGR */
};

struct gpdma_state {
    mm_u32 regs[0x1000 / 4];
};

struct ucpd_state {
    mm_u32 cfgr1;
    mm_u32 cr;
    mm_u32 imr;
    mm_u32 sr;
};

struct hash_ctx {
    struct hash_state *state;
    mm_bool secure_alias;
    struct rcc_state *rcc;
    struct simple_blk *tzsc;
};

struct aes_ctx {
    struct aes_state *state;
    mm_bool secure_alias;
    struct rcc_state *rcc;
    struct simple_blk *tzsc;
};

struct pka_ctx {
    struct pka_state *state;
    mm_bool secure_alias;
    struct rcc_state *rcc;
    struct simple_blk *tzsc;
};

/* uintptr_t substitute for C90 */
typedef unsigned long mm_uptr;

static void rcc_update_ready(struct rcc_state *r);
static void rcc_update_sysclk(struct rcc_state *r);
static void pwr_update_vos(struct pwr_state *p);
static void mpcbb_init_defaults(void);

static struct rcc_state rcc;
static struct pwr_state pwr;
static struct simple_blk tzsc_s;
static struct simple_blk tzsc_ns;
static struct simple_blk tzic_s;
static struct simple_blk tzic_ns;
static struct simple_blk crs;
static struct simple_blk crs_sec;
static struct ucpd_state ucpd1_state;
static struct ucpd_state ucpd1_state_sec;
static struct mpcbb_state mpcbb[2];
static struct rng_state rng;
static struct hash_state hash_accel;
static struct aes_state aes_accel;
static struct pka_state pka_accel;
static struct exti_state exti;
static struct iwdg_state iwdg;
static struct wwdg_state wwdg;
static struct flash_state flash_ctl;
static struct gpio_state gpio[9]; /* A..I */
static struct gpdma_state gpdma1;
static void *gpio_ctx[18][4];
static void *rng_ctx[2][4];
static struct hash_ctx hash_ctx[2];
static struct aes_ctx aes_ctx[2];
static struct pka_ctx pka_ctx[2];
static struct mm_nvic *g_rng_nvic = 0;
static struct mm_nvic *g_exti_nvic = 0;
static struct mm_nvic *g_wdg_nvic = 0;

#define RNG_IRQ 94
static const mm_u32 mpcbb_words[] = { 32u, 32u };

static mm_u32 stm32l552_gpio_bank_read(void *opaque, int bank);
static mm_u32 stm32l552_gpio_bank_read_moder(void *opaque, int bank);
static mm_bool stm32l552_gpio_bank_clock(void *opaque, int bank);
static mm_u32 stm32l552_gpio_bank_read_seccfgr(void *opaque, int bank);
static void exti_gpio_update(int bank, mm_u32 old_level, mm_u32 new_level);

static void ucpd_update_attach(struct ucpd_state *u)
{
    if (u == 0) {
        return;
    }
    if ((u->cfgr1 & UCPD_CFGR1_UCPDEN) == 0u) {
        return;
    }
    if ((u->cr & (UCPD_CR_ANAMODE | UCPD_CR_CCENABLE_BOTH)) != (UCPD_CR_ANAMODE | UCPD_CR_CCENABLE_BOTH)) {
        return;
    }
    if ((u->sr & (UCPD_SR_TYPECEVT1 | UCPD_SR_TYPECEVT2)) == 0u) {
        u->sr |= UCPD_SR_TYPECEVT1;
    }
    u->sr &= ~(UCPD_SR_TYPEC_VSTATE_CC_Msk | UCPD_SR_TYPEC_VSTATE_CC2_Msk);
    u->sr |= (3u << UCPD_SR_TYPEC_VSTATE_CC1_Pos);
}

static mm_bool ucpd_read(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 *value_out)
{
    struct ucpd_state *u = (struct ucpd_state *)opaque;
    mm_u32 value = 0;
    if (u == 0 || value_out == 0) {
        return MM_FALSE;
    }
    if (size_bytes != 4u) {
        return MM_FALSE;
    }
    ucpd_update_attach(u);
    switch (offset) {
    case UCPD_CFGR1:
        value = u->cfgr1;
        break;
    case UCPD_CR:
        value = u->cr;
        break;
    case UCPD_IMR:
        value = u->imr;
        break;
    case UCPD_SR:
        value = u->sr;
        break;
    default:
        value = 0;
        break;
    }
    *value_out = value;
    return MM_TRUE;
}

static mm_bool ucpd_write(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 value)
{
    struct ucpd_state *u = (struct ucpd_state *)opaque;
    if (u == 0) {
        return MM_FALSE;
    }
    if (size_bytes != 4u) {
        return MM_FALSE;
    }
    switch (offset) {
    case UCPD_CFGR1:
        u->cfgr1 = value;
        ucpd_update_attach(u);
        return MM_TRUE;
    case UCPD_CR:
        u->cr = value;
        ucpd_update_attach(u);
        return MM_TRUE;
    case UCPD_IMR:
        u->imr = value;
        return MM_TRUE;
    case UCPD_ICR:
        if ((value & UCPD_ICR_TYPECEVT1CF) != 0u) {
            u->sr &= ~UCPD_SR_TYPECEVT1;
        }
        if ((value & UCPD_ICR_TYPECEVT2CF) != 0u) {
            u->sr &= ~UCPD_SR_TYPECEVT2;
        }
        return MM_TRUE;
    default:
        return MM_TRUE;
    }
}

static mm_u32 bitrev32(mm_u32 v)
{
    mm_u32 r = 0u;
    mm_u32 i;
    for (i = 0u; i < 32u; ++i) {
        r <<= 1;
        r |= (v & 1u);
        v >>= 1;
    }
    return r;
}

static mm_u32 apply_datatype(mm_u32 value, mm_u32 datatype)
{
    switch (datatype & 0x3u) {
    case 1u:
        return (value << 16) | (value >> 16);
    case 2u:
        return ((value & 0x000000ffu) << 24) |
               ((value & 0x0000ff00u) << 8)  |
               ((value & 0x00ff0000u) >> 8)  |
               ((value & 0xff000000u) >> 24);
    case 3u:
        return bitrev32(value);
    default:
        break;
    }
    return value;
}

static mm_u32 read_be_word(const mm_u8 *buf)
{
    return ((mm_u32)buf[0] << 24) |
           ((mm_u32)buf[1] << 16) |
           ((mm_u32)buf[2] << 8) |
           (mm_u32)buf[3];
}

static mm_bool aes_buf_ensure(mm_u8 **buf, mm_u32 *cap, mm_u32 need)
{
    mm_u32 new_cap;
    mm_u8 *new_buf;
    if (need <= *cap) return MM_TRUE;
    new_cap = (*cap != 0u) ? *cap : 64u;
    while (new_cap < need) {
        new_cap *= 2u;
        if (new_cap < *cap) return MM_FALSE;
    }
    new_buf = (mm_u8 *)realloc(*buf, new_cap);
    if (new_buf == 0) return MM_FALSE;
    *buf = new_buf;
    *cap = new_cap;
    return MM_TRUE;
}

static mm_bool aes_buf_append(mm_u8 **buf, mm_u32 *len, mm_u32 *cap, const mm_u8 *data, mm_u32 size)
{
    if (!aes_buf_ensure(buf, cap, *len + size)) return MM_FALSE;
    memcpy(*buf + *len, data, size);
    *len += size;
    return MM_TRUE;
}

static void aes_reset_auth_state(struct aes_state *a)
{
    a->aad_len = 0u;
    a->payload_len = 0u;
    a->tag_ready = MM_FALSE;
    a->gcm_inited = MM_FALSE;
    a->ccm_inited = MM_FALSE;
    a->ccm_ctr_valid = MM_FALSE;
}

static void aes_build_iv_rev(const struct aes_state *a, mm_u8 *iv_out)
{
    mm_u32 i;
    for (i = 0u; i < 4u; ++i) {
        mm_u32 w = a->iv_words[3u - i];
        iv_out[i * 4u] = (mm_u8)(w & 0xffu);
        iv_out[i * 4u + 1u] = (mm_u8)((w >> 8) & 0xffu);
        iv_out[i * 4u + 2u] = (mm_u8)((w >> 16) & 0xffu);
        iv_out[i * 4u + 3u] = (mm_u8)((w >> 24) & 0xffu);
    }
}

static void aes_ccm_init_from_b0(struct aes_state *a)
{
    mm_u8 b0[16];
    mm_u32 flags;
    mm_u32 l_val;
    mm_u32 tag_len;
    aes_build_iv_rev(a, b0);
    flags = b0[0];
    l_val = (flags & 0x7u) + 1u;
    tag_len = (((flags >> 3) & 0x7u) * 2u) + 2u;
    a->ccm_nonce_len = 15u - l_val;
    if (a->ccm_nonce_len > sizeof(a->ccm_nonce)) {
        a->ccm_nonce_len = sizeof(a->ccm_nonce);
    }
    memcpy(a->ccm_nonce, &b0[1], a->ccm_nonce_len);
    a->ccm_tag_len = tag_len;
    memset(a->ccm_ctr, 0, sizeof(a->ccm_ctr));
    a->ccm_ctr[0] = (mm_u8)(l_val - 1u);
    memcpy(&a->ccm_ctr[1], a->ccm_nonce, a->ccm_nonce_len);
    a->ccm_ctr[15] = 1u;
    a->ccm_ctr_valid = MM_TRUE;
    a->ccm_inited = MM_TRUE;
}

static void hash_reset_state(struct hash_state *h)
{
    h->msg_len = 0u;
    h->nblw = 0u;
    h->nbwp = 0u;
    h->nbwe = 0x11u;
    h->digest_len = 0u;
    h->digest_ready = MM_FALSE;
    h->busy = MM_FALSE;
    h->dinne = MM_FALSE;
    h->regs[HASH_SR / 4u] = 0u;
}

static mm_bool hash_ensure_capacity(struct hash_state *h, mm_u32 extra)
{
    mm_u32 need = h->msg_len + extra;
    mm_u32 new_cap;
    mm_u8 *new_buf;
    if (need <= h->msg_cap) return MM_TRUE;
    new_cap = h->msg_cap ? h->msg_cap : 64u;
    while (new_cap < need) {
        new_cap *= 2u;
        if (new_cap < h->msg_cap) return MM_FALSE;
    }
    new_buf = (mm_u8 *)realloc(h->msg, new_cap);
    if (new_buf == 0) return MM_FALSE;
    h->msg = new_buf;
    h->msg_cap = new_cap;
    return MM_TRUE;
}

static mm_bool hash_append_word(struct hash_state *h, mm_u32 value, mm_u32 datatype)
{
    mm_u32 word;
    mm_u8 *dst;
    if (!hash_ensure_capacity(h, 4u)) return MM_FALSE;
    word = apply_datatype(value, datatype);
    dst = h->msg + h->msg_len;
    dst[0] = (mm_u8)(word & 0xffu);
    dst[1] = (mm_u8)((word >> 8) & 0xffu);
    dst[2] = (mm_u8)((word >> 16) & 0xffu);
    dst[3] = (mm_u8)((word >> 24) & 0xffu);
    h->msg_len += 4u;
    h->nbwp++;
    if (h->nbwe > 0u) {
        h->nbwe--;
    }
    h->dinne = MM_TRUE;
    return MM_TRUE;
}

static void hash_set_digest_regs(struct hash_state *h)
{
    mm_u32 i;
    mm_u32 words = h->digest_len / 4u;
    for (i = 0u; i < 5u; ++i) {
        mm_u32 off = (HASH_HRA0 / 4u) + i;
        if (i < words) {
            h->regs[off] = read_be_word(h->digest + i * 4u);
        } else {
            h->regs[off] = 0u;
        }
    }
    for (i = 0u; i < 16u; ++i) {
        mm_u32 off = (HASH_HR0 / 4u) + i;
        if (i < words) {
            h->regs[off] = read_be_word(h->digest + i * 4u);
        } else {
            h->regs[off] = 0u;
        }
    }
}

static void hash_compute_digest(struct hash_state *h, mm_u32 algo)
{
    const mm_u8 *data = h->msg;
    mm_u32 len = h->msg_len;
    mm_u8 last_buf[4];
    mm_u32 last_len = 0u;
    mm_u32 nblw = h->nblw & HASH_STR_NBLW_MASK;
    if (nblw != 0u && len >= 4u) {
        mm_u32 valid_bits = nblw;
        mm_u32 valid_bytes = (valid_bits + 7u) / 8u;
        mm_u32 bytes_before = len - 4u;
        mm_u32 rem_bits = valid_bits % 8u;
        memcpy(last_buf, h->msg + bytes_before, 4u);
        if (rem_bits != 0u && valid_bytes > 0u) {
            mm_u8 mask = (mm_u8)((1u << rem_bits) - 1u);
            last_buf[valid_bytes - 1u] &= mask;
        }
        data = h->msg;
        len = bytes_before;
        last_len = valid_bytes;
    }

    h->digest_len = 0u;
#ifdef M33MU_HAS_WOLFSSL
    switch (algo & 0x3u) {
    case 0x0u: {
        wc_Sha sha;
        wc_InitSha(&sha);
        wc_ShaUpdate(&sha, data, len);
        if (last_len != 0u) wc_ShaUpdate(&sha, last_buf, last_len);
        wc_ShaFinal(&sha, h->digest);
        h->digest_len = 20u;
        break;
    }
    case 0x1u: {
        wc_Sha224 sha;
        wc_InitSha224(&sha);
        wc_Sha224Update(&sha, data, len);
        if (last_len != 0u) wc_Sha224Update(&sha, last_buf, last_len);
        wc_Sha224Final(&sha, h->digest);
        h->digest_len = 28u;
        break;
    }
    case 0x2u: {
        wc_Sha256 sha;
        wc_InitSha256(&sha);
        wc_Sha256Update(&sha, data, len);
        if (last_len != 0u) wc_Sha256Update(&sha, last_buf, last_len);
        wc_Sha256Final(&sha, h->digest);
        h->digest_len = 32u;
        break;
    }
    case 0x3u: {
        wc_Sha384 sha;
        wc_InitSha384(&sha);
        wc_Sha384Update(&sha, data, len);
        if (last_len != 0u) wc_Sha384Update(&sha, last_buf, last_len);
        wc_Sha384Final(&sha, h->digest);
        h->digest_len = 48u;
        break;
    }
    default:
        break;
    }
#else
    (void)algo;
#endif
    if (h->digest_len == 0u) {
        memset(h->digest, 0, sizeof(h->digest));
        h->digest_len = 32u;
    }
    hash_set_digest_regs(h);
    h->digest_ready = MM_TRUE;
}

static mm_u32 hash_status_word(struct hash_state *h)
{
    mm_u32 sr = 0u;
    sr |= HASH_SR_DINIS;
    if (h->digest_ready) sr |= HASH_SR_DCIS;
    if (h->busy) sr |= HASH_SR_BUSY;
    if (h->dinne) sr |= HASH_SR_DINNE;
    sr |= (h->nbwp & 0x1fu) << HASH_SR_NBWP_SHIFT;
    sr |= (h->nbwe & 0x1fu) << HASH_SR_NBWE_SHIFT;
    return sr;
}

static mm_bool tzsc_requires_secure(const struct simple_blk *tzsc, mm_u32 bit)
{
    mm_u32 seccfgr2 = tzsc->regs[TZSC_SECCFGR2_OFFSET / 4u];
    return ((seccfgr2 >> bit) & 1u) != 0u;
}

static mm_bool hash_clock_enabled(const struct rcc_state *rcc)
{
    mm_u32 ahb2enr = rcc->regs[0x4c / 4];
    return ((ahb2enr >> 17) & 1u) != 0u;
}

static mm_bool aes_clock_enabled(const struct rcc_state *rcc)
{
    mm_u32 ahb2enr = rcc->regs[0x4c / 4];
    return ((ahb2enr >> 16) & 1u) != 0u;
}

static mm_bool hash_requires_secure(const struct simple_blk *tzsc)
{
    return tzsc_requires_secure(tzsc, TZSC_HASHSEC_BIT);
}

static mm_bool aes_requires_secure(const struct simple_blk *tzsc)
{
    return tzsc_requires_secure(tzsc, TZSC_AESSEC_BIT);
}

static mm_bool pka_clock_enabled(const struct rcc_state *rcc)
{
    mm_u32 ahb2enr = rcc->regs[0x4c / 4];
    return ((ahb2enr >> 19) & 1u) != 0u;
}

static mm_bool pka_requires_secure(const struct simple_blk *tzsc)
{
    return tzsc_requires_secure(tzsc, TZSC_PKASEC_BIT);
}

static mm_bool hash_read(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 *value_out)
{
    struct hash_ctx *ctx = (struct hash_ctx *)opaque;
    struct hash_state *h = ctx->state;
    if (value_out == 0 || size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if ((offset + size_bytes) > HASH_SIZE) return MM_FALSE;
    if (!hash_clock_enabled(ctx->rcc)) {
        *value_out = 0u;
        return MM_TRUE;
    }
    if (!ctx->secure_alias && hash_requires_secure(ctx->tzsc)) {
        *value_out = 0u;
        return MM_TRUE;
    }
    if (offset == HASH_SR) {
        mm_u32 sr = hash_status_word(h);
        memcpy(value_out, &sr, size_bytes);
        return MM_TRUE;
    }
    memcpy(value_out, (mm_u8 *)h->regs + offset, size_bytes);
    return MM_TRUE;
}

static mm_bool pka_read(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 *value_out)
{
    struct pka_ctx *ctx = (struct pka_ctx *)opaque;
    if (value_out == 0 || size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if (!pka_clock_enabled(ctx->rcc)) {
        *value_out = 0u;
        return MM_TRUE;
    }
    if (!ctx->secure_alias && pka_requires_secure(ctx->tzsc)) {
        *value_out = 0u;
        return MM_TRUE;
    }
    return mm_pka_read(ctx->state, offset, size_bytes, value_out);
}

static mm_bool hash_write(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 value)
{
    struct hash_ctx *ctx = (struct hash_ctx *)opaque;
    struct hash_state *h = ctx->state;
    mm_u32 datatype;
    mm_u32 algo;
    if (size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if ((offset + size_bytes) > HASH_SIZE) return MM_FALSE;
    if (!hash_clock_enabled(ctx->rcc)) {
        return MM_TRUE;
    }
    if (!ctx->secure_alias && hash_requires_secure(ctx->tzsc)) {
        return MM_TRUE;
    }
    if (offset == HASH_CR) {
        datatype = (value >> HASH_CR_DATATYPE_SHIFT) & 0x3u;
        algo = (value >> HASH_CR_ALGO_SHIFT) & 0x3u;
        h->regs[HASH_CR / 4u] = value & ~(HASH_CR_INIT);
        if ((value & HASH_CR_INIT) != 0u) {
            hash_reset_state(h);
            h->regs[HASH_CR / 4u] = value & ~(HASH_CR_INIT);
            h->regs[HASH_CR / 4u] = (h->regs[HASH_CR / 4u] & ~(0x3u << HASH_CR_ALGO_SHIFT)) |
                                    ((algo & 0x3u) << HASH_CR_ALGO_SHIFT);
        }
        h->regs[HASH_CR / 4u] = (h->regs[HASH_CR / 4u] & ~(0x3u << HASH_CR_DATATYPE_SHIFT)) |
                                ((datatype & 0x3u) << HASH_CR_DATATYPE_SHIFT);
        return MM_TRUE;
    }
    if (offset == HASH_DIN) {
        datatype = (h->regs[HASH_CR / 4u] >> HASH_CR_DATATYPE_SHIFT) & 0x3u;
        hash_append_word(h, value, datatype);
        return MM_TRUE;
    }
    if (offset == HASH_STR) {
        h->regs[HASH_STR / 4u] = value;
        h->nblw = value & HASH_STR_NBLW_MASK;
        if ((value & HASH_STR_DCAL) != 0u) {
            algo = (h->regs[HASH_CR / 4u] >> HASH_CR_ALGO_SHIFT) & 0x3u;
            h->busy = MM_TRUE;
            hash_compute_digest(h, algo);
            h->busy = MM_FALSE;
            h->dinne = MM_FALSE;
        }
        return MM_TRUE;
    }
    if (offset == HASH_SR) {
        h->regs[HASH_SR / 4u] &= ~(value & (HASH_SR_DINIS | HASH_SR_DCIS));
        if ((value & HASH_SR_DCIS) != 0u) {
            h->digest_ready = MM_FALSE;
        }
        return MM_TRUE;
    }
    if (offset == HASH_IMR || offset >= HASH_CSR0) {
        memcpy((mm_u8 *)h->regs + offset, &value, size_bytes);
        return MM_TRUE;
    }
    memcpy((mm_u8 *)h->regs + offset, &value, size_bytes);
    return MM_TRUE;
}

static mm_bool pka_write(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 value)
{
    struct pka_ctx *ctx = (struct pka_ctx *)opaque;
    if (size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if (!pka_clock_enabled(ctx->rcc)) {
        return MM_TRUE;
    }
    if (!ctx->secure_alias && pka_requires_secure(ctx->tzsc)) {
        return MM_TRUE;
    }
    return mm_pka_write(ctx->state, offset, size_bytes, value);
}

static mm_bool aes_read(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 *value_out)
{
    struct aes_ctx *ctx = (struct aes_ctx *)opaque;
    struct aes_state *a = ctx->state;
    mm_u32 val;
    if (value_out == 0 || size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if ((offset + size_bytes) > AES_SIZE) return MM_FALSE;
    if (!aes_clock_enabled(ctx->rcc)) {
        *value_out = 0u;
        return MM_TRUE;
    }
    if (!ctx->secure_alias && aes_requires_secure(ctx->tzsc)) {
        *value_out = 0u;
        return MM_TRUE;
    }
    if (offset == AES_SR) {
        val = a->regs[AES_SR / 4u] & ~(AES_SR_CCF | AES_SR_KEYVALID | AES_SR_BUSY);
        if (a->out_ready) val |= AES_SR_CCF;
        if (a->key_valid) val |= AES_SR_KEYVALID;
        memcpy(value_out, &val, size_bytes);
        return MM_TRUE;
    }
    if (offset == AES_DOUTR) {
        mm_u32 datatype = (a->regs[AES_CR / 4u] >> AES_CR_DATATYPE_SHIFT) & 0x3u;
        if (!a->out_ready || a->out_word >= 4u) {
            *value_out = 0u;
            return MM_TRUE;
        }
        val = (mm_u32)a->out_block[a->out_word * 4u] |
              ((mm_u32)a->out_block[a->out_word * 4u + 1u] << 8) |
              ((mm_u32)a->out_block[a->out_word * 4u + 2u] << 16) |
              ((mm_u32)a->out_block[a->out_word * 4u + 3u] << 24);
        val = apply_datatype(val, datatype);
        a->out_word++;
        memcpy(value_out, &val, size_bytes);
        return MM_TRUE;
    }
    memcpy(value_out, (mm_u8 *)a->regs + offset, size_bytes);
    return MM_TRUE;
}

static void aes_build_key(struct aes_state *a, mm_u8 *key_out, mm_u32 key_len)
{
    mm_u32 i;
    mm_u32 words = key_len / 4u;
    for (i = 0u; i < words; ++i) {
        mm_u32 w = a->key_words[i];
        key_out[i * 4u] = (mm_u8)(w & 0xffu);
        key_out[i * 4u + 1u] = (mm_u8)((w >> 8) & 0xffu);
        key_out[i * 4u + 2u] = (mm_u8)((w >> 16) & 0xffu);
        key_out[i * 4u + 3u] = (mm_u8)((w >> 24) & 0xffu);
    }
}

static void aes_build_iv(struct aes_state *a, mm_u8 *iv_out)
{
    mm_u32 i;
    for (i = 0u; i < 4u; ++i) {
        mm_u32 w = a->iv_words[i];
        iv_out[i * 4u] = (mm_u8)(w & 0xffu);
        iv_out[i * 4u + 1u] = (mm_u8)((w >> 8) & 0xffu);
        iv_out[i * 4u + 2u] = (mm_u8)((w >> 16) & 0xffu);
        iv_out[i * 4u + 3u] = (mm_u8)((w >> 24) & 0xffu);
    }
}

static void aes_store_iv(struct aes_state *a, const mm_u8 *iv_in)
{
    mm_u32 i;
    for (i = 0u; i < 4u; ++i) {
        a->iv_words[i] = (mm_u32)iv_in[i * 4u] |
                         ((mm_u32)iv_in[i * 4u + 1u] << 8) |
                         ((mm_u32)iv_in[i * 4u + 2u] << 16) |
                         ((mm_u32)iv_in[i * 4u + 3u] << 24);
    }
}

#ifdef M33MU_HAS_WOLFSSL
static void aes_store_iv_words(struct aes_state *a, const word32 *iv_words)
{
    mm_u32 i;
    mm_u8 iv_bytes[16];
    for (i = 0u; i < 4u; ++i) {
        mm_u32 w = (mm_u32)iv_words[i];
        iv_bytes[i * 4u] = (mm_u8)(w & 0xffu);
        iv_bytes[i * 4u + 1u] = (mm_u8)((w >> 8) & 0xffu);
        iv_bytes[i * 4u + 2u] = (mm_u8)((w >> 16) & 0xffu);
        iv_bytes[i * 4u + 3u] = (mm_u8)((w >> 24) & 0xffu);
    }
    aes_store_iv(a, iv_bytes);
}
#endif

static void aes_process_block(struct aes_state *a)
{
    mm_u8 key[32];
    mm_u8 iv[16];
    mm_u32 key_len = (a->regs[AES_CR / 4u] & AES_CR_KEYSIZE) ? 32u : 16u;
    mm_u32 mode = (a->regs[AES_CR / 4u] >> AES_CR_MODE_SHIFT) & 0x3u;
    mm_u32 chmod = ((a->regs[AES_CR / 4u] >> AES_CR_CHMOD_SHIFT) & 0x3u) |
                   ((a->regs[AES_CR / 4u] & AES_CR_CHMOD2) ? 0x4u : 0u);
    mm_bool decrypt = (mode != 0u);
#ifdef M33MU_HAS_WOLFSSL
    Aes aes;
#endif
    if (!a->key_valid) {
        memset(a->out_block, 0, sizeof(a->out_block));
        a->out_ready = MM_TRUE;
        a->out_word = 0u;
        a->regs[AES_SR / 4u] |= AES_SR_CCF | AES_SR_WRERR;
        a->regs[AES_SR / 4u] &= ~AES_SR_BUSY;
        return;
    }
#ifdef M33MU_HAS_WOLFSSL
    aes_build_key(a, key, key_len);
    aes_build_iv(a, iv);
    wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (chmod == 1u) {
        wc_AesSetKey(&aes, key, key_len, iv, decrypt ? AES_DECRYPTION : AES_ENCRYPTION);
        if (decrypt) {
            wc_AesCbcDecrypt(&aes, a->out_block, a->in_block, 16u);
        } else {
            wc_AesCbcEncrypt(&aes, a->out_block, a->in_block, 16u);
        }
        aes_store_iv_words(a, aes.reg);
    } else if (chmod == 2u) {
        wc_AesSetKeyDirect(&aes, key, key_len, iv, AES_ENCRYPTION);
        wc_AesCtrEncrypt(&aes, a->out_block, a->in_block, 16u);
        aes_store_iv_words(a, aes.reg);
    } else {
        wc_AesSetKey(&aes, key, key_len, NULL, decrypt ? AES_DECRYPTION : AES_ENCRYPTION);
        if (decrypt) {
            wc_AesEcbDecrypt(&aes, a->out_block, a->in_block, 16u);
        } else {
            wc_AesEcbEncrypt(&aes, a->out_block, a->in_block, 16u);
        }
    }
    wc_AesFree(&aes);
#else
    (void)key_len;
    (void)key;
    (void)iv;
    memcpy(a->out_block, a->in_block, sizeof(a->out_block));
#endif
    a->out_ready = MM_TRUE;
    a->out_word = 0u;
    a->regs[AES_SR / 4u] |= AES_SR_CCF;
    a->regs[AES_SR / 4u] &= ~AES_SR_BUSY;
}

static mm_u32 aes_algo_mode(const struct aes_state *a)
{
    mm_u32 cr = a->regs[AES_CR / 4u];
    if ((cr & AES_CR_CHMOD2) != 0u) {
        return 4u;
    }
    return (cr >> AES_CR_CHMOD_SHIFT) & 0x3u;
}

static mm_u32 aes_phase(const struct aes_state *a)
{
    return (a->regs[AES_CR / 4u] >> AES_CR_GCMPH_SHIFT) & 0x3u;
}

static void aes_prepare_gcm(struct aes_state *a, mm_bool decrypt)
{
#ifdef M33MU_HAS_WOLFSSL
    mm_u8 key[32];
    mm_u8 iv[16];
    mm_u32 key_len = (a->regs[AES_CR / 4u] & AES_CR_KEYSIZE) ? 32u : 16u;
    aes_build_key(a, key, key_len);
    aes_build_iv(a, iv);
#ifdef WOLFSSL_AESGCM_STREAM
    if (decrypt) {
        wc_AesGcmDecryptInit(&a->gcm_aes, key, key_len, iv, 16u);
    } else {
        wc_AesGcmEncryptInit(&a->gcm_aes, key, key_len, iv, 16u);
    }
#else
    wc_AesGcmSetKey(&a->gcm_aes, key, key_len);
#endif
    a->gcm_inited = MM_TRUE;
#else
    (void)decrypt;
#endif
}

static void aes_handle_gcm_block(struct aes_state *a, mm_u32 phase, mm_bool decrypt, const mm_u8 *in, mm_u32 len)
{
#ifdef M33MU_HAS_WOLFSSL
#ifdef WOLFSSL_AESGCM_STREAM
    if (!a->gcm_inited) {
        aes_prepare_gcm(a, decrypt);
    }
    if (phase == 1u) {
        wc_AesGcmEncryptUpdate(&a->gcm_aes, a->out_block, 0, 0, in, len);
        return;
    }
    if (phase == 2u) {
        if (decrypt) {
            wc_AesGcmDecryptUpdate(&a->gcm_aes, a->out_block, in, len, 0, 0);
        } else {
            wc_AesGcmEncryptUpdate(&a->gcm_aes, a->out_block, in, len, 0, 0);
        }
        if (len < 16u) {
            memset(a->out_block + len, 0, 16u - len);
        }
        a->out_ready = MM_TRUE;
        a->out_word = 0u;
    }
#else
    (void)decrypt;
    if (phase == 1u) {
        aes_buf_append(&a->aad, &a->aad_len, &a->aad_cap, in, len);
        return;
    }
    if (phase == 2u) {
        aes_buf_append(&a->payload, &a->payload_len, &a->payload_cap, in, len);
        memset(a->out_block, 0, sizeof(a->out_block));
        a->out_ready = MM_TRUE;
        a->out_word = 0u;
    }
#endif
#else
    (void)phase;
    (void)decrypt;
    (void)in;
    (void)len;
#endif
}

static void aes_finalize_gcm(struct aes_state *a, mm_bool decrypt)
{
#ifdef M33MU_HAS_WOLFSSL
#ifdef WOLFSSL_AESGCM_STREAM
    if (!a->gcm_inited) {
        aes_prepare_gcm(a, decrypt);
    }
    if (decrypt) {
        int ret = wc_AesGcmDecryptFinal(&a->gcm_aes, a->tag, 16u);
        (void)ret;
    } else {
        wc_AesGcmEncryptFinal(&a->gcm_aes, a->tag, 16u);
    }
#else
    {
        mm_u8 key[32];
        mm_u8 iv[16];
        mm_u32 key_len = (a->regs[AES_CR / 4u] & AES_CR_KEYSIZE) ? 32u : 16u;
        aes_build_key(a, key, key_len);
        aes_build_iv(a, iv);
        wc_AesGcmSetKey(&a->gcm_aes, key, key_len);
        if (decrypt) {
            wc_AesGcmDecrypt(&a->gcm_aes, a->payload, a->payload, a->payload_len,
                             iv, 16u, a->tag, 16u, a->aad, a->aad_len);
        } else {
            wc_AesGcmEncrypt(&a->gcm_aes, a->payload, a->payload, a->payload_len,
                             iv, 16u, a->tag, 16u, a->aad, a->aad_len);
        }
    }
#endif
    memcpy(a->out_block, a->tag, 16u);
    a->tag_ready = MM_TRUE;
    a->out_ready = MM_TRUE;
    a->out_word = 0u;
#else
    (void)decrypt;
#endif
}

static void aes_handle_ccm_block(struct aes_state *a, mm_u32 phase, mm_bool decrypt, const mm_u8 *in, mm_u32 len)
{
#ifdef M33MU_HAS_WOLFSSL
    mm_u8 key[32];
    mm_u32 key_len;
    if (!a->ccm_inited) {
        aes_ccm_init_from_b0(a);
    }
    if (phase == 1u) {
        aes_buf_append(&a->aad, &a->aad_len, &a->aad_cap, in, len);
        return;
    }
    if (phase == 2u) {
        mm_u8 out[16];
        key_len = (a->regs[AES_CR / 4u] & AES_CR_KEYSIZE) ? 32u : 16u;
        aes_build_key(a, key, key_len);
        if (!a->ccm_ctr_valid) {
            aes_ccm_init_from_b0(a);
        }
        wc_AesSetKeyDirect(&a->ccm_ctr_aes, key, key_len, a->ccm_ctr, AES_ENCRYPTION);
        wc_AesCtrEncrypt(&a->ccm_ctr_aes, out, in, len);
        memcpy(a->ccm_ctr, a->ccm_ctr_aes.reg, 16u);
        memset(a->out_block, 0, 16u);
        memcpy(a->out_block, out, len);
        if (len < 16u) {
            memset(a->out_block + len, 0, 16u - len);
        }
        a->out_ready = MM_TRUE;
        a->out_word = 0u;
        if (decrypt) {
            aes_buf_append(&a->payload, &a->payload_len, &a->payload_cap, out, len);
        } else {
            aes_buf_append(&a->payload, &a->payload_len, &a->payload_cap, in, len);
        }
    }
#else
    (void)phase;
    (void)decrypt;
    (void)in;
    (void)len;
#endif
}

static void aes_finalize_ccm(struct aes_state *a, mm_bool decrypt)
{
#ifdef M33MU_HAS_WOLFSSL
    mm_u8 key[32];
    mm_u32 key_len = (a->regs[AES_CR / 4u] & AES_CR_KEYSIZE) ? 32u : 16u;
    aes_build_key(a, key, key_len);
    wc_AesCcmSetKey(&a->ccm_ctr_aes, key, key_len);
    if (a->ccm_nonce_len == 0u) {
        aes_ccm_init_from_b0(a);
    }
    if (decrypt) {
        wc_AesCcmEncrypt(&a->ccm_ctr_aes, 0, a->payload, a->payload_len,
                         a->ccm_nonce, a->ccm_nonce_len, a->tag, a->ccm_tag_len,
                         a->aad, a->aad_len);
    } else {
        wc_AesCcmEncrypt(&a->ccm_ctr_aes, 0, a->payload, a->payload_len,
                         a->ccm_nonce, a->ccm_nonce_len, a->tag, a->ccm_tag_len,
                         a->aad, a->aad_len);
    }
    memset(a->out_block, 0, 16u);
    memcpy(a->out_block, a->tag, a->ccm_tag_len > 16u ? 16u : a->ccm_tag_len);
    a->tag_ready = MM_TRUE;
    a->out_ready = MM_TRUE;
    a->out_word = 0u;
#else
    (void)decrypt;
#endif
}

static mm_bool aes_write(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 value)
{
    struct aes_ctx *ctx = (struct aes_ctx *)opaque;
    struct aes_state *a = ctx->state;
    mm_u32 datatype;
    if (size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if ((offset + size_bytes) > AES_SIZE) return MM_FALSE;
    if (!aes_clock_enabled(ctx->rcc)) {
        return MM_TRUE;
    }
    if (!ctx->secure_alias && aes_requires_secure(ctx->tzsc)) {
        return MM_TRUE;
    }
    if (offset == AES_CR) {
        mm_u32 prev = a->regs[AES_CR / 4u];
        if ((value & AES_CR_IPRST) != 0u) {
            memset(a, 0, sizeof(*a));
        }
        a->regs[AES_CR / 4u] = value;
        a->npblb = (value >> AES_CR_NPBLB_SHIFT) & 0xFu;
        if (((prev ^ value) & (AES_CR_CHMOD2 | AES_CR_CHMOD_MASK | AES_CR_GCMPH_MASK)) != 0u) {
            aes_reset_auth_state(a);
        }
        if (((prev ^ value) & AES_CR_KEYSIZE) != 0u) {
            a->key_written = 0u;
            a->key_valid = MM_FALSE;
            a->regs[AES_SR / 4u] &= ~AES_SR_KEYVALID;
        }
        if (((value & AES_CR_GCMPH_MASK) == AES_CR_GCMPH_MASK)) {
            mm_u32 algo = aes_algo_mode(a);
            mm_bool decrypt = ((a->regs[AES_CR / 4u] >> AES_CR_MODE_SHIFT) & 0x3u) != 0u;
            if (algo == 3u) {
                aes_finalize_gcm(a, decrypt);
            } else if (algo == 4u) {
                aes_finalize_ccm(a, decrypt);
            }
        }
        return MM_TRUE;
    }
    if (offset == AES_KEYR0 || offset == AES_KEYR1 || offset == AES_KEYR2 || offset == AES_KEYR3 ||
        offset == AES_KEYR4 || offset == AES_KEYR5 || offset == AES_KEYR6 || offset == AES_KEYR7) {
        mm_u32 idx = (offset - AES_KEYR0) / 4u;
        mm_u32 key_len = (a->regs[AES_CR / 4u] & AES_CR_KEYSIZE) ? 32u : 16u;
        mm_u32 words = key_len / 4u;
        mm_u32 mask;
        if (idx < 8u) {
            a->key_words[idx] = value;
        }
        if (idx < words) {
            a->key_written |= (1u << idx);
        }
        mask = (words >= 8u) ? 0xFFu : ((1u << words) - 1u);
        a->key_valid = ((a->key_written & mask) == mask) ? MM_TRUE : MM_FALSE;
        a->regs[AES_SR / 4u] = (a->regs[AES_SR / 4u] & ~AES_SR_KEYVALID) |
                               (a->key_valid ? AES_SR_KEYVALID : 0u);
        return MM_TRUE;
    }
    if (offset == AES_IVR0 || offset == AES_IVR1 || offset == AES_IVR2 || offset == AES_IVR3) {
        mm_u32 idx = (offset - AES_IVR0) / 4u;
        if (idx < 4u) {
            a->iv_words[idx] = value;
        }
        a->regs[offset / 4u] = value;
        return MM_TRUE;
    }
    if (offset == AES_DINR) {
        mm_u32 word;
        mm_u32 algo;
        mm_u32 phase;
        mm_u32 valid_len = 16u;
        if ((a->regs[AES_CR / 4u] & AES_CR_EN) == 0u) {
            a->regs[AES_SR / 4u] |= AES_SR_WRERR;
            return MM_TRUE;
        }
        datatype = (a->regs[AES_CR / 4u] >> AES_CR_DATATYPE_SHIFT) & 0x3u;
        word = apply_datatype(value, datatype);
        a->in_block[a->in_words * 4u] = (mm_u8)(word & 0xffu);
        a->in_block[a->in_words * 4u + 1u] = (mm_u8)((word >> 8) & 0xffu);
        a->in_block[a->in_words * 4u + 2u] = (mm_u8)((word >> 16) & 0xffu);
        a->in_block[a->in_words * 4u + 3u] = (mm_u8)((word >> 24) & 0xffu);
        a->in_words++;
        if (a->in_words >= 4u) {
            algo = aes_algo_mode(a);
            phase = aes_phase(a);
            if (a->npblb != 0u && a->npblb < 16u) {
                valid_len = 16u - a->npblb;
            }
            a->regs[AES_SR / 4u] |= AES_SR_BUSY;
            if (algo == 3u) {
                mm_bool decrypt = ((a->regs[AES_CR / 4u] >> AES_CR_MODE_SHIFT) & 0x3u) != 0u;
                aes_handle_gcm_block(a, phase, decrypt, a->in_block, valid_len);
            } else if (algo == 4u) {
                mm_bool decrypt = ((a->regs[AES_CR / 4u] >> AES_CR_MODE_SHIFT) & 0x3u) != 0u;
                aes_handle_ccm_block(a, phase, decrypt, a->in_block, valid_len);
            } else {
                aes_process_block(a);
            }
            a->in_words = 0u;
        }
        return MM_TRUE;
    }
    if (offset == AES_ICR) {
        if ((value & 1u) != 0u) {
            a->regs[AES_SR / 4u] &= ~AES_SR_CCF;
            a->out_ready = MM_FALSE;
        }
        a->regs[AES_ICR / 4u] = value;
        return MM_TRUE;
    }
    memcpy((mm_u8 *)a->regs + offset, &value, size_bytes);
    return MM_TRUE;
}

static mm_bool flash_trace_enabled(void)
{
    static mm_bool init = MM_FALSE;
    static mm_bool enabled = MM_FALSE;
    if (!init) {
        const char *env = getenv("M33MU_FLASH_TRACE");
        enabled = (env != 0 && env[0] != '\0') ? MM_TRUE : MM_FALSE;
        init = MM_TRUE;
    }
    return enabled;
}

static mm_bool stm32l552_rcc_clock_list_line(void *opaque, int line, char *out, size_t out_len);

static mm_bool stm32l552_gpio_bank_info(void *opaque, int bank, char *name_out, size_t name_len, int *pins_out)
{
    (void)opaque;
    if (bank < 0 || bank >= 8) {
        return MM_FALSE;
    }
    if (name_out != 0 && name_len > 0u) {
        name_out[0] = (char)('A' + bank);
        if (name_len > 1u) {
            name_out[1] = '\0';
        }
    }
    if (pins_out != 0) {
        *pins_out = 16;
    }
    return MM_TRUE;
}

void mm_stm32l552_mmio_reset(void)
{
    size_t i;
    memset(&rcc, 0, sizeof(rcc));
    memset(&pwr, 0, sizeof(pwr));
    memset(&tzsc_s, 0, sizeof(tzsc_s));
    memset(&tzsc_ns, 0, sizeof(tzsc_ns));
    memset(&tzic_s, 0, sizeof(tzic_s));
    memset(&tzic_ns, 0, sizeof(tzic_ns));
    memset(&rng, 0, sizeof(rng));
    memset(&hash_accel, 0, sizeof(hash_accel));
    memset(&aes_accel, 0, sizeof(aes_accel));
    memset(&pka_accel, 0, sizeof(pka_accel));
    memset(&pka_accel, 0, sizeof(pka_accel));
    memset(&exti, 0, sizeof(exti));
    memset(&iwdg, 0, sizeof(iwdg));
    memset(&wwdg, 0, sizeof(wwdg));
    memset(&flash_ctl, 0, sizeof(flash_ctl));
    memset(&crs, 0, sizeof(crs));
    memset(&crs_sec, 0, sizeof(crs_sec));
    memset(&ucpd1_state, 0, sizeof(ucpd1_state));
    memset(&ucpd1_state_sec, 0, sizeof(ucpd1_state_sec));
    mpcbb_init_defaults();
    memset(&gpdma1, 0, sizeof(gpdma1));
    for (i = 0; i < sizeof(gpio) / sizeof(gpio[0]); ++i) {
        memset(&gpio[i], 0, sizeof(gpio[i]));
    }
    mm_gpio_bank_set_reader(stm32l552_gpio_bank_read, 0);
    mm_gpio_bank_set_moder_reader(stm32l552_gpio_bank_read_moder, 0);
    mm_gpio_bank_set_clock_reader(stm32l552_gpio_bank_clock, 0);
    mm_gpio_bank_set_seccfgr_reader(stm32l552_gpio_bank_read_seccfgr, 0);
    mm_gpio_set_bank_info_reader(stm32l552_gpio_bank_info, 0);
    mm_rcc_set_clock_list_reader(stm32l552_rcc_clock_list_line, 0);
    /* Enable HSI by default and mark ready flags. */
    rcc.regs[0] |= 1u;
    rcc_update_ready(&rcc);
    rcc_update_sysclk(&rcc);
    iwdg.regs[IWDG_RLR / 4u] = 0x00000FFFu;
    iwdg.regs[IWDG_WINR / 4u] = 0x00000FFFu;
    wwdg.regs[WWDG_CR / 4u] = 0x0000007Fu;
    wwdg.regs[WWDG_CFR / 4u] = 0x0000007Fu;
    wwdg.counter = 0x7Fu;
    exti.regs[EXTI_IMR1 / 4u] = 0xFFFE0000u;
    /* Power ready flags. */
    pwr_update_vos(&pwr);

    /* RNG reset values */
    rng.regs[RNG_CR_OFFSET / 4] = 0x00871f00u;
    rng.regs[RNG_HTCR_OFFSET / 4] = 0x000072acu;
    hash_reset_state(&hash_accel);
    mm_pka_reset(&pka_accel);

    /* FLASH reset values */
    flash_ctl.regs[FLASH_ACR / 4] = 0x00000013u;
    flash_ctl.regs[FLASH_NSCR / 4] = 0x00000001u;
    flash_ctl.regs[FLASH_SECCR / 4] = 0x00000001u;

    mm_stm32l552_usb_reset();
}

mm_u32 *mm_stm32l552_tzsc_regs(void)
{
    return tzsc_s.regs;
}


mm_bool mm_stm32l552_mpcbb_block_secure(int bank, mm_u32 block_index)
{
    mm_u32 word;
    mm_u32 bit;
    mm_u32 val;
    mm_bool sec;
    if (bank < 0 || bank >= (int)(sizeof(mpcbb) / sizeof(mpcbb[0]))) {
        return MM_FALSE;
    }
    word = block_index / 32u;
    if (word >= mpcbb_words[bank]) {
        return MM_FALSE;
    }
    bit = block_index % 32u;
    val = mpcbb[bank].regs[(MPCBB_SECCFGR_OFFSET / 4u) + word];
    sec = ((val >> bit) & 1u) != 0u;
    if ((mpcbb[bank].regs[MPCBB_CR_OFFSET / 4u] & MPCBB_CR_INVSECSTATE) != 0u) {
        sec = !sec;
    }
    return sec;
}

static mm_bool gpio_clock_enabled(const struct rcc_state *rcc, int index)
{
    /* AHB2ENR offset 0x4C, GPIOAEN bit0..GPIOHEN bit7 */
    mm_u32 ahb2enr = rcc->regs[0x4c / 4];
    return ((ahb2enr >> index) & 1u) != 0u;
}

enum rcc_bus_kind {
    RCC_BUS_AHB2 = 0,
    RCC_BUS_APB1 = 1,
    RCC_BUS_APB1_2 = 2,
    RCC_BUS_APB2 = 3
};

struct rcc_clk_name {
    const char *name;
    enum rcc_bus_kind bus;
    mm_u32 bit;
};

static const struct rcc_clk_name rcc_clk_names[] = {
    { "GPIOA", RCC_BUS_AHB2, 0u },
    { "GPIOB", RCC_BUS_AHB2, 1u },
    { "GPIOC", RCC_BUS_AHB2, 2u },
    { "GPIOD", RCC_BUS_AHB2, 3u },
    { "GPIOE", RCC_BUS_AHB2, 4u },
    { "GPIOF", RCC_BUS_AHB2, 5u },
    { "GPIOG", RCC_BUS_AHB2, 6u },
    { "GPIOH", RCC_BUS_AHB2, 7u },
    { "AES", RCC_BUS_AHB2, 16u },
    { "HASH", RCC_BUS_AHB2, 17u },
    { "RNG", RCC_BUS_AHB2, 18u },
    { "PKA", RCC_BUS_AHB2, 19u },
    { "TIM2", RCC_BUS_APB1, 0u },
    { "TIM3", RCC_BUS_APB1, 1u },
    { "TIM4", RCC_BUS_APB1, 2u },
    { "TIM5", RCC_BUS_APB1, 3u },
    { "USART2", RCC_BUS_APB1, 17u },
    { "USART3", RCC_BUS_APB1, 18u },
    { "UART4", RCC_BUS_APB1, 19u },
    { "UART5", RCC_BUS_APB1, 20u },
    { "USART1", RCC_BUS_APB2, 14u },
    { "LPUART1", RCC_BUS_APB1_2, 0u }
};

static mm_u32 rcc_bus_reg(const struct rcc_state *r, enum rcc_bus_kind bus)
{
    if (r == 0) {
        return 0u;
    }
    switch (bus) {
    case RCC_BUS_AHB2:
        return r->regs[0x4c / 4];
    case RCC_BUS_APB1:
        return r->regs[0x58 / 4];
    case RCC_BUS_APB1_2:
        return r->regs[0x5c / 4];
    case RCC_BUS_APB2:
        return r->regs[0x60 / 4];
    default:
        return 0u;
    }
}

static const char *rcc_bus_name(enum rcc_bus_kind bus)
{
    switch (bus) {
    case RCC_BUS_AHB2: return "AHB2";
    case RCC_BUS_APB1: return "APB1";
    case RCC_BUS_APB1_2: return "APB1_2";
    case RCC_BUS_APB2: return "APB2";
    default: return "RCC";
    }
}

static mm_bool stm32l552_rcc_clock_list_line(void *opaque, int line, char *out, size_t out_len)
{
    enum rcc_bus_kind bus;
    int line_idx = 0;
    size_t i;
    (void)opaque;
    if (out == 0 || out_len == 0u) {
        return MM_FALSE;
    }
    for (bus = RCC_BUS_AHB2; bus <= RCC_BUS_APB2; ++bus) {
        mm_u32 reg = rcc_bus_reg(&rcc, bus);
        char buf[256];
        size_t pos = 0;
        mm_bool have = MM_FALSE;
        if (reg == 0u) {
            continue;
        }
        pos += snprintf(buf + pos, sizeof(buf) - pos, "%s:", rcc_bus_name(bus));
        for (i = 0; i < sizeof(rcc_clk_names) / sizeof(rcc_clk_names[0]); ++i) {
            if (rcc_clk_names[i].bus != bus) {
                continue;
            }
            if ((reg & (1u << rcc_clk_names[i].bit)) == 0u) {
                continue;
            }
            if (pos + 2u < sizeof(buf)) {
                pos += snprintf(buf + pos, sizeof(buf) - pos, " %s", rcc_clk_names[i].name);
                have = MM_TRUE;
            }
        }
        if (!have) {
            continue;
        }
        if (line_idx == line) {
            snprintf(out, out_len, "%s", buf);
            return MM_TRUE;
        }
        line_idx++;
    }
    return MM_FALSE;
}

static mm_u32 stm32l552_gpio_bank_read(void *opaque, int bank)
{
    (void)opaque;
    if (bank < 0 || bank >= (int)(sizeof(gpio) / sizeof(gpio[0]))) {
        return 0u;
    }
    return gpio[bank].regs[0x14u / 4];
}

static mm_u32 stm32l552_gpio_bank_read_moder(void *opaque, int bank)
{
    (void)opaque;
    if (bank < 0 || bank >= (int)(sizeof(gpio) / sizeof(gpio[0]))) {
        return 0u;
    }
    return gpio[bank].regs[0x00u / 4];
}

static mm_bool stm32l552_gpio_bank_clock(void *opaque, int bank)
{
    (void)opaque;
    return gpio_clock_enabled(&rcc, bank);
}

static mm_u32 stm32l552_gpio_bank_read_seccfgr(void *opaque, int bank)
{
    (void)opaque;
    if (bank < 0 || bank >= (int)(sizeof(gpio) / sizeof(gpio[0]))) {
        return 0u;
    }
    return gpio[bank].regs[0x30u / 4];
}

static mm_bool rng_clock_enabled(const struct rcc_state *rcc)
{
    /* RCC_AHB2ENR offset 0x4C, RNGEN bit18 */
    mm_u32 ahb2enr = rcc->regs[0x4c / 4];
    return ((ahb2enr >> 18) & 1u) != 0u;
}

static mm_bool rng_requires_secure(const struct simple_blk *tzsc)
{
    return tzsc_requires_secure(tzsc, TZSC_RNGSEC_BIT);
}

static void rng_fill(struct rng_state *r)
{
    mm_u32 v = 0;
    ssize_t n = getrandom(&v, sizeof(v), GRND_NONBLOCK);
    if (n != (ssize_t)sizeof(v)) {
        v = 0;
    }
    r->dr = v;
    r->dr_valid = MM_TRUE;
    r->regs[RNG_SR_OFFSET / 4] |= 1u;
    if (g_rng_nvic != 0 && (r->regs[RNG_CR_OFFSET / 4] & (1u << 3)) != 0u) {
        mm_nvic_set_pending(g_rng_nvic, (mm_u32)RNG_IRQ, MM_TRUE);
    }
}

static mm_u32 flash_sector_size(void)
{
    mm_u32 banks = FLASH_BANK_COUNT;
    if (flash_ctl.flash_size == 0u) {
        return 0u;
    }
    if (banks == 0u || (flash_ctl.flash_size % banks) != 0u) {
        banks = 1u;
    }
    return (FLASH_SECTOR_COUNT == 0u) ? 0u
        : ((flash_ctl.flash_size / banks) / FLASH_SECTOR_COUNT);
}

static void flash_set_busy(mm_u32 reg_offset, mm_bool busy)
{
    mm_u32 idx = reg_offset / 4u;
    if (busy) {
        flash_ctl.regs[idx] |= FLASH_FLAG_BSY;
    } else {
        flash_ctl.regs[idx] &= ~FLASH_FLAG_BSY;
    }
}

static void flash_set_eop(mm_u32 reg_offset)
{
    flash_ctl.regs[reg_offset / 4u] |= FLASH_FLAG_EOP;
}

static void flash_clear_eop(mm_u32 reg_offset)
{
    flash_ctl.regs[reg_offset / 4u] &= ~FLASH_FLAG_EOP;
}

static mm_bool flash_is_unlocked(mm_u32 reg_offset)
{
    return (flash_ctl.regs[reg_offset / 4u] & FLASH_CR_LOCK) == 0u;
}

static void flash_handle_key(mm_u32 offset, mm_u32 value)
{
    mm_u8 *stage = (offset == FLASH_NSKEYR) ? &flash_ctl.ns_key_stage : &flash_ctl.sec_key_stage;
    mm_u32 cr_off = (offset == FLASH_NSKEYR) ? FLASH_NSCR : FLASH_SECCR;
    if (*stage == 0u) {
        if (value == FLASH_KEY1) {
            *stage = 1u;
        } else {
            *stage = 0u;
        }
        return;
    }
    if (*stage == 1u) {
        if (value == FLASH_KEY2) {
            flash_ctl.regs[cr_off / 4u] &= ~FLASH_CR_LOCK;
        }
        *stage = 0u;
    }
}

static void flash_apply_erase(mm_u32 cr_off, mm_u32 sr_off)
{
    mm_u32 cr = flash_ctl.regs[cr_off / 4u];
    mm_u32 sector_size = flash_sector_size();
    mm_u32 bank_size = 0;
    mm_u32 bank_offset = 0;
    mm_u32 start = 0;
    mm_u32 length = 0;
    if (flash_ctl.flash == 0 || flash_ctl.flash_size == 0 || sector_size == 0) {
        return;
    }
    if ((cr & FLASH_CR_BER) != 0u) {
        start = 0;
        length = flash_ctl.flash_size;
    } else if ((cr & FLASH_CR_SER) != 0u) {
        mm_u32 snb = (cr & FLASH_CR_SNB_MASK) >> FLASH_CR_SNB_SHIFT;
        start = snb * sector_size;
        bank_size = flash_ctl.flash_size / FLASH_BANK_COUNT;
        if (FLASH_BANK_COUNT != 0u && bank_size != 0u && (cr & FLASH_CR_BKSEL) != 0u) {
            bank_offset = bank_size;
            start += bank_offset;
        }
        if (start >= flash_ctl.flash_size) {
            return;
        }
        length = sector_size;
        if (start + length > flash_ctl.flash_size) {
            length = flash_ctl.flash_size - start;
        }
    } else {
        return;
    }
    if (flash_trace_enabled()) {
        const char *sec = (cr_off == FLASH_SECCR) ? "S" : "NS";
        const char *mode = (cr & FLASH_CR_BER) ? "BER" : "SER";
        mm_u32 snb = (cr & FLASH_CR_SNB_MASK) >> FLASH_CR_SNB_SHIFT;
        printf("[FLASH_ERASE] %s mode=%s snb=%lu start=0x%08lx len=0x%08lx\n",
               sec,
               mode,
               (unsigned long)snb,
               (unsigned long)start,
               (unsigned long)length);
    }
    flash_set_busy(sr_off, MM_TRUE);
    memset(flash_ctl.flash + start, 0xFF, length);
    flash_set_busy(sr_off, MM_FALSE);
    flash_set_eop(sr_off);
    if (flash_ctl.persist != 0 && flash_ctl.persist->enabled) {
        mm_flash_persist_flush((struct mm_flash_persist *)flash_ctl.persist, start, length);
    }
}

static mm_bool flash_write_cb(void *opaque, enum mm_sec_state sec, mm_u32 addr, mm_u32 size_bytes, mm_u32 value)
{
    mm_u32 base;
    mm_u32 offset;
    mm_u32 cr_off;
    mm_u32 sr_off;
    mm_u32 sector_size;
    mm_u32 sector_base;
    mm_u32 i;
    (void)opaque;

    if (flash_ctl.flash == 0 || flash_ctl.flash_size == 0) {
        return MM_FALSE;
    }
    if (addr >= flash_ctl.base_s && addr < flash_ctl.base_s + flash_ctl.flash_size) {
        base = flash_ctl.base_s;
    } else if (addr >= flash_ctl.base_ns && addr < flash_ctl.base_ns + flash_ctl.flash_size) {
        base = flash_ctl.base_ns;
    } else {
        return MM_FALSE;
    }
    offset = addr - base;
    cr_off = (sec == MM_SECURE) ? FLASH_SECCR : FLASH_NSCR;
    sr_off = (sec == MM_SECURE) ? FLASH_SECSR : FLASH_NSSR;

    if (offset + size_bytes > flash_ctl.flash_size) {
        return MM_FALSE;
    }
    if (flash_trace_enabled()) {
        printf("[FLASH_WRITE] %s addr=0x%08lx size=%lu value=0x%08lx\n",
               (sec == MM_SECURE) ? "S" : "NS",
               (unsigned long)addr,
               (unsigned long)size_bytes,
               (unsigned long)value);
    }
    if (!flash_is_unlocked(cr_off)) {
        return MM_TRUE;
    }
    if ((flash_ctl.regs[cr_off / 4u] & FLASH_CR_PG) == 0u) {
        return MM_TRUE;
    }

    sector_size = flash_sector_size();
    if ((flash_ctl.flags & MM_TARGET_FLAG_NVM_WRITEONCE) != 0u && sector_size != 0u) {
        sector_base = (offset / sector_size) * sector_size;
        for (i = 0; i < sector_size; ++i) {
            if (sector_base + i >= flash_ctl.flash_size) {
                break;
            }
            if (flash_ctl.flash[sector_base + i] != 0xFFu) {
                return MM_TRUE;
            }
        }
    }

    if (size_bytes == 4u) {
        flash_ctl.flash[offset] = (mm_u8)(value & 0xFFu);
        flash_ctl.flash[offset + 1u] = (mm_u8)((value >> 8) & 0xFFu);
        flash_ctl.flash[offset + 2u] = (mm_u8)((value >> 16) & 0xFFu);
        flash_ctl.flash[offset + 3u] = (mm_u8)((value >> 24) & 0xFFu);
    } else if (size_bytes == 2u) {
        flash_ctl.flash[offset] = (mm_u8)(value & 0xFFu);
        flash_ctl.flash[offset + 1u] = (mm_u8)((value >> 8) & 0xFFu);
    } else if (size_bytes == 1u) {
        flash_ctl.flash[offset] = (mm_u8)(value & 0xFFu);
    } else {
        return MM_FALSE;
    }
    flash_set_eop(sr_off);
    if (flash_ctl.persist != 0 && flash_ctl.persist->enabled) {
        mm_flash_persist_flush((struct mm_flash_persist *)flash_ctl.persist, offset, size_bytes);
    }
    return MM_TRUE;
}

/* Reset bits currently unused (could clear state if asserted). */

static mm_bool rcc_read(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 *value_out)
{
    struct rcc_state *r = (struct rcc_state *)opaque;
    if (value_out == 0 || size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if ((offset + size_bytes) > RCC_SIZE) return MM_FALSE;
    memcpy(value_out, (mm_u8 *)r->regs + offset, size_bytes);
    return MM_TRUE;
}

static void rcc_update_ready(struct rcc_state *r)
{
    mm_u32 cr = r->regs[0]; /* offset 0x0 */
    /* Mirror RDY bits to match ON bits (immediate ready). */
    /* MSIRDY bit1 follows MSION bit0 */
    if ((cr & (1u << 0)) != 0u) cr |= (1u << 1); else cr &= ~(1u << 1);
    /* HSIRDY bit10 follows HSION bit8 */
    if ((cr & (1u << 8)) != 0u) cr |= (1u << 10); else cr &= ~(1u << 10);
    /* HSERDY bit17 follows HSEON bit16 */
    if ((cr & (1u << 16)) != 0u) cr |= (1u << 17); else cr &= ~(1u << 17);
    /* PLLRDY bit25 follows PLLON bit24 */
    if ((cr & (1u << 24)) != 0u) cr |= (1u << 25); else cr &= ~(1u << 25);
    r->regs[0] = cr;
}

static mm_u64 rcc_msi_hz(const struct rcc_state *r)
{
    static const mm_u64 ranges[] = {
        100000ull, 200000ull, 400000ull, 800000ull,
        1000000ull, 2000000ull, 4000000ull, 8000000ull,
        16000000ull, 24000000ull, 32000000ull, 48000000ull
    };
    mm_u32 cr = r->regs[RCC_CR / 4];
    mm_u32 idx = (cr >> 4) & 0x0fu;
    if (idx >= (mm_u32)(sizeof(ranges) / sizeof(ranges[0]))) {
        idx = 6u;
    }
    return ranges[idx];
}

static mm_u64 rcc_pll_p_clk(const struct rcc_state *r)
{
    mm_u32 pllcfgr = r->regs[RCC_PLLCFGR / 4];
    mm_u32 src = pllcfgr & 0x3u;
    mm_u64 fin = 0;
    mm_u32 divm = ((pllcfgr >> 4) & 0x0fu) + 1u;
    mm_u32 n = (pllcfgr >> 8) & 0x7fu;
    mm_u32 rdiv_sel = (pllcfgr >> 25) & 0x3u;
    mm_u32 rdiv = 2u;

    if ((pllcfgr & (1u << 24)) == 0u) {
        return 0;
    }

    if (src == 1u) fin = rcc_msi_hz(r); /* MSI */
    else if (src == 2u) fin = 16000000ull; /* HSI16 */
    else if (src == 3u) fin = 8000000ull; /* HSE */
    else fin = 0;

    switch (rdiv_sel) {
    case 0u: rdiv = 2u; break;
    case 1u: rdiv = 4u; break;
    case 2u: rdiv = 6u; break;
    case 3u: rdiv = 8u; break;
    default: rdiv = 2u; break;
    }

    if (fin == 0 || divm == 0u || n == 0u || rdiv == 0u) {
        return 0;
    }
    return (fin / (mm_u64)divm) * (mm_u64)n / (mm_u64)rdiv;
}

static void rcc_update_sysclk(struct rcc_state *r)
{
    mm_u32 cfgr = r->regs[RCC_CFGR / 4];
    mm_u32 sw = cfgr & 0x3u;
    mm_u32 hpre = (cfgr >> 4) & 0xfu;
    mm_u64 sys = 0;
    mm_u32 div = 1u;

    if (sw == 0u) sys = rcc_msi_hz(r); /* MSI */
    else if (sw == 1u) sys = 16000000ull; /* HSI16 */
    else if (sw == 2u) sys = 8000000ull; /* HSE */
    else if (sw == 3u) sys = rcc_pll_p_clk(r);

    if (hpre >= 8u) {
        switch (hpre) {
        case 8u: div = 2u; break;
        case 9u: div = 4u; break;
        case 10u: div = 8u; break;
        case 11u: div = 16u; break;
        case 12u: div = 64u; break;
        case 13u: div = 128u; break;
        case 14u: div = 256u; break;
        case 15u: div = 512u; break;
        default: div = 1u; break;
        }
    }
    if (sys == 0) {
        r->cpu_hz = 0;
    } else {
        r->cpu_hz = sys / (mm_u64)div;
        if (r->cpu_hz == 0) r->cpu_hz = 1;
    }
    r->regs[RCC_CFGR / 4] = (r->regs[RCC_CFGR / 4] & ~(0x3u << 2)) | (sw << 2);
}

static mm_bool rcc_write(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 value)
{
    struct rcc_state *r = (struct rcc_state *)opaque;
    if (size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if ((offset + size_bytes) > RCC_SIZE) return MM_FALSE;
    memcpy((mm_u8 *)r->regs + offset, &value, size_bytes);
    if (offset == RCC_CR) {
        rcc_update_ready(r);
    }
    if (offset == RCC_CFGR || offset == RCC_PLLCFGR || offset == RCC_CR) {
        rcc_update_sysclk(r);
    }
    return MM_TRUE;
}

static mm_bool pwr_read(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 *value_out)
{
    struct pwr_state *p = (struct pwr_state *)opaque;
    if (value_out == 0 || size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if ((offset + size_bytes) > PWR_SIZE) return MM_FALSE;
    memcpy(value_out, (mm_u8 *)p->regs + offset, size_bytes);
    return MM_TRUE;
}

static void pwr_update_vos(struct pwr_state *p)
{
    mm_u32 sr2 = p->regs[PWR_SR2 / 4];
    sr2 &= ~(1u << 10); /* VOSF cleared -> ready */
    p->regs[PWR_SR2 / 4] = sr2;
}

static mm_bool pwr_write(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 value)
{
    struct pwr_state *p = (struct pwr_state *)opaque;
    if (size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if ((offset + size_bytes) > PWR_SIZE) return MM_FALSE;
    memcpy((mm_u8 *)p->regs + offset, &value, size_bytes);
    if (offset == PWR_CR1) {
        pwr_update_vos(p);
    }
    return MM_TRUE;
}

static mm_bool simple_blk_read(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 *value_out)
{
    struct simple_blk *b = (struct simple_blk *)opaque;
    if (value_out == 0 || size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if ((offset + size_bytes) > GTZC_BLK_SIZE) return MM_FALSE;
    memcpy(value_out, (mm_u8 *)b->regs + offset, size_bytes);
    return MM_TRUE;
}

static mm_bool simple_blk_write(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 value)
{
    struct simple_blk *b = (struct simple_blk *)opaque;
    if (size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if ((offset + size_bytes) > GTZC_BLK_SIZE) return MM_FALSE;
    memcpy((mm_u8 *)b->regs + offset, &value, size_bytes);
    return MM_TRUE;
}

static mm_bool mpcbb_read(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 *value_out)
{
    struct mpcbb_state *b = (struct mpcbb_state *)opaque;
    if (value_out == 0 || size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if ((offset + size_bytes) > MPCBB_SIZE) return MM_FALSE;
    memcpy(value_out, (mm_u8 *)b->regs + offset, size_bytes);
    return MM_TRUE;
}

static mm_bool mpcbb_write(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 value)
{
    struct mpcbb_state *b = (struct mpcbb_state *)opaque;
    if (size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if ((offset + size_bytes) > MPCBB_SIZE) return MM_FALSE;
    memcpy((mm_u8 *)b->regs + offset, &value, size_bytes);
    return MM_TRUE;
}

static void mpcbb_init_defaults(void)
{
    mm_u32 bank;
    for (bank = 0; bank < (mm_u32)(sizeof(mpcbb) / sizeof(mpcbb[0])); ++bank) {
        mm_u32 word;
        memset(&mpcbb[bank], 0, sizeof(mpcbb[bank]));
        for (word = 0; word < mpcbb_words[bank]; ++word) {
            mpcbb[bank].regs[(MPCBB_SECCFGR_OFFSET / 4u) + word] = 0xFFFFFFFFu;
        }
    }
}

static mm_bool gpio_read(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 *value_out)
{
    struct gpio_state *g = ((struct gpio_state *)((void **)opaque)[0]);
    struct rcc_state *rcc = (struct rcc_state *)((void **)opaque)[2];
    int index = (int)(mm_uptr)((void **)opaque)[3];
    mm_bool is_secure_alias = ((void **)opaque)[1] != 0;
    mm_u32 seccfgr = g->regs[0x30u / 4];
    mm_u32 v = 0;
    mm_u32 mask = ~seccfgr; /* pins accessible to NS */

    if (value_out == 0 || size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if (offset >= sizeof(g->regs)) return MM_FALSE;

    if (!gpio_clock_enabled(rcc, index)) {
        *value_out = 0;
        return MM_TRUE;
    }

    memcpy(&v, (mm_u8 *)g->regs + offset, size_bytes);

    if (!is_secure_alias) {
        if (offset == 0x30u) { /* SECCFGR */
            v = 0;
        } else if (offset == 0x10u || offset == 0x14u || offset == 0x18u || offset == 0x1cu || offset == 0x20u || offset == 0x24u || offset == 0x28u || offset == 0x2cu) {
            /* Data/bit set/reset/lock/AF/BRR/HSLVR: mask secure pins */
            v &= mask;
        } else if (offset <= 0x0cu || offset == 0x04u || offset == 0x08u) {
            /* config registers are readable but secure bits masked */
            v &= mask | (mask << 16); /* apply per-bit twice per 2 bits? conservative: mask low 16 bits */ 
        }
    }

    *value_out = v;
    return MM_TRUE;
}

static void gpio_apply_brr(struct gpio_state *g, mm_u32 bits, mm_u32 mask)
{
    g->regs[0x14u / 4] &= ~(bits & mask);
}

static void gpio_apply_bsrr(struct gpio_state *g, mm_u32 val, mm_u32 mask)
{
    mm_u32 set = val & 0xFFFFu;
    mm_u32 reset = (val >> 16) & 0xFFFFu;
    mm_u32 odr = g->regs[0x14u / 4];
    odr |= (set & mask);
    odr &= ~(reset & mask);
    g->regs[0x14u / 4] = odr;
}

static void gpio_sync_odr(struct gpio_state *g, int bank, mm_u32 old_odr)
{
    mm_u32 new_odr = g->regs[GPIO_ODR_OFFSET / 4];
    if (new_odr != old_odr) {
        g->regs[GPIO_IDR_OFFSET / 4] = new_odr;
        exti_gpio_update(bank, old_odr, new_odr);
    }
}

static mm_u32 gpio_mask_to_2bit(mm_u32 mask)
{
    mm_u32 out = 0;
    int i;
    for (i = 0; i < 16; ++i) {
        if ((mask & (1u << i)) != 0u) {
            out |= (3u << (i * 2));
        }
    }
    return out;
}

static mm_bool gpio_write(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 value)
{
    struct gpio_state *g = ((struct gpio_state *)((void **)opaque)[0]);
    struct rcc_state *rcc = (struct rcc_state *)((void **)opaque)[2];
    int index = (int)(mm_uptr)((void **)opaque)[3];
    mm_bool is_secure_alias = ((void **)opaque)[1] != 0;
    mm_u32 seccfgr = g->regs[0x30u / 4];
    mm_u32 mask = ~seccfgr;

    if (size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if (offset >= sizeof(g->regs)) return MM_FALSE;

    if (!gpio_clock_enabled(rcc, index)) {
        return MM_TRUE; /* WI if disabled */
    }

    /* Non-secure alias write handling */
    if (!is_secure_alias) {
        if (offset == 0x30u) {
            /* SECCFGR is Secure-only: WI */
            return MM_TRUE;
        }
        /* Mask out secure pins */
        if (offset == 0x18u) { /* BSRR */
            mm_u32 old_odr = g->regs[GPIO_ODR_OFFSET / 4];
            gpio_apply_bsrr(g, value, mask & 0xFFFFu);
            gpio_sync_odr(g, index, old_odr);
            return MM_TRUE;
        } else if (offset == 0x28u) { /* BRR */
            mm_u32 old_odr = g->regs[GPIO_ODR_OFFSET / 4];
            gpio_apply_brr(g, value & 0xFFFFu, mask & 0xFFFFu);
            gpio_sync_odr(g, index, old_odr);
            return MM_TRUE;
        } else {
            /* General regs: apply mask */
            if (offset == 0x00u) { /* MODER: 2 bits per pin */
                mm_u32 m2 = gpio_mask_to_2bit(mask & 0xFFFFu);
                value &= (m2 | (m2 << 16));
            } else {
                value &= (mask | (mask << 16));
            }
        }
    }

    if (offset == 0x18u) { /* BSRR */
        mm_u32 old_odr = g->regs[GPIO_ODR_OFFSET / 4];
        gpio_apply_bsrr(g, value, 0xFFFFu);
        gpio_sync_odr(g, index, old_odr);
        return MM_TRUE;
    }
    if (offset == 0x28u) { /* BRR */
        mm_u32 old_odr = g->regs[GPIO_ODR_OFFSET / 4];
        gpio_apply_brr(g, value & 0xFFFFu, 0xFFFFu);
        gpio_sync_odr(g, index, old_odr);
        return MM_TRUE;
    }

    if (offset == GPIO_ODR_OFFSET) {
        mm_u32 old_odr = g->regs[GPIO_ODR_OFFSET / 4];
        memcpy((mm_u8 *)g->regs + offset, &value, size_bytes);
        gpio_sync_odr(g, index, old_odr);
        return MM_TRUE;
    }

    memcpy((mm_u8 *)g->regs + offset, &value, size_bytes);
    return MM_TRUE;
}

static mm_bool gpdma_read(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 *value_out)
{
    struct gpdma_state *d = (struct gpdma_state *)opaque;
    if (value_out == 0 || size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if ((offset + size_bytes) > sizeof(d->regs)) return MM_FALSE;
    memcpy(value_out, (mm_u8 *)d->regs + offset, size_bytes);
    return MM_TRUE;
}

static mm_bool gpdma_write(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 value)
{
    struct gpdma_state *d = (struct gpdma_state *)opaque;
    if (size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if ((offset + size_bytes) > sizeof(d->regs)) return MM_FALSE;
    memcpy((mm_u8 *)d->regs + offset, &value, size_bytes);
    return MM_TRUE;
}

static mm_bool flash_read(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 *value_out)
{
    struct flash_state *f = (struct flash_state *)opaque;
    if (value_out == 0 || size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if ((offset + size_bytes) > FLASH_SIZE) return MM_FALSE;
    memcpy(value_out, (mm_u8 *)f->regs + offset, size_bytes);
    return MM_TRUE;
}

static mm_bool flash_write(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 value)
{
    struct flash_state *f = (struct flash_state *)opaque;
    mm_u32 cr_off;
    mm_u32 sr_off;
    if (size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if ((offset + size_bytes) > FLASH_SIZE) return MM_FALSE;

    if (offset == FLASH_NSKEYR || offset == FLASH_SECKEYR) {
        flash_handle_key(offset, value);
        return MM_TRUE;
    }

    if (offset == FLASH_NSCCR || offset == FLASH_SECCCR) {
        sr_off = (offset == FLASH_NSCCR) ? FLASH_NSSR : FLASH_SECSR;
        if ((value & (1u << 16)) != 0u) {
            flash_clear_eop(sr_off);
        }
        return MM_TRUE;
    }

    if (offset == FLASH_NSCR || offset == FLASH_SECCR) {
        cr_off = offset;
        sr_off = (offset == FLASH_NSCR) ? FLASH_NSSR : FLASH_SECSR;
        if (!flash_is_unlocked(cr_off) && (value & FLASH_CR_LOCK) == 0u) {
            return MM_TRUE;
        }
        memcpy((mm_u8 *)f->regs + offset, &value, size_bytes);
        if ((value & FLASH_CR_LOCK) != 0u) {
            f->regs[cr_off / 4u] |= FLASH_CR_LOCK;
        }
        if ((value & FLASH_CR_STRT) != 0u) {
            flash_apply_erase(cr_off, sr_off);
            f->regs[cr_off / 4u] &= ~FLASH_CR_STRT;
        }
        return MM_TRUE;
    }

    memcpy((mm_u8 *)f->regs + offset, &value, size_bytes);
    return MM_TRUE;
}

static mm_bool rng_read(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 *value_out)
{
    struct rng_state *r = ((struct rng_state *)((void **)opaque)[0]);
    mm_bool secure_alias = ((void **)opaque)[1] != 0;
    struct rcc_state *rcc = (struct rcc_state *)((void **)opaque)[2];
    struct simple_blk *tzsc = (struct simple_blk *)((void **)opaque)[3];

    if (value_out == 0 || size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if ((offset + size_bytes) > RNG_SIZE) return MM_FALSE;

    if (!secure_alias && rng_requires_secure(tzsc)) {
        *value_out = 0;
        return MM_TRUE;
    }
    if (!rng_clock_enabled(rcc)) {
        *value_out = 0;
        return MM_TRUE;
    }

    if (offset == RNG_SR_OFFSET) {
        if (!r->dr_valid) {
            rng_fill(r);
        }
        *value_out = r->regs[RNG_SR_OFFSET / 4];
        return MM_TRUE;
    }
    if (offset == RNG_DR_OFFSET) {
        if (!r->dr_valid) {
            rng_fill(r);
        }
        *value_out = r->dr;
        r->dr_valid = MM_FALSE;
        r->regs[RNG_SR_OFFSET / 4] &= ~1u;
        return MM_TRUE;
    }

    memcpy(value_out, (mm_u8 *)r->regs + offset, size_bytes);
    return MM_TRUE;
}

static mm_bool rng_write(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 value)
{
    struct rng_state *r = ((struct rng_state *)((void **)opaque)[0]);
    mm_bool secure_alias = ((void **)opaque)[1] != 0;
    struct rcc_state *rcc = (struct rcc_state *)((void **)opaque)[2];
    struct simple_blk *tzsc = (struct simple_blk *)((void **)opaque)[3];

    if (size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if ((offset + size_bytes) > RNG_SIZE) return MM_FALSE;

    if (!secure_alias && rng_requires_secure(tzsc)) {
        return MM_TRUE;
    }
    if (!rng_clock_enabled(rcc)) {
        return MM_TRUE;
    }

    if (offset == RNG_SR_OFFSET || offset == RNG_DR_OFFSET) {
        return MM_TRUE;
    }

    memcpy((mm_u8 *)r->regs + offset, &value, size_bytes);
    if (offset == RNG_CR_OFFSET) {
        if ((value & (1u << 2)) == 0u) {
            r->dr_valid = MM_FALSE;
            r->regs[RNG_SR_OFFSET / 4] &= ~1u;
        }
        if ((value & (1u << 3)) != 0u) {
            if (g_rng_nvic != 0 && (r->regs[RNG_SR_OFFSET / 4] & 1u) != 0u) {
                mm_nvic_set_pending(g_rng_nvic, (mm_u32)RNG_IRQ, MM_TRUE);
            }
        }
    }
    return MM_TRUE;
}

static mm_bool wwdg_clock_enabled(void)
{
    return ((rcc.regs[0x58 / 4] >> 11) & 1u) != 0u;
}

static int exti_line_bank(int line)
{
    mm_u32 reg;
    mm_u32 shift;
    mm_u32 val;
    if (line < 0 || line > 15) return -1;
    reg = exti.regs[(EXTI_EXTICR1 + (mm_u32)(line / 4) * 4u) / 4u];
    shift = (mm_u32)(line % 4) * 8u;
    val = (reg >> shift) & 0xFFu;
    if (val > 8u) return -1;
    return (int)val;
}

static void exti_raise_irq(int line)
{
    if (g_exti_nvic != 0) {
        mm_nvic_set_pending(g_exti_nvic, (mm_u32)(11 + line), MM_TRUE);
    }
}

static void exti_set_pending_rise(int line)
{
    exti.regs[EXTI_RPR1 / 4u] |= (1u << line);
    if ((exti.regs[EXTI_IMR1 / 4u] & (1u << line)) != 0u) {
        exti_raise_irq(line);
    }
}

static void exti_set_pending_fall(int line)
{
    exti.regs[EXTI_FPR1 / 4u] |= (1u << line);
    if ((exti.regs[EXTI_IMR1 / 4u] & (1u << line)) != 0u) {
        exti_raise_irq(line);
    }
}

static void exti_gpio_update(int bank, mm_u32 old_level, mm_u32 new_level)
{
    int line;
    mm_u32 changed = old_level ^ new_level;
    if (changed == 0u) return;
    for (line = 0; line < 16; ++line) {
        mm_u32 mask = (1u << line);
        if ((changed & mask) == 0u) continue;
        if (exti_line_bank(line) != bank) continue;
        if ((new_level & mask) != 0u) {
            if ((exti.regs[EXTI_RTSR1 / 4u] & mask) != 0u) {
                exti_set_pending_rise(line);
            }
        } else {
            if ((exti.regs[EXTI_FTSR1 / 4u] & mask) != 0u) {
                exti_set_pending_fall(line);
            }
        }
    }
}

static mm_bool exti_read(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 *value_out)
{
    struct exti_state *e = (struct exti_state *)opaque;
    if (value_out == 0 || size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if ((offset + size_bytes) > EXTI_SIZE) return MM_FALSE;
    if (offset == EXTI_SWIER1) {
        *value_out = 0;
        return MM_TRUE;
    }
    memcpy(value_out, (mm_u8 *)e->regs + offset, size_bytes);
    return MM_TRUE;
}

static mm_bool exti_write(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 value)
{
    struct exti_state *e = (struct exti_state *)opaque;
    int line;
    if (size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if ((offset + size_bytes) > EXTI_SIZE) return MM_FALSE;
    if (offset == EXTI_SWIER1) {
        mm_u32 v = value & 0xFFFFu;
        for (line = 0; line < 16; ++line) {
            if ((v & (1u << line)) != 0u) {
                exti_set_pending_rise(line);
            }
        }
        return MM_TRUE;
    }
    if (offset == EXTI_RPR1) {
        e->regs[offset / 4u] &= ~value;
        return MM_TRUE;
    }
    if (offset == EXTI_FPR1) {
        e->regs[offset / 4u] &= ~value;
        return MM_TRUE;
    }
    memcpy((mm_u8 *)e->regs + offset, &value, size_bytes);
    return MM_TRUE;
}

static mm_bool iwdg_read(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 *value_out)
{
    struct iwdg_state *w = (struct iwdg_state *)opaque;
    if (value_out == 0 || size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if ((offset + size_bytes) > IWDG_SIZE) return MM_FALSE;
    if (offset == IWDG_KR) {
        *value_out = 0;
        return MM_TRUE;
    }
    memcpy(value_out, (mm_u8 *)w->regs + offset, size_bytes);
    return MM_TRUE;
}

static void iwdg_apply_key(struct iwdg_state *w, mm_u32 key)
{
    if (key == 0x5555u) {
        w->write_access = MM_TRUE;
    } else if (key == 0xAAAAu) {
        w->counter = w->regs[IWDG_RLR / 4u] & 0x0FFFu;
    } else if (key == 0xCCCCu) {
        w->running = MM_TRUE;
        w->write_access = MM_FALSE;
        w->counter = w->regs[IWDG_RLR / 4u] & 0x0FFFu;
    }
}

static mm_bool iwdg_write(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 value)
{
    struct iwdg_state *w = (struct iwdg_state *)opaque;
    if (size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if ((offset + size_bytes) > IWDG_SIZE) return MM_FALSE;
    if (offset == IWDG_KR) {
        iwdg_apply_key(w, value & 0xFFFFu);
        return MM_TRUE;
    }
    if (!w->write_access) {
        return MM_TRUE;
    }
    if (offset == IWDG_PR) {
        w->regs[IWDG_PR / 4u] = value & 0x7u;
        return MM_TRUE;
    }
    if (offset == IWDG_RLR) {
        w->regs[IWDG_RLR / 4u] = value & 0x0FFFu;
        return MM_TRUE;
    }
    if (offset == IWDG_WINR) {
        w->regs[IWDG_WINR / 4u] = value & 0x0FFFu;
        return MM_TRUE;
    }
    if (offset == IWDG_EWCR) {
        w->regs[IWDG_EWCR / 4u] = value;
        return MM_TRUE;
    }
    return MM_TRUE;
}

static mm_bool wwdg_read(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 *value_out)
{
    struct wwdg_state *w = (struct wwdg_state *)opaque;
    if (value_out == 0 || size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if ((offset + size_bytes) > WWDG_SIZE) return MM_FALSE;
    if (!wwdg_clock_enabled()) {
        *value_out = 0;
        return MM_TRUE;
    }
    memcpy(value_out, (mm_u8 *)w->regs + offset, size_bytes);
    return MM_TRUE;
}

static mm_bool wwdg_write(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 value)
{
    struct wwdg_state *w = (struct wwdg_state *)opaque;
    if (size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if ((offset + size_bytes) > WWDG_SIZE) return MM_FALSE;
    if (!wwdg_clock_enabled()) {
        return MM_TRUE;
    }
    if (offset == WWDG_CR) {
        w->regs[WWDG_CR / 4u] = value & 0xFFu;
        w->counter = w->regs[WWDG_CR / 4u] & 0x7Fu;
        return MM_TRUE;
    }
    if (offset == WWDG_CFR) {
        w->regs[WWDG_CFR / 4u] = value;
        return MM_TRUE;
    }
    if (offset == WWDG_SR) {
        w->regs[WWDG_SR / 4u] &= ~value;
        return MM_TRUE;
    }
    memcpy((mm_u8 *)w->regs + offset, &value, size_bytes);
    return MM_TRUE;
}

mm_u32 *mm_stm32l552_rcc_regs(void)
{
    return rcc.regs;
}

mm_u64 mm_stm32l552_cpu_hz(void)
{
    return rcc.cpu_hz;
}

void mm_stm32l552_exti_set_nvic(struct mm_nvic *nvic)
{
    g_exti_nvic = nvic;
    g_wdg_nvic = nvic;
}

void mm_stm32l552_watchdog_tick(mm_u64 cycles)
{
    static const mm_u32 iwdg_presc_div[8] = { 4u, 8u, 16u, 32u, 64u, 128u, 256u, 256u };
    mm_u64 cpu_hz = mm_stm32l552_cpu_hz();

    if (wwdg_clock_enabled() && wwdg.counter != 0u && (wwdg.regs[WWDG_CR / 4u] & 0x80u) != 0u) {
        mm_u32 wdgtb = (wwdg.regs[WWDG_CFR / 4u] >> 11) & 0x7u;
        mm_u64 step = 4096u * (mm_u64)(1u << wdgtb);
        wwdg.accum += cycles;
        while (wwdg.accum >= step) {
            wwdg.accum -= step;
            if (wwdg.counter > 0u) {
                wwdg.counter--;
                wwdg.regs[WWDG_CR / 4u] = (wwdg.regs[WWDG_CR / 4u] & ~0x7Fu) | (wwdg.counter & 0x7Fu);
                if (wwdg.counter == 0x40u && (wwdg.regs[WWDG_CFR / 4u] & (1u << 9)) != 0u) {
                    wwdg.regs[WWDG_SR / 4u] |= 1u;
                    if (g_wdg_nvic != 0) {
                        mm_nvic_set_pending(g_wdg_nvic, 0u, MM_TRUE);
                    }
                }
                if (wwdg.counter == 0x3Fu) {
                    mm_system_request_reset();
                    break;
                }
            }
        }
    }

    if (iwdg.running) {
        mm_u32 pr = iwdg.regs[IWDG_PR / 4u] & 0x7u;
        mm_u64 ticks_per_sec;
        mm_u64 cycles_per_tick;
        mm_u64 lsi = 32000u;
        mm_u32 div = iwdg_presc_div[pr];
        ticks_per_sec = lsi / (mm_u64)div;
        if (ticks_per_sec == 0) ticks_per_sec = 1;
        if (cpu_hz == 0) cpu_hz = 1;
        cycles_per_tick = cpu_hz / ticks_per_sec;
        if (cycles_per_tick == 0) cycles_per_tick = 1;
        iwdg.accum += cycles;
        while (iwdg.accum >= cycles_per_tick) {
            iwdg.accum -= cycles_per_tick;
            if (iwdg.counter > 0u) {
                iwdg.counter--;
            }
            if (iwdg.counter == 0u) {
                mm_system_request_reset();
                break;
            }
        }
    }
}

mm_bool mm_stm32l552_register_mmio(struct mmio_bus *bus)
{
    struct mmio_region reg;

    memset(&rcc, 0, sizeof(rcc));
    memset(&pwr, 0, sizeof(pwr));
    memset(&tzsc_s, 0, sizeof(tzsc_s));
    memset(&tzsc_ns, 0, sizeof(tzsc_ns));
    memset(&tzic_s, 0, sizeof(tzic_s));
    memset(&tzic_ns, 0, sizeof(tzic_ns));
    memset(&rng, 0, sizeof(rng));
    memset(&hash_accel, 0, sizeof(hash_accel));
    memset(&aes_accel, 0, sizeof(aes_accel));
    memset(&exti, 0, sizeof(exti));
    memset(&iwdg, 0, sizeof(iwdg));
    memset(&wwdg, 0, sizeof(wwdg));
    memset(&flash_ctl, 0, sizeof(flash_ctl));
    memset(gpio, 0, sizeof(gpio));
    mpcbb_init_defaults();
    memset(&gpdma1, 0, sizeof(gpdma1));
    rcc.regs[RCC_CR / 4] = 0x00000063u;
    rcc_update_ready(&rcc);
    rcc_update_sysclk(&rcc);
    hash_ctx[0].state = &hash_accel;
    hash_ctx[0].secure_alias = MM_FALSE;
    hash_ctx[0].rcc = &rcc;
    hash_ctx[0].tzsc = &tzsc_s;
    hash_ctx[1].state = &hash_accel;
    hash_ctx[1].secure_alias = MM_TRUE;
    hash_ctx[1].rcc = &rcc;
    hash_ctx[1].tzsc = &tzsc_s;
    aes_ctx[0].state = &aes_accel;
    aes_ctx[0].secure_alias = MM_FALSE;
    aes_ctx[0].rcc = &rcc;
    aes_ctx[0].tzsc = &tzsc_s;
    aes_ctx[1].state = &aes_accel;
    aes_ctx[1].secure_alias = MM_TRUE;
    aes_ctx[1].rcc = &rcc;
    aes_ctx[1].tzsc = &tzsc_s;
    pka_ctx[0].state = &pka_accel;
    pka_ctx[0].secure_alias = MM_FALSE;
    pka_ctx[0].rcc = &rcc;
    pka_ctx[0].tzsc = &tzsc_s;
    pka_ctx[1].state = &pka_accel;
    pka_ctx[1].secure_alias = MM_TRUE;
    pka_ctx[1].rcc = &rcc;
    pka_ctx[1].tzsc = &tzsc_s;
    rng.regs[RNG_CR_OFFSET / 4] = 0x00871f00u;
    rng.regs[RNG_HTCR_OFFSET / 4] = 0x000072acu;
    flash_ctl.regs[FLASH_ACR / 4] = 0x00000013u;
    flash_ctl.regs[FLASH_NSCR / 4] = 0x00000001u;
    flash_ctl.regs[FLASH_SECCR / 4] = 0x00000001u;
    iwdg.regs[IWDG_RLR / 4] = 0x00000FFFu;
    iwdg.regs[IWDG_WINR / 4] = 0x00000FFFu;
    wwdg.regs[WWDG_CR / 4] = 0x0000007Fu;
    wwdg.regs[WWDG_CFR / 4] = 0x0000007Fu;
    wwdg.counter = 0x7Fu;
    exti.regs[EXTI_IMR1 / 4u] = 0xFFFE0000u;

    /* RCC */
    reg.base = RCC_BASE;
    reg.size = RCC_SIZE;
    reg.opaque = &rcc;
    reg.read = rcc_read;
    reg.write = rcc_write;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;
    /* RCC secure alias */
    reg.base = RCC_SEC_BASE;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;

    /* PWR */
    reg.base = PWR_BASE;
    reg.size = PWR_SIZE;
    reg.opaque = &pwr;
    reg.read = pwr_read;
    reg.write = pwr_write;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;
    /* PWR secure alias */
    reg.base = PWR_SEC_BASE;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;

    /* UCPD1 */
    reg.base = UCPD1_BASE;
    reg.size = UCPD1_SIZE;
    reg.opaque = &ucpd1_state;
    reg.read = ucpd_read;
    reg.write = ucpd_write;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;
    /* UCPD1 secure alias */
    reg.base = UCPD1_SEC_BASE;
    reg.opaque = &ucpd1_state_sec;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;

    /* CRS */
    reg.base = CRS_BASE;
    reg.size = CRS_SIZE;
    reg.opaque = &crs;
    reg.read = simple_blk_read;
    reg.write = simple_blk_write;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;
    /* CRS secure alias */
    reg.base = CRS_SEC_BASE;
    reg.opaque = &crs_sec;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;

    /* FLASH controller */
    reg.base = FLASH_BASE;
    reg.size = FLASH_SIZE;
    reg.opaque = &flash_ctl;
    reg.read = flash_read;
    reg.write = flash_write;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;
    /* FLASH secure alias */
    reg.base = FLASH_SEC_BASE;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;

    /* GTZC TZSC secure */
    reg.base = GTZC_TZSC_S_BASE;
    reg.size = GTZC_TZSC_SIZE;
    reg.opaque = &tzsc_s;
    reg.read = simple_blk_read;
    reg.write = simple_blk_write;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;

    /* GTZC TZSC non-secure alias */
    reg.base = GTZC_TZSC_NS_BASE;
    reg.opaque = &tzsc_ns;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;

    /* GTZC TZIC secure */
    reg.base = GTZC_TZIC_S_BASE;
    reg.size = GTZC_TZIC_SIZE;
    reg.opaque = &tzic_s;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;

    /* GTZC TZIC non-secure alias */
    reg.base = GTZC_TZIC_NS_BASE;
    reg.opaque = &tzic_ns;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;

    /* MPCBB1..2 (non-secure and secure aliases) */
    reg.size = MPCBB_SIZE;
    reg.read = mpcbb_read;
    reg.write = mpcbb_write;
    reg.base = MPCBB1_BASE;
    reg.opaque = &mpcbb[0];
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;
    reg.base = MPCBB1_SEC_BASE;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;

    reg.base = MPCBB2_BASE;
    reg.opaque = &mpcbb[1];
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;
    reg.base = MPCBB2_SEC_BASE;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;

    /* AES (non-secure and secure aliases) */
    reg.base = AES_BASE;
    reg.size = AES_SIZE;
    reg.opaque = &aes_ctx[0];
    reg.read = aes_read;
    reg.write = aes_write;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;
    reg.base = AES_SEC_BASE;
    reg.opaque = &aes_ctx[1];
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;

    /* HASH (non-secure and secure aliases) */
    reg.base = HASH_BASE;
    reg.size = HASH_SIZE;
    reg.opaque = &hash_ctx[0];
    reg.read = hash_read;
    reg.write = hash_write;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;
    reg.base = HASH_SEC_BASE;
    reg.opaque = &hash_ctx[1];
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;

    /* PKA (non-secure and secure aliases) */
    reg.base = PKA_BASE;
    reg.size = PKA_SIZE;
    reg.opaque = &pka_ctx[0];
    reg.read = pka_read;
    reg.write = pka_write;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;
    reg.base = PKA_SEC_BASE;
    reg.opaque = &pka_ctx[1];
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;


    /* RNG (non-secure and secure aliases) */
    reg.base = RNG_BASE;
    reg.size = RNG_SIZE;
    rng_ctx[0][0] = &rng;
    rng_ctx[0][1] = (void *)0;
    rng_ctx[0][2] = &rcc;
    rng_ctx[0][3] = &tzsc_s;
    reg.opaque = rng_ctx[0];
    reg.read = rng_read;
    reg.write = rng_write;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;

    reg.base = RNG_SEC_BASE;
    rng_ctx[1][0] = &rng;
    rng_ctx[1][1] = (void *)1;
    rng_ctx[1][2] = &rcc;
    rng_ctx[1][3] = &tzsc_s;
    reg.opaque = rng_ctx[1];
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;

    /* EXTI (non-secure and secure aliases) */
    reg.base = EXTI_BASE;
    reg.size = EXTI_SIZE;
    reg.opaque = &exti;
    reg.read = exti_read;
    reg.write = exti_write;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;
    reg.base = EXTI_SEC_BASE;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;

    /* IWDG (non-secure and secure aliases) */
    reg.base = IWDG_BASE;
    reg.size = IWDG_SIZE;
    reg.opaque = &iwdg;
    reg.read = iwdg_read;
    reg.write = iwdg_write;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;
    reg.base = IWDG_SEC_BASE;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;

    /* WWDG (non-secure and secure aliases) */
    reg.base = WWDG_BASE;
    reg.size = WWDG_SIZE;
    reg.opaque = &wwdg;
    reg.read = wwdg_read;
    reg.write = wwdg_write;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;
    reg.base = WWDG_SEC_BASE;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;

    /* GPDMA1 (non-secure and secure aliases) */
    reg.size = 0x1000u;
    reg.read = gpdma_read;
    reg.write = gpdma_write;
    reg.base = 0x40020000u; /* GPDMA1 */
    reg.opaque = &gpdma1;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;
    reg.base = 0x50020000u; /* SEC_GPDMA1 */
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;

    /* GPIO A..I: NS alias 0x4202xxxx, Secure alias 0x5202xxxx */
    {
        mm_u32 base_ns = 0x42020000u;
        mm_u32 base_s  = 0x52020000u;
        int i;
        for (i = 0; i < 9; ++i) {
            /* NS */
            reg.base = base_ns + (mm_u32)(i * 0x400u);
            reg.size = 0x400u;
            gpio_ctx[i * 2][0] = &gpio[i];
            gpio_ctx[i * 2][1] = (void *)0; /* not secure alias */
            gpio_ctx[i * 2][2] = &rcc;
            gpio_ctx[i * 2][3] = (void *)(mm_uptr)i;
            reg.opaque = gpio_ctx[i * 2];
            reg.read = gpio_read;
            reg.write = gpio_write;
            if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;

            /* Secure */
            reg.base = base_s + (mm_u32)(i * 0x400u);
            gpio_ctx[i * 2 + 1][0] = &gpio[i];
            gpio_ctx[i * 2 + 1][1] = (void *)1; /* secure alias */
            gpio_ctx[i * 2 + 1][2] = &rcc;
            gpio_ctx[i * 2 + 1][3] = (void *)(mm_uptr)i;
            reg.opaque = gpio_ctx[i * 2 + 1];
            if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;
        }
    }

    if (!mm_stm32l552_usb_register_mmio(bus)) return MM_FALSE;

    return MM_TRUE;
}

void mm_stm32l552_flash_bind(struct mm_memmap *map,
                             mm_u8 *flash,
                             mm_u32 flash_size,
                             const struct mm_flash_persist *persist,
                             mm_u32 flags)
{
    if (map == 0) {
        return;
    }
    flash_ctl.flash = flash;
    flash_ctl.flash_size = flash_size;
    flash_ctl.persist = persist;
    flash_ctl.flags = flags;
    flash_ctl.base_s = map->flash_base_s;
    flash_ctl.base_ns = map->flash_base_ns;
    mm_memmap_set_flash_writer(map, flash_write_cb, &flash_ctl);
}

void mm_stm32l552_rng_set_nvic(struct mm_nvic *nvic)
{
    g_rng_nvic = nvic;
}
