/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Arm CryptoCell-312 MMIO peripheral model for nRF5340.
 *
 * See nrf5340_cryptocell.h for the register layout and design rationale.
 *
 * Operation model
 * ---------------
 * The real CC-312 uses a DMA-driven pipeline:
 *   1. Write AES key/IV (or HASH mode/initial state).
 *   2. Program AES_CONTROL / HASH_CONTROL.
 *   3. Write SRC_MEM_ADDR (input data pointer in target address space).
 *   4. Write DST_MEM_ADDR (output pointer for AES; HASH result in HASH_H[]).
 *   5. Write SRC_MEM_SIZE (triggers DMA + operation).
 *   6. Poll IRR.HASH_DONE or IRR.AES_DONE (or wait for IRQ 68).
 *   7. For AES: read DST (already written to target RAM).
 *      For SHA-256: read HASH_H[0..7].
 *
 * We trigger the operation synchronously on the SRC_MEM_SIZE write.
 * The result is placed in target RAM (AES) or in HASH_H[] (SHA-256)
 * before the write returns.
 *
 * AES_CONTROL bits (per CC-312 / nrf5340_application.h):
 *   [2:0] mode: 0=ECB, 1=CBC, 3=CTR
 *   [3]   direction: 0=encrypt, 1=decrypt
 *   [5:4] key size: 0=128, 1=192, 2=256
 *
 * HASH_CONTROL bits:
 *   [3:0] mode: 1=MD5, 2=SHA-1, 3=SHA-256, 5=SHA-384, 6=SHA-512
 *
 * IRR bits (HOST_RGF IRR at engine-base + 0xA00):
 *   [0]  AXIM_COMP (AXI master completion — we use it as generic "done")
 *   [1]  AES_COMPLETE
 *   [2]  HASH_COMPLETE
 *   [8]  CONFIG_COMPLETE
 *   [9]  ERROR
 *
 * TODO: align with real CC-312 nrfx driver for complete silicon fidelity.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "nrf5340_cryptocell.h"
#include "../mm_host_crypto.h"
#include "m33mu/nvic.h"
#include "m33mu/memmap.h"
#include "m33mu/cpu.h"   /* for MM_SECURE */

/* -------------------------------------------------------------------------
 * CRYPTOCELL_IRQn
 * Per nrf5340_application.h: CRYPTOCELL_IRQn = 68
 * ------------------------------------------------------------------------- */
#define CRYPTOCELL_IRQn    68u

/* -------------------------------------------------------------------------
 * Engine region (base = 0x50845000) register offsets
 * ------------------------------------------------------------------------- */

/* AES sub-block */
#define AES_KEY_0_OFF      0x400u  /* 8 words (32 bytes) */
#define AES_KEY_1_OFF      0x420u  /* 8 words — not used in this model */
#define AES_IV_0_OFF       0x440u  /* 4 words (16 bytes) */
#define AES_IV_1_OFF       0x450u  /* not used */
#define AES_CTR_OFF        0x460u  /* not used */
#define AES_BUSY_OFF       0x470u
#define AES_REMAINING_OFF  0x4BCu
#define AES_CONTROL_OFF    0x4C0u
#define AES_HW_FLAGS_OFF   0x4C8u
#define AES_SW_RESET_OFF   0x4F4u

/* HASH sub-block */
#define HASH_H_OFF         0x640u  /* 8 words (32 bytes) */
#define HASH_PAD_AUTO_OFF  0x684u
#define HASH_XOR_DIN_OFF   0x688u
#define HASH_INIT_STATE_OFF 0x694u
#define HASH_SELECT_OFF    0x6A4u
#define HASH_CONTROL_OFF   0x7C0u
#define HASH_PAD_OFF       0x7C4u
#define HASH_PAD_FORCE_OFF 0x7C8u
#define HASH_CUR_LEN_0_OFF 0x7CCu
#define HASH_CUR_LEN_1_OFF 0x7D0u
#define HASH_HW_FLAGS_OFF  0x7DCu
#define HASH_SW_RESET_OFF  0x7E4u
#define HASH_ENDIAN_OFF    0x7E8u

/* CTL sub-block */
#define CTL_CRYPTO_CTL_OFF 0x900u
#define CTL_CRYPTO_BUSY_OFF 0x910u
#define CTL_HASH_BUSY_OFF  0x91Cu
#define CTL_CONTEXT_ID_OFF 0x930u

/* DIN sub-block */
#define DIN_BUFFER_OFF     0xC00u
#define DIN_DMA_MEM_BUSY_OFF 0xC20u
#define DIN_SRC_MEM_ADDR_OFF 0xC28u
#define DIN_SRC_MEM_SIZE_OFF 0xC2Cu  /* write triggers DMA */
#define DIN_DIN_FIFO_EMPTY_OFF 0xC50u
#define DIN_SW_RESET_OFF   0xC44u

/* DOUT sub-block */
#define DOUT_BUFFER_OFF    0xD00u
#define DOUT_DMA_MEM_BUSY_OFF 0xD20u
#define DOUT_DST_MEM_ADDR_OFF 0xD28u
#define DOUT_DST_MEM_SIZE_OFF 0xD2Cu
#define DOUT_DOUT_FIFO_EMPTY_OFF 0xD50u
#define DOUT_SW_RESET_OFF  0xD58u

/* HOST_RGF sub-block */
#define HOST_IRR_OFF       0xA00u
#define HOST_IMR_OFF       0xA04u
#define HOST_ICR_OFF       0xA08u
#define HOST_ENDIAN_OFF    0xA0Cu
#define HOST_SIGNATURE_OFF 0xA24u
#define HOST_BOOT_OFF      0xA28u
#define HOST_CC_IS_IDLE_OFF 0xA7Cu
#define HOST_POWERDOWN_OFF  0xA80u

/* Size of the engine register region we expose */
#define CC_ENGINE_SIZE     0x2000u

/* CRYPTOCELL control region (0x50844000) size */
#define CC_CTRL_SIZE       0x1000u
#define CC_CTRL_ENABLE_OFF 0x500u

/* IRR / ICR bits */
#define IRR_AXIM_COMP      (1u << 0)
#define IRR_AES_COMPLETE   (1u << 1)
#define IRR_HASH_COMPLETE  (1u << 2)
#define IRR_CONFIG_COMPLETE (1u << 8)
#define IRR_ERROR          (1u << 9)

/* AES_CONTROL bits */
#define AES_CTRL_MODE_MASK  0x07u
#define AES_CTRL_MODE_ECB   0u
#define AES_CTRL_MODE_CBC   1u
#define AES_CTRL_MODE_CTR   3u
#define AES_CTRL_DECRYPT    (1u << 3)
#define AES_CTRL_KEYSZ_MASK (0x3u << 4)
#define AES_CTRL_KEYSZ_128  (0u << 4)
#define AES_CTRL_KEYSZ_192  (1u << 4)
#define AES_CTRL_KEYSZ_256  (2u << 4)

/* HASH_CONTROL mode values */
#define HASH_MODE_SHA256    3u
#define HASH_MODE_SHA384    5u
#define HASH_MODE_SHA512    6u

/* -------------------------------------------------------------------------
 * Peripheral state
 * ------------------------------------------------------------------------- */

/* Maximum key size (AES-256 = 32 bytes = 8 words) */
#define CC_AES_KEY_WORDS  8u
#define CC_AES_IV_WORDS   4u
#define CC_HASH_H_WORDS   8u

struct mm_nrf5340_cryptocell {
    /* NVIC + memmap back-pointers */
    struct mm_nvic   *nvic;
    struct mm_memmap *map;

    /* CRYPTOCELL control region */
    mm_u32 ctrl_enable;

    /* AES registers */
    mm_u32 aes_key[CC_AES_KEY_WORDS];    /* AES_KEY_0[0..7] */
    mm_u32 aes_iv[CC_AES_IV_WORDS];      /* AES_IV_0[0..3] */
    mm_u32 aes_remaining;
    mm_u32 aes_control;

    /* HASH registers */
    mm_u32 hash_h[CC_HASH_H_WORDS];      /* result / init state */
    mm_u32 hash_control;
    mm_u32 hash_pad;
    mm_u32 hash_pad_auto;
    mm_u32 hash_init_state;
    mm_u32 hash_cur_len[2];

    /* CTL registers */
    mm_u32 crypto_ctl;

    /* DIN/DOUT */
    mm_u32 din_src_addr;
    mm_u32 din_src_size;
    mm_u32 dout_dst_addr;
    mm_u32 dout_dst_size;

    /* HOST_RGF interrupt registers */
    mm_u32 irr;      /* interrupt request register (R/O; cleared via ICR) */
    mm_u32 imr;      /* interrupt mask (0 bit = unmasked) */
    mm_u32 endianness;

    /* General-purpose staging regs (context ID, etc.) */
    mm_u32 context_id;
};

/* -------------------------------------------------------------------------
 * Lifecycle
 * ------------------------------------------------------------------------- */

struct mm_nrf5340_cryptocell *mm_nrf5340_cryptocell_new(void)
{
    struct mm_nrf5340_cryptocell *cc;
    cc = (struct mm_nrf5340_cryptocell *)calloc(1, sizeof(*cc));
    return cc;
}

void mm_nrf5340_cryptocell_reset(struct mm_nrf5340_cryptocell *cc)
{
    struct mm_nvic   *nvic_save;
    struct mm_memmap *map_save;
    if (cc == NULL) return;
    nvic_save = cc->nvic;
    map_save  = cc->map;
    memset(cc, 0, sizeof(*cc));
    cc->nvic = nvic_save;
    cc->map  = map_save;
    /* IMR reset: all interrupts masked by default (1 = masked per CC-312 spec) */
    cc->imr = 0xFFFFFFFFu;
}

void mm_nrf5340_cryptocell_free(struct mm_nrf5340_cryptocell *cc)
{
    free(cc);
}

void mm_nrf5340_cryptocell_set_nvic(struct mm_nrf5340_cryptocell *cc,
                                    struct mm_nvic *nvic)
{
    if (cc != NULL) cc->nvic = nvic;
}

void mm_nrf5340_cryptocell_set_memmap(struct mm_nrf5340_cryptocell *cc,
                                      struct mm_memmap *map)
{
    if (cc != NULL) cc->map = map;
}

/* -------------------------------------------------------------------------
 * IRQ delivery helper
 * Interrupt fires when the corresponding bit in IRR is 1 AND the same bit
 * in IMR is 0 (unmasked).
 * ------------------------------------------------------------------------- */
static void cc_maybe_irq(struct mm_nrf5340_cryptocell *cc)
{
    if (cc->nvic == NULL) return;
    if ((cc->irr & ~cc->imr) != 0u) {
        mm_nvic_set_pending(cc->nvic, CRYPTOCELL_IRQn, MM_TRUE);
    }
}

/* -------------------------------------------------------------------------
 * Helper: read N bytes from target address space into a local buffer.
 * Returns MM_FALSE if any byte fails.
 * ------------------------------------------------------------------------- */
static mm_bool cc_read_mem(struct mm_nrf5340_cryptocell *cc,
                           mm_u32 addr, mm_u8 *out, mm_u32 len)
{
    mm_u32 i;
    mm_u32 val;
    mm_u32 aligned;
    mm_u32 off;

    if (cc->map == NULL || out == NULL) return MM_FALSE;

    /* Word-aligned path */
    if ((addr & 3u) == 0u && (len & 3u) == 0u) {
        for (i = 0u; i < len; i += 4u) {
            if (!mm_memmap_read(cc->map, MM_SECURE, addr + i, 4u, &val))
                return MM_FALSE;
            out[i]     = (mm_u8)(val & 0xffu);
            out[i + 1] = (mm_u8)((val >> 8)  & 0xffu);
            out[i + 2] = (mm_u8)((val >> 16) & 0xffu);
            out[i + 3] = (mm_u8)((val >> 24) & 0xffu);
        }
        return MM_TRUE;
    }

    /* Unaligned fallback: read byte by byte via 4-byte aligned reads */
    for (i = 0u; i < len; ++i) {
        aligned = (addr + i) & ~3u;
        off     = (addr + i) & 3u;
        if (!mm_memmap_read(cc->map, MM_SECURE, aligned, 4u, &val))
            return MM_FALSE;
        out[i] = (mm_u8)((val >> (off * 8u)) & 0xffu);
    }
    return MM_TRUE;
}

/* -------------------------------------------------------------------------
 * Helper: write N bytes to target address space.
 * ------------------------------------------------------------------------- */
static mm_bool cc_write_mem(struct mm_nrf5340_cryptocell *cc,
                            mm_u32 addr, const mm_u8 *src, mm_u32 len)
{
    mm_u32 i;
    mm_u32 val;

    if (cc->map == NULL || src == NULL) return MM_FALSE;

    /* Word-aligned path */
    if ((addr & 3u) == 0u && (len & 3u) == 0u) {
        for (i = 0u; i < len; i += 4u) {
            val = (mm_u32)src[i] |
                  ((mm_u32)src[i + 1] << 8) |
                  ((mm_u32)src[i + 2] << 16) |
                  ((mm_u32)src[i + 3] << 24);
            if (!mm_memmap_write(cc->map, MM_SECURE, addr + i, 4u, val))
                return MM_FALSE;
        }
        return MM_TRUE;
    }

    /* Unaligned: write word by word via RMW (simple byte-write via write8) */
    for (i = 0u; i < len; ++i) {
        if (!mm_memmap_write8(cc->map, MM_SECURE, addr + i, src[i]))
            return MM_FALSE;
    }
    return MM_TRUE;
}

/* -------------------------------------------------------------------------
 * Build AES key bytes from word array (words are little-endian as written
 * by firmware on an LE host).
 * ------------------------------------------------------------------------- */
static void cc_words_to_bytes(const mm_u32 *words, mm_u32 n_words, mm_u8 *out)
{
    mm_u32 i;
    for (i = 0u; i < n_words; ++i) {
        mm_u32 w = words[i];
        out[i * 4u]     = (mm_u8)(w & 0xffu);
        out[i * 4u + 1] = (mm_u8)((w >> 8) & 0xffu);
        out[i * 4u + 2] = (mm_u8)((w >> 16) & 0xffu);
        out[i * 4u + 3] = (mm_u8)((w >> 24) & 0xffu);
    }
}

/* -------------------------------------------------------------------------
 * Execute operation triggered by SRC_MEM_SIZE write.
 *
 * Determines the active operation from AES_CONTROL / HASH_CONTROL /
 * CRYPTO_CTL and dispatches to host-crypto helpers.
 * ------------------------------------------------------------------------- */
static void cc_execute(struct mm_nrf5340_cryptocell *cc, mm_u32 len)
{
    mm_u32 hash_mode;
    mm_u32 aes_mode;
    mm_bool decrypt;
    mm_u32 keysz;
    mm_u32 key_len;
    mm_u8  key_bytes[32];
    mm_u8  iv_bytes[16];
    mm_u8 *inbuf;
    mm_u8 *outbuf;
    mm_bool ok;
    mm_u32 i;
    mm_u32 w;

    if (len == 0u) {
        cc->irr |= IRR_ERROR;
        cc_maybe_irq(cc);
        return;
    }

    /*
     * Determine operation type from HASH_CONTROL mode.
     * If HASH_CONTROL.mode != 0, this is a HASH operation.
     * Otherwise it's an AES operation.
     *
     * CRYPTO_CTL selects: bit[2:0] = 0 -> HASH, bit[2:0] = 1 -> AES.
     * (simplified: if HASH_CONTROL != 0, do hash; else do AES)
     */
    hash_mode = cc->hash_control & 0xFu;

    if (hash_mode != 0u) {
        /* ---- HASH operation ---- */
        if (hash_mode != HASH_MODE_SHA256) {
            /* Only SHA-256 is implemented. */
            fprintf(stderr, "[CC312] HASH mode %u not implemented (TODO)\n",
                    hash_mode);
            cc->irr |= IRR_ERROR;
            cc_maybe_irq(cc);
            return;
        }

        inbuf = (mm_u8 *)malloc(len);
        if (inbuf == NULL) {
            cc->irr |= IRR_ERROR;
            cc_maybe_irq(cc);
            return;
        }

        if (!cc_read_mem(cc, cc->din_src_addr, inbuf, len)) {
            free(inbuf);
            cc->irr |= IRR_ERROR;
            cc_maybe_irq(cc);
            return;
        }

        {
            mm_u8 digest[32];
            ok = mm_host_sha256(inbuf, (size_t)len, digest);
            free(inbuf);

            if (!ok) {
                /* No wolfSSL — store zero digest so firmware doesn't hang */
                memset(digest, 0, sizeof(digest));
            }

            /* Store result in HASH_H[0..7] (big-endian words per CC-312 spec) */
            for (i = 0u; i < 8u; ++i) {
                w = ((mm_u32)digest[i * 4u]      << 24) |
                    ((mm_u32)digest[i * 4u + 1u] << 16) |
                    ((mm_u32)digest[i * 4u + 2u] << 8)  |
                    ((mm_u32)digest[i * 4u + 3u]);
                cc->hash_h[i] = w;
            }

            /* If DST_MEM_ADDR is set, also write the digest to target RAM */
            if (cc->dout_dst_addr != 0u) {
                cc_write_mem(cc, cc->dout_dst_addr, digest, 32u);
            }
        }

        cc->irr |= IRR_HASH_COMPLETE | IRR_AXIM_COMP;
        cc_maybe_irq(cc);
        return;
    }

    /* ---- AES operation ---- */
    aes_mode = cc->aes_control & AES_CTRL_MODE_MASK;
    if (aes_mode != AES_CTRL_MODE_CBC) {
        /* Only AES-CBC is implemented. */
        fprintf(stderr, "[CC312] AES mode %u not implemented (TODO)\n",
                aes_mode);
        cc->irr |= IRR_ERROR;
        cc_maybe_irq(cc);
        return;
    }

    /* Validate length is a multiple of 16 */
    if ((len & 0xFu) != 0u) {
        fprintf(stderr, "[CC312] AES CBC len %u not multiple of 16\n",
                (unsigned)len);
        cc->irr |= IRR_ERROR;
        cc_maybe_irq(cc);
        return;
    }

    /* Determine key size */
    keysz = (cc->aes_control & AES_CTRL_KEYSZ_MASK) >> 4;
    switch (keysz) {
    case 1u:  key_len = 24u; break;
    case 2u:  key_len = 32u; break;
    default:  key_len = 16u; break;
    }

    decrypt = (cc->aes_control & AES_CTRL_DECRYPT) != 0u;

    /* Build key and IV byte arrays (LE word order) */
    cc_words_to_bytes(cc->aes_key, key_len / 4u, key_bytes);
    cc_words_to_bytes(cc->aes_iv,  CC_AES_IV_WORDS, iv_bytes);

    inbuf  = (mm_u8 *)malloc(len);
    outbuf = (mm_u8 *)malloc(len);
    if (inbuf == NULL || outbuf == NULL) {
        free(inbuf);
        free(outbuf);
        cc->irr |= IRR_ERROR;
        cc_maybe_irq(cc);
        return;
    }

    if (!cc_read_mem(cc, cc->din_src_addr, inbuf, len)) {
        free(inbuf);
        free(outbuf);
        cc->irr |= IRR_ERROR;
        cc_maybe_irq(cc);
        return;
    }

    if (decrypt) {
        ok = mm_host_aes_cbc_dec(key_bytes, (size_t)key_len,
                                 iv_bytes, inbuf, outbuf, (size_t)len);
    } else {
        ok = mm_host_aes_cbc_enc(key_bytes, (size_t)key_len,
                                 iv_bytes, inbuf, outbuf, (size_t)len);
    }

    if (!ok) {
        /* No wolfSSL - return zeroes so firmware doesn't deadlock */
        memset(outbuf, 0, len);
    }

    if (cc->dout_dst_addr != 0u) {
        cc_write_mem(cc, cc->dout_dst_addr, outbuf, len);
    }

    free(inbuf);
    free(outbuf);

    cc->irr |= IRR_AES_COMPLETE | IRR_AXIM_COMP;
    cc_maybe_irq(cc);
}

/* -------------------------------------------------------------------------
 * CRYPTOCELL control region MMIO (0x50844000, size 0x1000)
 * Only ENABLE @ 0x500 is interesting.
 * ------------------------------------------------------------------------- */

mm_bool mm_nrf5340_cryptocell_ctrl_read(void *opaque, mm_u32 offset,
                                        mm_u32 size_bytes, mm_u32 *value_out)
{
    struct mm_nrf5340_cryptocell *cc = (struct mm_nrf5340_cryptocell *)opaque;
    if (cc == NULL || value_out == NULL) return MM_FALSE;
    if (size_bytes == 0u || size_bytes > 4u) return MM_FALSE;
    if ((offset + size_bytes) > CC_CTRL_SIZE) return MM_FALSE;

    if (offset == CC_CTRL_ENABLE_OFF && size_bytes == 4u) {
        *value_out = cc->ctrl_enable;
        return MM_TRUE;
    }
    *value_out = 0u;
    return MM_TRUE;
}

mm_bool mm_nrf5340_cryptocell_ctrl_write(void *opaque, mm_u32 offset,
                                         mm_u32 size_bytes, mm_u32 value)
{
    struct mm_nrf5340_cryptocell *cc = (struct mm_nrf5340_cryptocell *)opaque;
    if (cc == NULL) return MM_FALSE;
    if (size_bytes == 0u || size_bytes > 4u) return MM_FALSE;
    if ((offset + size_bytes) > CC_CTRL_SIZE) return MM_FALSE;

    if (offset == CC_CTRL_ENABLE_OFF && size_bytes == 4u) {
        cc->ctrl_enable = value;
    }
    return MM_TRUE;
}

/* -------------------------------------------------------------------------
 * Engine region MMIO (0x50845000, size 0x2000)
 * ------------------------------------------------------------------------- */

mm_bool mm_nrf5340_cryptocell_read(void *opaque, mm_u32 offset,
                                   mm_u32 size_bytes, mm_u32 *value_out)
{
    struct mm_nrf5340_cryptocell *cc = (struct mm_nrf5340_cryptocell *)opaque;
    mm_u32 idx;

    if (cc == NULL || value_out == NULL) return MM_FALSE;
    if (size_bytes == 0u || size_bytes > 4u) return MM_FALSE;
    if ((offset + size_bytes) > CC_ENGINE_SIZE) return MM_FALSE;

    /* Default: return 0 for unknown/unmodelled registers */
    *value_out = 0u;

    /* AES registers */
    if (offset >= AES_KEY_0_OFF && offset < AES_KEY_0_OFF + CC_AES_KEY_WORDS * 4u) {
        /* AES_KEY is write-only in real hardware; return 0 */
        return MM_TRUE;
    }
    if (offset >= AES_IV_0_OFF && offset < AES_IV_0_OFF + CC_AES_IV_WORDS * 4u) {
        idx = (offset - AES_IV_0_OFF) / 4u;
        *value_out = cc->aes_iv[idx];
        return MM_TRUE;
    }
    if (offset == AES_REMAINING_OFF) {
        *value_out = cc->aes_remaining;
        return MM_TRUE;
    }
    if (offset == AES_CONTROL_OFF) {
        *value_out = cc->aes_control;
        return MM_TRUE;
    }
    if (offset == AES_BUSY_OFF) {
        *value_out = 0u; /* always ready */
        return MM_TRUE;
    }
    if (offset == AES_HW_FLAGS_OFF) {
        *value_out = 0x00000001u; /* AES supported */
        return MM_TRUE;
    }

    /* HASH registers */
    if (offset >= HASH_H_OFF && offset < HASH_H_OFF + CC_HASH_H_WORDS * 4u) {
        idx = (offset - HASH_H_OFF) / 4u;
        *value_out = cc->hash_h[idx];
        return MM_TRUE;
    }
    if (offset == HASH_CONTROL_OFF) {
        *value_out = cc->hash_control;
        return MM_TRUE;
    }
    if (offset == HASH_PAD_OFF) {
        *value_out = cc->hash_pad;
        return MM_TRUE;
    }
    if (offset == HASH_PAD_AUTO_OFF) {
        *value_out = cc->hash_pad_auto;
        return MM_TRUE;
    }
    if (offset == HASH_CUR_LEN_0_OFF) {
        *value_out = cc->hash_cur_len[0];
        return MM_TRUE;
    }
    if (offset == HASH_CUR_LEN_1_OFF) {
        *value_out = cc->hash_cur_len[1];
        return MM_TRUE;
    }
    if (offset == HASH_HW_FLAGS_OFF) {
        *value_out = 0x00000004u; /* SHA-256 supported */
        return MM_TRUE;
    }

    /* CTL registers */
    if (offset == CTL_CRYPTO_CTL_OFF) {
        *value_out = cc->crypto_ctl;
        return MM_TRUE;
    }
    if (offset == CTL_CRYPTO_BUSY_OFF || offset == CTL_HASH_BUSY_OFF) {
        *value_out = 0u; /* always idle */
        return MM_TRUE;
    }
    if (offset == CTL_CONTEXT_ID_OFF) {
        *value_out = cc->context_id;
        return MM_TRUE;
    }

    /* DIN registers */
    if (offset == DIN_SRC_MEM_ADDR_OFF) {
        *value_out = cc->din_src_addr;
        return MM_TRUE;
    }
    if (offset == DIN_SRC_MEM_SIZE_OFF) {
        *value_out = cc->din_src_size;
        return MM_TRUE;
    }
    if (offset == DIN_DMA_MEM_BUSY_OFF) {
        *value_out = 0u;
        return MM_TRUE;
    }
    if (offset == DIN_DIN_FIFO_EMPTY_OFF) {
        *value_out = 1u; /* FIFO empty (ready) */
        return MM_TRUE;
    }

    /* DOUT registers */
    if (offset == DOUT_DST_MEM_ADDR_OFF) {
        *value_out = cc->dout_dst_addr;
        return MM_TRUE;
    }
    if (offset == DOUT_DST_MEM_SIZE_OFF) {
        *value_out = cc->dout_dst_size;
        return MM_TRUE;
    }
    if (offset == DOUT_DMA_MEM_BUSY_OFF) {
        *value_out = 0u;
        return MM_TRUE;
    }
    if (offset == DOUT_DOUT_FIFO_EMPTY_OFF) {
        *value_out = 1u;
        return MM_TRUE;
    }

    /* HOST_RGF registers */
    if (offset == HOST_IRR_OFF) {
        *value_out = cc->irr;
        return MM_TRUE;
    }
    if (offset == HOST_IMR_OFF) {
        *value_out = cc->imr;
        return MM_TRUE;
    }
    if (offset == HOST_ICR_OFF) {
        *value_out = 0u; /* write-only */
        return MM_TRUE;
    }
    if (offset == HOST_ENDIAN_OFF) {
        *value_out = cc->endianness;
        return MM_TRUE;
    }
    if (offset == HOST_SIGNATURE_OFF) {
        *value_out = 0xDCC63116u; /* CC-312 subsystem signature */
        return MM_TRUE;
    }
    if (offset == HOST_BOOT_OFF) {
        *value_out = 0x00000001u; /* AES supported in boot config */
        return MM_TRUE;
    }
    if (offset == HOST_CC_IS_IDLE_OFF) {
        *value_out = 1u; /* always idle */
        return MM_TRUE;
    }
    if (offset == HOST_POWERDOWN_OFF) {
        *value_out = 0u;
        return MM_TRUE;
    }

    return MM_TRUE; /* default 0 for unmapped */
}

mm_bool mm_nrf5340_cryptocell_write(void *opaque, mm_u32 offset,
                                    mm_u32 size_bytes, mm_u32 value)
{
    struct mm_nrf5340_cryptocell *cc = (struct mm_nrf5340_cryptocell *)opaque;
    mm_u32 idx;

    if (cc == NULL) return MM_FALSE;
    if (size_bytes == 0u || size_bytes > 4u) return MM_FALSE;
    if ((offset + size_bytes) > CC_ENGINE_SIZE) return MM_FALSE;

    /* AES registers */
    if (offset >= AES_KEY_0_OFF && offset < AES_KEY_0_OFF + CC_AES_KEY_WORDS * 4u
        && size_bytes == 4u) {
        idx = (offset - AES_KEY_0_OFF) / 4u;
        cc->aes_key[idx] = value;
        return MM_TRUE;
    }
    if (offset >= AES_IV_0_OFF && offset < AES_IV_0_OFF + CC_AES_IV_WORDS * 4u
        && size_bytes == 4u) {
        idx = (offset - AES_IV_0_OFF) / 4u;
        cc->aes_iv[idx] = value;
        return MM_TRUE;
    }
    if (offset == AES_REMAINING_OFF) {
        cc->aes_remaining = value;
        return MM_TRUE;
    }
    if (offset == AES_CONTROL_OFF) {
        cc->aes_control = value;
        return MM_TRUE;
    }
    if (offset == AES_SW_RESET_OFF) {
        /* Reset AES engine state */
        memset(cc->aes_key, 0, sizeof(cc->aes_key));
        memset(cc->aes_iv, 0, sizeof(cc->aes_iv));
        cc->aes_remaining = 0u;
        cc->aes_control = 0u;
        return MM_TRUE;
    }

    /* HASH registers */
    if (offset >= HASH_H_OFF && offset < HASH_H_OFF + CC_HASH_H_WORDS * 4u
        && size_bytes == 4u) {
        idx = (offset - HASH_H_OFF) / 4u;
        cc->hash_h[idx] = value;
        return MM_TRUE;
    }
    if (offset == HASH_CONTROL_OFF) {
        cc->hash_control = value;
        return MM_TRUE;
    }
    if (offset == HASH_PAD_OFF) {
        cc->hash_pad = value;
        return MM_TRUE;
    }
    if (offset == HASH_PAD_AUTO_OFF) {
        cc->hash_pad_auto = value;
        return MM_TRUE;
    }
    if (offset == HASH_XOR_DIN_OFF) {
        /* Accepted, not acted on */
        return MM_TRUE;
    }
    if (offset == HASH_INIT_STATE_OFF) {
        cc->hash_init_state = value;
        return MM_TRUE;
    }
    if (offset == HASH_SELECT_OFF) {
        /* Accepted, not acted on */
        return MM_TRUE;
    }
    if (offset == HASH_CUR_LEN_0_OFF) {
        cc->hash_cur_len[0] = value;
        return MM_TRUE;
    }
    if (offset == HASH_CUR_LEN_1_OFF) {
        cc->hash_cur_len[1] = value;
        return MM_TRUE;
    }
    if (offset == HASH_SW_RESET_OFF) {
        memset(cc->hash_h, 0, sizeof(cc->hash_h));
        cc->hash_control = 0u;
        cc->hash_pad = 0u;
        cc->hash_cur_len[0] = 0u;
        cc->hash_cur_len[1] = 0u;
        return MM_TRUE;
    }
    if (offset == HASH_ENDIAN_OFF || offset == HASH_PAD_FORCE_OFF) {
        /* Accepted, not acted on */
        return MM_TRUE;
    }

    /* CTL registers */
    if (offset == CTL_CRYPTO_CTL_OFF) {
        cc->crypto_ctl = value;
        return MM_TRUE;
    }
    if (offset == CTL_CONTEXT_ID_OFF) {
        cc->context_id = value;
        return MM_TRUE;
    }

    /* DIN registers */
    if (offset == DIN_SRC_MEM_ADDR_OFF) {
        cc->din_src_addr = value;
        return MM_TRUE;
    }
    if (offset == DIN_SRC_MEM_SIZE_OFF) {
        /* Writing SRC_MEM_SIZE triggers the DMA + cryptographic operation */
        cc->din_src_size = value;
        cc_execute(cc, value);
        return MM_TRUE;
    }
    if (offset == DIN_SW_RESET_OFF) {
        cc->din_src_addr = 0u;
        cc->din_src_size = 0u;
        return MM_TRUE;
    }

    /* DOUT registers */
    if (offset == DOUT_DST_MEM_ADDR_OFF) {
        cc->dout_dst_addr = value;
        return MM_TRUE;
    }
    if (offset == DOUT_DST_MEM_SIZE_OFF) {
        cc->dout_dst_size = value;
        return MM_TRUE;
    }
    if (offset == DOUT_SW_RESET_OFF) {
        cc->dout_dst_addr = 0u;
        cc->dout_dst_size = 0u;
        return MM_TRUE;
    }
    if (offset == DOUT_DOUT_FIFO_EMPTY_OFF || offset == DOUT_DMA_MEM_BUSY_OFF) {
        /* Accepted, not acted on */
        return MM_TRUE;
    }

    /* HOST_RGF registers */
    if (offset == HOST_ICR_OFF) {
        /* W1C: clear corresponding bits in IRR */
        cc->irr &= ~value;
        return MM_TRUE;
    }
    if (offset == HOST_IMR_OFF) {
        cc->imr = value;
        return MM_TRUE;
    }
    if (offset == HOST_ENDIAN_OFF) {
        cc->endianness = value;
        return MM_TRUE;
    }
    if (offset == HOST_POWERDOWN_OFF) {
        /* Power-down sequence: accepted, not acted on */
        return MM_TRUE;
    }

    /* All other registers: silently ignore */
    return MM_TRUE;
}
