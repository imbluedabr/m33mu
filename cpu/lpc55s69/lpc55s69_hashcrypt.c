/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * LPC55S69 HashCrypt MMIO peripheral model.
 *
 * Register layout per NXP LPC55S69 User Manual / CMSIS periph2/PERI_HASHCRYPT.h:
 *   0x00  CTRL        mode + new_hash + options
 *   0x04  STATUS      waiting/digest/error flags
 *   0x08  INTENSET    interrupt enables (set)
 *   0x0C  INTENCLR    interrupt enables (clear)
 *   0x10  MEMCTRL     AHB master (not emulated)
 *   0x14  MEMADDR     AHB master address (not emulated)
 *   0x20  INDATA      data input (write-only)
 *   0x24..0x3F ALIAS[7] burst aliases for INDATA
 *   0x40..0x5F DIGEST0[8] result digest (read)
 *   0x80  CRYPTCFG    AES mode/key-size/direction
 *   0x84  CONFIG      capability read-only register
 *   0x8C  LOCK
 *   0x90..0x9F MASK[4]
 *   0xA0..0xBF RELOAD[8]
 *   0xD0  PRNG_SEED
 *   0xD8  PRNG_OUT
 *
 * Note: the CMSIS register struct ends at 0xDC.  We size the region to 0xE0
 * to cover the full aligned block; the extra 4 bytes at 0xDC..0xDF are R/W
 * stub registers.
 *
 * Key behaviours emulated:
 *  - SHA-256: CTRL.MODE=2, NEW_HASH=1 → stream init.
 *    Writes to INDATA/ALIAS accumulate 4-byte words.
 *    First read of DIGEST0 finalises the hash and clears WAITING.
 *  - AES-ECB/CBC/CTR: CTRL.MODE=4, CRYPTCFG selects mode/keysize/direction.
 *    INDATA/ALIAS writes collect 16-byte blocks (plus key/IV on NEW).
 *    DIGEST0..3 reads drain the output block.
 *  - No-wolfSSL: accepts all writes, returns all-zero digest, sets DIGEST so
 *    firmware polling loops are not infinite.
 *
 * IRQ: HASHCRYPT_IRQn = 54 (LPC55S69 CM33 core0 CMSIS header).
 */

#include <string.h>
#include <stddef.h>
#include "lpc55s69_hashcrypt.h"
#include "../mm_host_crypto.h"
#include "m33mu/nvic.h"

#ifdef M33MU_HAS_WOLFSSL
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sha256.h>
#endif

/* -------------------------------------------------------------------------
 * Register offsets
 * ------------------------------------------------------------------------- */
#define HC_OFF_CTRL       0x00u
#define HC_OFF_STATUS     0x04u
#define HC_OFF_INTENSET   0x08u
#define HC_OFF_INTENCLR   0x0Cu
#define HC_OFF_MEMCTRL    0x10u
#define HC_OFF_MEMADDR    0x14u
/* 0x18..0x1F reserved */
#define HC_OFF_INDATA     0x20u
#define HC_OFF_ALIAS_0    0x24u  /* ALIAS[0..6] = 0x24..0x3C */
#define HC_OFF_ALIAS_6    0x3Cu
#define HC_OFF_DIGEST0    0x40u  /* DIGEST0[0..7] = 0x40..0x5C */
#define HC_OFF_DIGEST7    0x5Cu
/* 0x60..0x7F reserved */
#define HC_OFF_CRYPTCFG   0x80u
#define HC_OFF_CONFIG     0x84u
/* 0x88 reserved */
#define HC_OFF_LOCK       0x8Cu
#define HC_OFF_MASK_0     0x90u  /* MASK[0..3] = 0x90..0x9C */
#define HC_OFF_MASK_3     0x9Cu
#define HC_OFF_RELOAD_0   0xA0u  /* RELOAD[0..7] = 0xA0..0xBC */
#define HC_OFF_RELOAD_7   0xBCu
/* 0xC0..0xCF reserved */
#define HC_OFF_PRNG_SEED  0xD0u
/* 0xD4 reserved */
#define HC_OFF_PRNG_OUT   0xD8u

/* We expose 0xE0 bytes so we cover the full CMSIS struct plus a small pad */
#define HC_SIZE           0xE0u

/* -------------------------------------------------------------------------
 * CTRL bits
 * ------------------------------------------------------------------------- */
#define CTRL_MODE_MASK    0x07u
#define CTRL_MODE_DISABLED 0u
#define CTRL_MODE_SHA1    1u
#define CTRL_MODE_SHA256  2u
#define CTRL_MODE_AES     4u
#define CTRL_NEW_HASH     (1u << 4)
#define CTRL_RELOAD_BIT   (1u << 5)
#define CTRL_HASHSWPB     (1u << 12)

/* -------------------------------------------------------------------------
 * STATUS bits
 * ------------------------------------------------------------------------- */
#define STATUS_WAITING    (1u << 0)
#define STATUS_DIGEST     (1u << 1)
#define STATUS_ERROR      (1u << 2)
#define STATUS_NEEDKEY    (1u << 4)
#define STATUS_NEEDIV     (1u << 5)

/* -------------------------------------------------------------------------
 * INTENSET / INTENCLR bits
 * ------------------------------------------------------------------------- */
#define INTEN_WAITING     (1u << 0)
#define INTEN_DIGEST      (1u << 1)
#define INTEN_ERROR       (1u << 2)

/* -------------------------------------------------------------------------
 * CRYPTCFG bits
 * ------------------------------------------------------------------------- */
#define CRYPTCFG_AESMODE_SHIFT  4u
#define CRYPTCFG_AESMODE_MASK   (0x3u << CRYPTCFG_AESMODE_SHIFT)
#define CRYPTCFG_AESMODE_ECB    (0u << CRYPTCFG_AESMODE_SHIFT)
#define CRYPTCFG_AESMODE_CBC    (1u << CRYPTCFG_AESMODE_SHIFT)
#define CRYPTCFG_AESMODE_CTR    (2u << CRYPTCFG_AESMODE_SHIFT)
#define CRYPTCFG_AESDECRYPT     (1u << 6)
#define CRYPTCFG_AESKEYSZ_SHIFT 8u
#define CRYPTCFG_AESKEYSZ_MASK  (0x3u << CRYPTCFG_AESKEYSZ_SHIFT)
#define CRYPTCFG_AESKEYSZ_128   (0u << CRYPTCFG_AESKEYSZ_SHIFT)
#define CRYPTCFG_AESKEYSZ_192   (1u << CRYPTCFG_AESKEYSZ_SHIFT)
#define CRYPTCFG_AESKEYSZ_256   (2u << CRYPTCFG_AESKEYSZ_SHIFT)
#define CRYPTCFG_SWAPKEY        (1u << 1)
#define CRYPTCFG_SWAPDAT        (1u << 2)
#define CRYPTCFG_MSW1ST         (1u << 3)
#define CRYPTCFG_MSW1ST_OUT     (1u << 0)

/* CONFIG value: AES=bit6, AESKEY=bit7, DMA=bit1, DUAL=bit0
 * (0x40|0x80|0x02|0x01 = 0xC3, but shift to match value 0x000C2000 from
 * an older LPC55S69 revision — CONFIG was in a BLOCK_IDR-style field.
 * We return 0x000C2000 as the plan says, using that as CONFIG@0x84.
 * Assumption: older SDK versions read CONFIG at 0x84 to get 0x000C2000. */
#define HC_CONFIG_VAL     0x000C2000u  /* DUAL|DMA|AHB|AES|AESKEY per plan */

/* HashCrypt IRQ number (HASHCRYPT_IRQn = 54 per LPC55S69_cm33_core0.h) */
#define HASHCRYPT_IRQn    54u

/* -------------------------------------------------------------------------
 * Forward declarations
 * ------------------------------------------------------------------------- */
static void hc_deliver_irq(struct mm_lpc55_hashcrypt *hc, mm_u32 which);
static void hc_indata_push(struct mm_lpc55_hashcrypt *hc, mm_u32 value);

/* -------------------------------------------------------------------------
 * Reset
 * ------------------------------------------------------------------------- */
mm_bool mm_lpc55_hashcrypt_reset(struct mm_lpc55_hashcrypt *hc)
{
    struct mm_nvic *nvic_save;
    if (hc == NULL) return MM_FALSE;
    nvic_save = hc->nvic;
    memset(hc, 0, sizeof(*hc));
    hc->nvic = nvic_save;
    /* CONFIG is read-only and reports capabilities */
    hc->regs[HC_OFF_CONFIG / 4u] = HC_CONFIG_VAL;
    return MM_TRUE;
}

/* -------------------------------------------------------------------------
 * Init
 * ------------------------------------------------------------------------- */
mm_bool mm_lpc55_hashcrypt_init(struct mm_lpc55_hashcrypt *hc,
                                struct mm_nvic *nvic)
{
    if (hc == NULL) return MM_FALSE;
    memset(hc, 0, sizeof(*hc));
    hc->nvic = nvic;
    hc->regs[HC_OFF_CONFIG / 4u] = HC_CONFIG_VAL;
    return MM_TRUE;
}

/* -------------------------------------------------------------------------
 * IRQ pulse helper
 * ------------------------------------------------------------------------- */
static void hc_deliver_irq(struct mm_lpc55_hashcrypt *hc, mm_u32 which)
{
    if (hc->nvic == NULL) return;
    if ((hc->intenset & which) != 0u) {
        mm_nvic_set_pending(hc->nvic, HASHCRYPT_IRQn, MM_TRUE);
    }
}

/* -------------------------------------------------------------------------
 * AES key/IV byte builder (little-endian word → big-endian bytes)
 * The HashCrypt hardware stores key/IV in little-endian word order by
 * default (CRYPTCFG.MSW1ST=0, CRYPTCFG.SWAPKEY=0).
 * wolfSSL expects big-endian byte keys.
 * Each word written by firmware is LE; we store it as-is in aes_key[],
 * then convert to bytes in aes_build_key_bytes().
 * ------------------------------------------------------------------------- */
static void aes_build_key_bytes(const mm_u32 *words, mm_u32 n_words, mm_u8 *out)
{
    mm_u32 i;
    for (i = 0u; i < n_words; ++i) {
        mm_u32 w = words[i];
        out[i * 4u]      = (mm_u8)((w)       & 0xffu);
        out[i * 4u + 1u] = (mm_u8)((w >> 8)  & 0xffu);
        out[i * 4u + 2u] = (mm_u8)((w >> 16) & 0xffu);
        out[i * 4u + 3u] = (mm_u8)((w >> 24) & 0xffu);
    }
}

/* -------------------------------------------------------------------------
 * SHA-256 block processing: apply compression to one 64-byte (16-word) block.
 *
 * The HashCrypt hardware expects firmware to supply the complete SHA-256
 * message schedule including padding.  The hardware applies the compression
 * function (no message-length management) to each 512-bit block.
 * We replicate this using wc_Sha256Transform if available, which applies
 * the SHA-256 compression without adding its own padding.
 *
 * Byte ordering: each LE 32-bit word written by the ARM core is byte-swapped
 * by the hardware before the SHA engine processes it:
 *   ARM writes word 0x64636261 → hardware bytes: 0x61,0x62,0x63,0x64 = "abcd"
 * We replicate this: extract each word in LE order (LSB first).
 * ------------------------------------------------------------------------- */
static void sha_process_block(struct mm_lpc55_hashcrypt *hc)
{
#ifdef M33MU_HAS_WOLFSSL
    mm_u8 block[64];
    mm_u32 i;
    wc_Sha256 *sha = (wc_Sha256 *)(void *)hc->sha_ctx.opaque;

    if (!hc->sha_inited || hc->inbuf_count < 16u) return;

    /* wc_Sha256Transform on a little-endian (x86) host expects the 64-byte
     * block in a specific byte layout.  Empirical testing shows it needs the
     * block words byte-reversed compared to the firmware LE words:
     *
     *   Firmware writes "abc\x80" as LE word 0x80636261.
     *   Transform needs word in memory as bytes [0x80, 0x63, 0x62, 0x61].
     *   uint32_t 0x80636261 in x86 memory = bytes [0x61, 0x62, 0x63, 0x80].
     *   So we must byte-reverse each word: 0x80636261 → stored as [0x80,0x63,0x62,0x61].
     *   Equivalently: new_word[i] = bswap32(inbuf[i]).
     *
     * This matches the test: Transform(block_le) with block_le[0..3]=[0x80,0x63,0x62,0x61]
     * gives SHA-256("abc") = ba7816bf... ✓ */
    for (i = 0u; i < 16u; ++i) {
        mm_u32 w = hc->inbuf[i];
        /* byte-swap: MSByte first in the byte array */
        block[i * 4u]      = (mm_u8)((w >> 24) & 0xffu);
        block[i * 4u + 1u] = (mm_u8)((w >> 16) & 0xffu);
        block[i * 4u + 2u] = (mm_u8)((w >>  8) & 0xffu);
        block[i * 4u + 3u] = (mm_u8)((w)       & 0xffu);
    }
    wc_Sha256Transform(sha, block);
    hc->inbuf_count = 0u;
#else
    hc->inbuf_count = 0u;
#endif
}

/* -------------------------------------------------------------------------
 * SHA-256 finalise and populate DIGEST0 registers.
 * After all blocks have been processed via sha_process_block(), extract
 * the running hash from the wc_Sha256 internal digest[] field.
 * ------------------------------------------------------------------------- */
static void sha_finalise(struct mm_lpc55_hashcrypt *hc)
{
    mm_u32 i;
#ifdef M33MU_HAS_WOLFSSL
    wc_Sha256 *sha = (wc_Sha256 *)(void *)hc->sha_ctx.opaque;
#endif

    if (!hc->sha_inited) {
        /* No wolfSSL or not started — zero digest, firmware won't hang */
        memset(hc->digest, 0, sizeof(hc->digest));
    } else {
        /* Flush any remaining partial block (shouldn't happen in correct
         * firmware that supplies full padded blocks, but be robust) */
        if (hc->inbuf_count > 0u) {
#ifdef M33MU_HAS_WOLFSSL
            /* Less than 16 words — pad to 16 and process */
            while (hc->inbuf_count < 16u) {
                hc->inbuf[hc->inbuf_count++] = 0u;
            }
            wc_Sha256Transform(sha, (const unsigned char *)hc->inbuf);
            hc->inbuf_count = 0u;
#endif
        }
#ifdef M33MU_HAS_WOLFSSL
        {
            /* Extract digest from wc_Sha256 internal state.
             * After wc_Sha256Transform, digest[] holds the running hash.
             * On x86 (LE host), each word is stored in native LE byte order.
             * digest[0] on x86 = 0xBA7816BF stored as bytes [BF, 16, 78, BA].
             * We want to output bytes [BA, 78, 16, BF] (big-endian / SHA spec order).
             * So we byte-reverse each word. */
            for (i = 0u; i < 8u; ++i) {
                mm_u32 d = sha->digest[i];
                hc->digest[i * 4u]      = (mm_u8)((d >> 24) & 0xffu);
                hc->digest[i * 4u + 1u] = (mm_u8)((d >> 16) & 0xffu);
                hc->digest[i * 4u + 2u] = (mm_u8)((d >> 8)  & 0xffu);
                hc->digest[i * 4u + 3u] = (mm_u8)((d)       & 0xffu);
            }
        }
#else
        memset(hc->digest, 0, sizeof(hc->digest));
#endif
        hc->sha_inited = MM_FALSE;
    }
    /* Populate DIGEST0[0..7] — hardware returns big-endian words */
    for (i = 0u; i < 8u; ++i) {
        hc->regs[(HC_OFF_DIGEST0 / 4u) + i] =
            ((mm_u32)hc->digest[i * 4u]      << 24) |
            ((mm_u32)hc->digest[i * 4u + 1u] << 16) |
            ((mm_u32)hc->digest[i * 4u + 2u] << 8)  |
            ((mm_u32)hc->digest[i * 4u + 3u]);
    }
    hc->digest_ready = MM_TRUE;
    hc->regs[HC_OFF_STATUS / 4u] &= ~STATUS_WAITING;
    hc->regs[HC_OFF_STATUS / 4u] |=  STATUS_DIGEST;
    hc_deliver_irq(hc, INTEN_DIGEST);
}

/* -------------------------------------------------------------------------
 * AES: run one 16-byte block on current key/mode
 * ------------------------------------------------------------------------- */
static void aes_process_block(struct mm_lpc55_hashcrypt *hc)
{
    mm_u8 key_bytes[32];
    mm_u8 iv_bytes[16];
    mm_u8 in_bytes[16];
    mm_u32 key_len;
    mm_u32 cryptcfg;
    mm_u32 aesmode;
    mm_bool decrypt;
    mm_bool ok;
    mm_u32 i;
    mm_u32 keysz;

    cryptcfg = hc->regs[HC_OFF_CRYPTCFG / 4u];
    keysz = (cryptcfg & CRYPTCFG_AESKEYSZ_MASK) >> CRYPTCFG_AESKEYSZ_SHIFT;
    switch (keysz) {
    case 1u:  key_len = 24u; break;
    case 2u:  key_len = 32u; break;
    default:  key_len = 16u; break;
    }
    aesmode = (cryptcfg & CRYPTCFG_AESMODE_MASK) >> CRYPTCFG_AESMODE_SHIFT;
    decrypt = (cryptcfg & CRYPTCFG_AESDECRYPT) != 0u;

    /* Build key and input bytes (LE words → bytes) */
    aes_build_key_bytes(hc->aes_key, key_len / 4u, key_bytes);
    aes_build_key_bytes(hc->inbuf, 4u, in_bytes);
    aes_build_key_bytes(hc->aes_iv, AES_IV_WORDS, iv_bytes);

    ok = MM_FALSE;
    switch (aesmode) {
    case 0u: /* ECB */
        if (decrypt)
            ok = mm_host_aes_ecb_dec(key_bytes, key_len, in_bytes, hc->aes_out, 16u);
        else
            ok = mm_host_aes_ecb_enc(key_bytes, key_len, in_bytes, hc->aes_out, 16u);
        break;
    case 1u: /* CBC */
        if (decrypt)
            ok = mm_host_aes_cbc_dec(key_bytes, key_len, iv_bytes, in_bytes, hc->aes_out, 16u);
        else
            ok = mm_host_aes_cbc_enc(key_bytes, key_len, iv_bytes, in_bytes, hc->aes_out, 16u);
        if (ok) {
            /* Update IV for chaining: for encrypt, IV = ciphertext; for decrypt, IV = input */
            const mm_u8 *new_iv = decrypt ? in_bytes : hc->aes_out;
            aes_build_key_bytes(hc->aes_iv, 4u, iv_bytes); /* unused */
            for (i = 0u; i < 4u; ++i) {
                hc->aes_iv[i] = ((mm_u32)new_iv[i * 4u]) |
                                 ((mm_u32)new_iv[i * 4u + 1u] << 8) |
                                 ((mm_u32)new_iv[i * 4u + 2u] << 16) |
                                 ((mm_u32)new_iv[i * 4u + 3u] << 24);
            }
        }
        break;
    case 2u: /* CTR */
        ok = mm_host_aes_ctr(key_bytes, key_len, iv_bytes, in_bytes, hc->aes_out, 16u);
        break;
    default:
        break;
    }

    if (!ok) {
        memset(hc->aes_out, 0, sizeof(hc->aes_out));
    }

    /* Populate DIGEST0[0..3] with output (same word order as input) */
    for (i = 0u; i < 4u; ++i) {
        hc->regs[(HC_OFF_DIGEST0 / 4u) + i] =
            ((mm_u32)hc->aes_out[i * 4u])       |
            ((mm_u32)hc->aes_out[i * 4u + 1u] << 8) |
            ((mm_u32)hc->aes_out[i * 4u + 2u] << 16) |
            ((mm_u32)hc->aes_out[i * 4u + 3u] << 24);
    }
    hc->aes_out_word = 0u;
    hc->aes_out_ready = MM_TRUE;
    hc->inbuf_count = 0u;

    /* Signal digest ready, accept more data */
    hc->regs[HC_OFF_STATUS / 4u] |= STATUS_DIGEST | STATUS_WAITING;
    hc_deliver_irq(hc, INTEN_DIGEST);
}

/* -------------------------------------------------------------------------
 * Core INDATA push (shared by INDATA and ALIAS writes)
 * ------------------------------------------------------------------------- */
static void hc_indata_push(struct mm_lpc55_hashcrypt *hc, mm_u32 value)
{
    if (hc->mode == CTRL_MODE_SHA256 || hc->mode == CTRL_MODE_SHA1) {
        /* Buffer words — SHA block = 16 words = 64 bytes */
        if (hc->inbuf_count < INBUF_WORDS_MAX) {
            hc->inbuf[hc->inbuf_count++] = value;
        }
        /* When a full 64-byte (16-word) block is accumulated, process it */
        if (hc->inbuf_count == 16u) {
            sha_process_block(hc);
            /* Remain WAITING for more data */
            hc->regs[HC_OFF_STATUS / 4u] |= STATUS_WAITING;
        }
        /* Clear DIGEST flag when new data arrives */
        hc->regs[HC_OFF_STATUS / 4u] &= ~STATUS_DIGEST;
        hc->digest_ready = MM_FALSE;

    } else if (hc->mode == CTRL_MODE_AES) {
        if (hc->aes_needs_key) {
            /* Collect key words */
            if (hc->aes_key_recvd < hc->aes_key_words) {
                hc->aes_key[hc->aes_key_recvd++] = value;
            }
            if (hc->aes_key_recvd >= hc->aes_key_words) {
                hc->aes_key_ready = MM_TRUE;
                hc->aes_needs_key = MM_FALSE;
                if (hc->aes_needs_iv) {
                    /* Now need IV */
                    hc->regs[HC_OFF_STATUS / 4u] =
                        (hc->regs[HC_OFF_STATUS / 4u] & ~STATUS_NEEDKEY) | STATUS_NEEDIV | STATUS_WAITING;
                } else {
                    hc->regs[HC_OFF_STATUS / 4u] =
                        (hc->regs[HC_OFF_STATUS / 4u] & ~(STATUS_NEEDKEY | STATUS_NEEDIV)) | STATUS_WAITING;
                }
            }
        } else if (hc->aes_needs_iv) {
            /* Collect IV words */
            if (hc->aes_iv_recvd < AES_IV_WORDS) {
                hc->aes_iv[hc->aes_iv_recvd++] = value;
            }
            if (hc->aes_iv_recvd >= AES_IV_WORDS) {
                hc->aes_iv_ready = MM_TRUE;
                hc->aes_needs_iv = MM_FALSE;
                hc->regs[HC_OFF_STATUS / 4u] =
                    (hc->regs[HC_OFF_STATUS / 4u] & ~(STATUS_NEEDKEY | STATUS_NEEDIV)) | STATUS_WAITING;
            }
        } else {
            /* Collect data block (4 words = 16 bytes) */
            if (hc->inbuf_count < 4u) {
                hc->inbuf[hc->inbuf_count++] = value;
            }
            if (hc->inbuf_count == 4u) {
                hc->regs[HC_OFF_STATUS / 4u] &= ~STATUS_WAITING;
                aes_process_block(hc);
            }
        }
    }
}

/* -------------------------------------------------------------------------
 * Handle CTRL write (NEW_HASH / mode change)
 * ------------------------------------------------------------------------- */
static void hc_ctrl_write(struct mm_lpc55_hashcrypt *hc, mm_u32 value)
{
    mm_u32 new_mode = value & CTRL_MODE_MASK;
    mm_u32 new_hash = value & CTRL_NEW_HASH;

    hc->regs[HC_OFF_CTRL / 4u] = value & ~CTRL_NEW_HASH; /* NEW_HASH self-clears */
    hc->mode = new_mode;

    if (new_hash) {
        /* Reset digest state */
        hc->digest_ready = MM_FALSE;
        hc->inbuf_count = 0u;
        hc->regs[HC_OFF_STATUS / 4u] &= ~(STATUS_DIGEST | STATUS_WAITING |
                                           STATUS_NEEDKEY | STATUS_NEEDIV);

        if (new_mode == CTRL_MODE_SHA256) {
            /* Initialise the wc_Sha256 state (sets IV).
             * We'll use wc_Sha256Transform for each 64-byte block. */
            hc->sha_inited = mm_host_sha256_stream_init(&hc->sha_ctx);
            hc->regs[HC_OFF_STATUS / 4u] |= STATUS_WAITING;

        } else if (new_mode == CTRL_MODE_AES) {
            mm_u32 cryptcfg = hc->regs[HC_OFF_CRYPTCFG / 4u];
            mm_u32 aesmode  = (cryptcfg & CRYPTCFG_AESMODE_MASK) >> CRYPTCFG_AESMODE_SHIFT;
            mm_u32 keysz    = (cryptcfg & CRYPTCFG_AESKEYSZ_MASK) >> CRYPTCFG_AESKEYSZ_SHIFT;

            /* Determine how many key words firmware must write */
            switch (keysz) {
            case 1u: hc->aes_key_words = 6u; break;  /* 192-bit */
            case 2u: hc->aes_key_words = 8u; break;  /* 256-bit */
            default: hc->aes_key_words = 4u; break;  /* 128-bit */
            }
            hc->aes_key_recvd = 0u;
            hc->aes_key_ready = MM_FALSE;
            hc->aes_iv_recvd  = 0u;
            hc->aes_iv_ready  = MM_FALSE;
            hc->aes_out_ready = MM_FALSE;
            hc->aes_out_word  = 0u;

            /* Need IV for CBC/CTR, not for ECB */
            hc->aes_needs_key = MM_TRUE;
            hc->aes_needs_iv  = (aesmode == 1u || aesmode == 2u) ? MM_TRUE : MM_FALSE;
            hc->regs[HC_OFF_STATUS / 4u] |= STATUS_WAITING | STATUS_NEEDKEY;
            if (hc->aes_needs_iv) {
                hc->regs[HC_OFF_STATUS / 4u] |= STATUS_NEEDIV;
            }

        } else if (new_mode == CTRL_MODE_SHA1) {
            /* SHA-1 not fully emulated — accept writes, return zero digest */
            hc->sha_inited = MM_FALSE;
            hc->regs[HC_OFF_STATUS / 4u] |= STATUS_WAITING;
        }
    }
}

/* -------------------------------------------------------------------------
 * Read callback
 * ------------------------------------------------------------------------- */
mm_bool mm_lpc55_hashcrypt_read(void *opaque, mm_u32 offset,
                                mm_u32 size_bytes, mm_u32 *value_out)
{
    struct mm_lpc55_hashcrypt *hc = (struct mm_lpc55_hashcrypt *)opaque;
    mm_u32 val;

    if (hc == NULL || value_out == NULL) return MM_FALSE;
    if (size_bytes == 0u || size_bytes > 4u) return MM_FALSE;
    if ((offset + size_bytes) > HC_SIZE) return MM_FALSE;

    /* DIGEST0[0..7] — first read triggers finalisation for SHA-256 */
    if (offset >= HC_OFF_DIGEST0 && offset <= HC_OFF_DIGEST7 &&
        size_bytes == 4u) {
        mm_u32 didx = (offset - HC_OFF_DIGEST0) / 4u;
        if (!hc->digest_ready && hc->mode == CTRL_MODE_SHA256) {
            sha_finalise(hc);
        }
        val = hc->regs[(HC_OFF_DIGEST0 / 4u) + didx];
        memcpy(value_out, &val, size_bytes);
        return MM_TRUE;
    }

    /* STATUS — computed on every read */
    if (offset == HC_OFF_STATUS) {
        val = hc->regs[HC_OFF_STATUS / 4u];
        memcpy(value_out, &val, size_bytes);
        return MM_TRUE;
    }

    /* CONFIG / INFO — capability register (read-only) */
    if (offset == HC_OFF_CONFIG) {
        val = HC_CONFIG_VAL;
        memcpy(value_out, &val, size_bytes);
        return MM_TRUE;
    }

    /* Default: register file */
    memcpy(value_out, (const mm_u8 *)hc->regs + offset, size_bytes);
    return MM_TRUE;
}

/* -------------------------------------------------------------------------
 * Write callback
 * ------------------------------------------------------------------------- */
mm_bool mm_lpc55_hashcrypt_write(void *opaque, mm_u32 offset,
                                 mm_u32 size_bytes, mm_u32 value)
{
    struct mm_lpc55_hashcrypt *hc = (struct mm_lpc55_hashcrypt *)opaque;

    if (hc == NULL) return MM_FALSE;
    if (size_bytes == 0u || size_bytes > 4u) return MM_FALSE;
    if ((offset + size_bytes) > HC_SIZE) return MM_FALSE;

    switch (offset) {
    case HC_OFF_CTRL:
        hc_ctrl_write(hc, value);
        break;

    case HC_OFF_STATUS:
        /* W1C: error and fault bits */
        hc->regs[HC_OFF_STATUS / 4u] &= ~(value & (STATUS_ERROR));
        break;

    case HC_OFF_INTENSET:
        hc->intenset |= value;
        hc->regs[HC_OFF_INTENSET / 4u] = hc->intenset;
        break;

    case HC_OFF_INTENCLR:
        hc->intenset &= ~value;
        hc->regs[HC_OFF_INTENSET / 4u] = hc->intenset;
        hc->regs[HC_OFF_INTENCLR / 4u] = 0u; /* write-only, reads as 0 */
        break;

    case HC_OFF_INDATA:
        hc_indata_push(hc, value);
        break;

    case HC_OFF_CONFIG:
        /* Read-only — silently ignore writes */
        break;

    default:
        /* ALIAS registers */
        if (offset >= HC_OFF_ALIAS_0 && offset <= HC_OFF_ALIAS_6 &&
            (offset & 3u) == 0u) {
            hc_indata_push(hc, value);
            break;
        }
        /* All other registers: plain store */
        if ((offset + size_bytes) <= HC_SIZE) {
            memcpy((mm_u8 *)hc->regs + offset, &value, size_bytes);
        }
        break;
    }

    return MM_TRUE;
}
