/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * LPC55S69 HashCrypt peripheral model.
 * Implements SHA-256 (streaming) and AES-ECB/CBC/CTR via the mm_host_crypto
 * bridge.  Register layout per LPC55S69 User Manual chapter 48.
 */

#ifndef LPC55S69_HASHCRYPT_H
#define LPC55S69_HASHCRYPT_H

#include <stddef.h>
#include "m33mu/types.h"
#include "../mm_host_crypto.h"

struct mmio_bus;
struct mm_nvic;

/* -------------------------------------------------------------------------
 * Internal constants (duplicated here so mmio.c can size the struct inline)
 * ------------------------------------------------------------------------- */
#define HC_SIZE             0xE0u
#define AES_MAX_KEY_WORDS   8u
#define AES_IV_WORDS        4u
#define INBUF_WORDS_MAX     16u

/*
 * HashCrypt peripheral state.
 * Defined here (not just forward-declared) so that lpc55s69_mmio.c can
 * embed the struct as a static variable without heap allocation.
 */
struct mm_lpc55_hashcrypt {
    /* Raw register file backing store */
    mm_u32 regs[HC_SIZE / 4u];

    /* NVIC pointer for IRQ delivery */
    struct mm_nvic *nvic;

    /* Current operational mode */
    mm_u32 mode;       /* 0 disabled, 1 SHA1, 2 SHA256, 4 AES */

    /* SHA-256 streaming context */
    struct mm_host_sha256_ctx sha_ctx;
    mm_bool sha_inited;

    /* Accumulated input words (before committing to SHA / AES) */
    mm_u32 inbuf[INBUF_WORDS_MAX];
    mm_u32 inbuf_count;  /* words accumulated so far in current block */

    /* AES key / IV (word arrays, little-endian from firmware writes) */
    mm_u32 aes_key[AES_MAX_KEY_WORDS];
    mm_u32 aes_key_words;  /* number of words expected */
    mm_u32 aes_key_recvd;  /* number received */
    mm_bool aes_key_ready;

    mm_u32 aes_iv[AES_IV_WORDS];
    mm_u32 aes_iv_recvd;
    mm_bool aes_iv_ready;

    /* AES output staging — one 16-byte block */
    mm_u8  aes_out[16];
    mm_u32 aes_out_word;   /* next word index to return on DIGEST reads */
    mm_bool aes_out_ready;

    /* Phase tracking for AES initialisation sequence */
    mm_bool aes_needs_key;
    mm_bool aes_needs_iv;

    /* Interrupt enable shadow (mirrors INTENSET register) */
    mm_u32 intenset;

    /* Digest buffer (SHA-256: 32 bytes = 8 words) */
    mm_u8  digest[32];
    mm_bool digest_ready;
};

/* Initialise and reset the peripheral state. */
mm_bool mm_lpc55_hashcrypt_init(struct mm_lpc55_hashcrypt *hc,
                                struct mm_nvic *nvic);
mm_bool mm_lpc55_hashcrypt_reset(struct mm_lpc55_hashcrypt *hc);

/* MMIO callbacks registered by lpc55s69_mmio. */
mm_bool mm_lpc55_hashcrypt_read(void *opaque, mm_u32 offset,
                                mm_u32 size_bytes, mm_u32 *value_out);
mm_bool mm_lpc55_hashcrypt_write(void *opaque, mm_u32 offset,
                                 mm_u32 size_bytes, mm_u32 value);

#endif /* LPC55S69_HASHCRYPT_H */
