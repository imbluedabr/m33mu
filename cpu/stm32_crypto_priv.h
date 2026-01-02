#ifndef M33MU_STM32_CRYPTO_PRIV_H
#define M33MU_STM32_CRYPTO_PRIV_H

#include "m33mu/types.h"
#include "m33mu/pka.h"

#ifndef AES_SIZE
#define AES_SIZE 0x400u
#endif
#ifndef HASH_SIZE
#define HASH_SIZE 0x400u
#endif

struct rcc_state;
struct simple_blk;
struct hash_state;

#ifdef M33MU_HAS_WOLFSSL
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#endif

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
    mm_bool pending_clear;
    mm_bool saved_valid;
    mm_u32 saved_len;
};

void hash_reset_state(struct hash_state *h, mm_bool full_reset);

struct aes_state {
    mm_u32 regs[AES_SIZE / 4];
    mm_u32 key_words[8];
    mm_u32 key_written;
    mm_u32 iv_words[4];
    mm_u8 in_block[16];
    mm_u32 in_raw[4];
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
    mm_u64 gcm_aad_bits;
    mm_u64 gcm_payload_bits;
    mm_bool gcm_len_valid;
    mm_bool gcm_capture_ok;
    mm_bool gcm_use_icb;
    mm_bool gcm_ctr_inited;
    mm_u8 gcm_icb[16];
    mm_u8 gcm_iv[16];
    mm_bool gcm_inited;
    mm_bool ccm_inited;
    mm_u8 ccm_nonce[16];
    mm_u32 ccm_nonce_len;
    mm_u32 ccm_tag_len;
    mm_u8 ccm_ctr[16];
    mm_bool ccm_ctr_valid;
#ifdef M33MU_HAS_WOLFSSL
    Aes gcm_aes;
    Aes gcm_ctr_aes;
    Aes ccm_ctr_aes;
#endif
};

struct hash_ctx {
    struct hash_state *state;
    mm_bool secure_alias;
    struct rcc_state *rcc;
    struct simple_blk *tzsc;
    mm_bool (*clock_enabled)(const struct rcc_state *rcc);
    mm_bool (*requires_secure)(const struct simple_blk *tzsc);
};

struct aes_ctx {
    struct aes_state *state;
    mm_bool secure_alias;
    struct rcc_state *rcc;
    struct simple_blk *tzsc;
    mm_bool is_saes;
    mm_bool (*clock_enabled)(const struct rcc_state *rcc, mm_bool is_saes);
    mm_bool (*requires_secure)(const struct simple_blk *tzsc, mm_bool is_saes);
};

struct pka_ctx {
    struct pka_state *state;
    mm_bool secure_alias;
    struct rcc_state *rcc;
    struct simple_blk *tzsc;
    mm_bool (*clock_enabled)(const struct rcc_state *rcc);
    mm_bool (*requires_secure)(const struct simple_blk *tzsc);
};

#endif /* M33MU_STM32_CRYPTO_PRIV_H */
