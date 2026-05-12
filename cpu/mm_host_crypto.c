/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * mm_host_crypto: host-side crypto bridge implementation.
 * wolfSSL is used when M33MU_HAS_WOLFSSL is defined; otherwise every
 * function emits a single warning to stderr and returns MM_FALSE.
 */

#include <stddef.h>
#include <string.h>
#include <stdio.h>

#include "mm_host_crypto.h"

#ifdef M33MU_HAS_WOLFSSL
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* compile-time check: opaque[] must be large enough for wc_Sha256 */
typedef char mm_host_sha256_ctx_size_check
    [(sizeof(wc_Sha256) <= sizeof(((struct mm_host_sha256_ctx *)0)->opaque))
     ? 1 : -1];

#endif /* M33MU_HAS_WOLFSSL */

/* -------------------------------------------------------------------------
 * Internal one-shot warning helpers (one per family of operation)
 * ------------------------------------------------------------------------- */
#ifndef M33MU_HAS_WOLFSSL
static void warn_once_aes(void)
{
    static mm_bool warned = MM_FALSE;
    if (!warned) {
        warned = MM_TRUE;
        fprintf(stderr,
            "[mm_host_crypto] AES requested but wolfSSL not available;"
            " returning failure\n");
    }
}

static void warn_once_sha(void)
{
    static mm_bool warned = MM_FALSE;
    if (!warned) {
        warned = MM_TRUE;
        fprintf(stderr,
            "[mm_host_crypto] SHA requested but wolfSSL not available;"
            " returning failure\n");
    }
}

static void warn_once_rng(void)
{
    static mm_bool warned = MM_FALSE;
    if (!warned) {
        warned = MM_TRUE;
        fprintf(stderr,
            "[mm_host_crypto] RNG requested but wolfSSL not available;"
            " returning failure\n");
    }
}
#endif /* !M33MU_HAS_WOLFSSL */

/* -------------------------------------------------------------------------
 * AES-ECB encrypt
 * ------------------------------------------------------------------------- */
mm_bool mm_host_aes_ecb_enc(const mm_u8 *key, size_t key_len,
                            const mm_u8 *in, mm_u8 *out, size_t len)
{
#ifdef M33MU_HAS_WOLFSSL
    Aes aes;
    int ret;
    if (key == NULL || in == NULL || out == NULL || (len % 16u) != 0u)
        return MM_FALSE;
    ret = wc_AesSetKey(&aes, key, (word32)key_len, NULL, AES_ENCRYPTION);
    if (ret != 0) return MM_FALSE;
    ret = wc_AesEcbEncrypt(&aes, out, in, (word32)len);
    wc_AesFree(&aes);
    return (ret == 0) ? MM_TRUE : MM_FALSE;
#else
    (void)key; (void)key_len; (void)in; (void)out; (void)len;
    warn_once_aes();
    return MM_FALSE;
#endif
}

/* -------------------------------------------------------------------------
 * AES-ECB decrypt
 * ------------------------------------------------------------------------- */
mm_bool mm_host_aes_ecb_dec(const mm_u8 *key, size_t key_len,
                            const mm_u8 *in, mm_u8 *out, size_t len)
{
#ifdef M33MU_HAS_WOLFSSL
    Aes aes;
    int ret;
    if (key == NULL || in == NULL || out == NULL || (len % 16u) != 0u)
        return MM_FALSE;
    ret = wc_AesSetKey(&aes, key, (word32)key_len, NULL, AES_DECRYPTION);
    if (ret != 0) return MM_FALSE;
    ret = wc_AesEcbDecrypt(&aes, out, in, (word32)len);
    wc_AesFree(&aes);
    return (ret == 0) ? MM_TRUE : MM_FALSE;
#else
    (void)key; (void)key_len; (void)in; (void)out; (void)len;
    warn_once_aes();
    return MM_FALSE;
#endif
}

/* -------------------------------------------------------------------------
 * AES-CBC encrypt
 * ------------------------------------------------------------------------- */
mm_bool mm_host_aes_cbc_enc(const mm_u8 *key, size_t key_len,
                            const mm_u8 *iv, const mm_u8 *in,
                            mm_u8 *out, size_t len)
{
#ifdef M33MU_HAS_WOLFSSL
    Aes aes;
    int ret;
    if (key == NULL || iv == NULL || in == NULL || out == NULL
            || (len % 16u) != 0u)
        return MM_FALSE;
    ret = wc_AesSetKey(&aes, key, (word32)key_len, iv, AES_ENCRYPTION);
    if (ret != 0) return MM_FALSE;
    ret = wc_AesCbcEncrypt(&aes, out, in, (word32)len);
    wc_AesFree(&aes);
    return (ret == 0) ? MM_TRUE : MM_FALSE;
#else
    (void)key; (void)key_len; (void)iv; (void)in; (void)out; (void)len;
    warn_once_aes();
    return MM_FALSE;
#endif
}

/* -------------------------------------------------------------------------
 * AES-CBC decrypt
 * ------------------------------------------------------------------------- */
mm_bool mm_host_aes_cbc_dec(const mm_u8 *key, size_t key_len,
                            const mm_u8 *iv, const mm_u8 *in,
                            mm_u8 *out, size_t len)
{
#ifdef M33MU_HAS_WOLFSSL
    Aes aes;
    int ret;
    if (key == NULL || iv == NULL || in == NULL || out == NULL
            || (len % 16u) != 0u)
        return MM_FALSE;
    ret = wc_AesSetKey(&aes, key, (word32)key_len, iv, AES_DECRYPTION);
    if (ret != 0) return MM_FALSE;
    ret = wc_AesCbcDecrypt(&aes, out, in, (word32)len);
    wc_AesFree(&aes);
    return (ret == 0) ? MM_TRUE : MM_FALSE;
#else
    (void)key; (void)key_len; (void)iv; (void)in; (void)out; (void)len;
    warn_once_aes();
    return MM_FALSE;
#endif
}

/* -------------------------------------------------------------------------
 * AES-CTR
 * ------------------------------------------------------------------------- */
mm_bool mm_host_aes_ctr(const mm_u8 *key, size_t key_len,
                        const mm_u8 *iv, const mm_u8 *in,
                        mm_u8 *out, size_t len)
{
#ifdef M33MU_HAS_WOLFSSL
    Aes aes;
    int ret;
    if (key == NULL || iv == NULL || in == NULL || out == NULL)
        return MM_FALSE;
    ret = wc_AesSetKey(&aes, key, (word32)key_len, iv, AES_ENCRYPTION);
    if (ret != 0) return MM_FALSE;
    ret = wc_AesCtrEncrypt(&aes, out, in, (word32)len);
    wc_AesFree(&aes);
    return (ret == 0) ? MM_TRUE : MM_FALSE;
#else
    (void)key; (void)key_len; (void)iv; (void)in; (void)out; (void)len;
    warn_once_aes();
    return MM_FALSE;
#endif
}

/* -------------------------------------------------------------------------
 * SHA-1 (one-shot)
 * ------------------------------------------------------------------------- */
mm_bool mm_host_sha1(const mm_u8 *in, size_t len, mm_u8 out[20])
{
#ifdef M33MU_HAS_WOLFSSL
    wc_Sha sha;
    int ret;
    if (in == NULL || out == NULL) return MM_FALSE;
    ret = wc_InitSha(&sha);
    if (ret != 0) return MM_FALSE;
    ret = wc_ShaUpdate(&sha, in, (word32)len);
    if (ret != 0) return MM_FALSE;
    ret = wc_ShaFinal(&sha, out);
    return (ret == 0) ? MM_TRUE : MM_FALSE;
#else
    (void)in; (void)len; (void)out;
    warn_once_sha();
    return MM_FALSE;
#endif
}

/* -------------------------------------------------------------------------
 * SHA-256 (one-shot)
 * ------------------------------------------------------------------------- */
mm_bool mm_host_sha256(const mm_u8 *in, size_t len, mm_u8 out[32])
{
#ifdef M33MU_HAS_WOLFSSL
    wc_Sha256 sha;
    int ret;
    if (in == NULL || out == NULL) return MM_FALSE;
    ret = wc_InitSha256(&sha);
    if (ret != 0) return MM_FALSE;
    ret = wc_Sha256Update(&sha, in, (word32)len);
    if (ret != 0) return MM_FALSE;
    ret = wc_Sha256Final(&sha, out);
    return (ret == 0) ? MM_TRUE : MM_FALSE;
#else
    (void)in; (void)len; (void)out;
    warn_once_sha();
    return MM_FALSE;
#endif
}

/* -------------------------------------------------------------------------
 * Streaming SHA-256 — init
 * ------------------------------------------------------------------------- */
mm_bool mm_host_sha256_stream_init(struct mm_host_sha256_ctx *ctx)
{
#ifdef M33MU_HAS_WOLFSSL
    wc_Sha256 *sha = (wc_Sha256 *)(void *)ctx->opaque;
    int ret;
    if (ctx == NULL) return MM_FALSE;
    memset(ctx->opaque, 0, sizeof(ctx->opaque));
    ret = wc_InitSha256(sha);
    return (ret == 0) ? MM_TRUE : MM_FALSE;
#else
    (void)ctx;
    warn_once_sha();
    return MM_FALSE;
#endif
}

/* -------------------------------------------------------------------------
 * Streaming SHA-256 — update
 * ------------------------------------------------------------------------- */
mm_bool mm_host_sha256_stream_update(struct mm_host_sha256_ctx *ctx,
                                     const mm_u8 *in, size_t len)
{
#ifdef M33MU_HAS_WOLFSSL
    wc_Sha256 *sha = (wc_Sha256 *)(void *)ctx->opaque;
    int ret;
    if (ctx == NULL || in == NULL) return MM_FALSE;
    ret = wc_Sha256Update(sha, in, (word32)len);
    return (ret == 0) ? MM_TRUE : MM_FALSE;
#else
    (void)ctx; (void)in; (void)len;
    warn_once_sha();
    return MM_FALSE;
#endif
}

/* -------------------------------------------------------------------------
 * Streaming SHA-256 — final
 * ------------------------------------------------------------------------- */
mm_bool mm_host_sha256_stream_final(struct mm_host_sha256_ctx *ctx,
                                    mm_u8 out[32])
{
#ifdef M33MU_HAS_WOLFSSL
    wc_Sha256 *sha = (wc_Sha256 *)(void *)ctx->opaque;
    int ret;
    if (ctx == NULL || out == NULL) return MM_FALSE;
    ret = wc_Sha256Final(sha, out);
    return (ret == 0) ? MM_TRUE : MM_FALSE;
#else
    (void)ctx; (void)out;
    warn_once_sha();
    return MM_FALSE;
#endif
}

/* -------------------------------------------------------------------------
 * RNG
 * ------------------------------------------------------------------------- */
mm_bool mm_host_rng_get(mm_u8 *out, size_t len)
{
#ifdef M33MU_HAS_WOLFSSL
    WC_RNG rng;
    int ret;
    if (out == NULL) return MM_FALSE;
    ret = wc_InitRng(&rng);
    if (ret != 0) return MM_FALSE;
    ret = wc_RNG_GenerateBlock(&rng, out, (word32)len);
    wc_FreeRng(&rng);
    return (ret == 0) ? MM_TRUE : MM_FALSE;
#else
    (void)out; (void)len;
    warn_once_rng();
    return MM_FALSE;
#endif
}
