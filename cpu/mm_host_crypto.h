/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * mm_host_crypto: thin host-side crypto bridge used by peripheral models
 * (HashCrypt, OTFDEC, CC-312, ...).  Each function:
 *  - if wolfSSL is available: calls wc_* to produce real output.
 *  - if wolfSSL is absent:    emits a one-shot stderr warning and
 *    returns MM_FALSE so callers can fall back to dummy-success behaviour.
 */

#ifndef MM_HOST_CRYPTO_H
#define MM_HOST_CRYPTO_H

#include "m33mu/types.h"
#include <stddef.h>

/* -------------------------------------------------------------------------
 * AES (ECB, CBC, CTR)
 * key_len: 16, 24, or 32 bytes.
 * len must be a multiple of 16 for ECB/CBC.
 * ------------------------------------------------------------------------- */
mm_bool mm_host_aes_ecb_enc(const mm_u8 *key, size_t key_len,
                            const mm_u8 *in, mm_u8 *out, size_t len);
mm_bool mm_host_aes_ecb_dec(const mm_u8 *key, size_t key_len,
                            const mm_u8 *in, mm_u8 *out, size_t len);
mm_bool mm_host_aes_cbc_enc(const mm_u8 *key, size_t key_len,
                            const mm_u8 *iv, const mm_u8 *in,
                            mm_u8 *out, size_t len);
mm_bool mm_host_aes_cbc_dec(const mm_u8 *key, size_t key_len,
                            const mm_u8 *iv, const mm_u8 *in,
                            mm_u8 *out, size_t len);
mm_bool mm_host_aes_ctr(const mm_u8 *key, size_t key_len,
                        const mm_u8 *iv, const mm_u8 *in,
                        mm_u8 *out, size_t len);

/* -------------------------------------------------------------------------
 * SHA-1 / SHA-256 (one-shot)
 * ------------------------------------------------------------------------- */
mm_bool mm_host_sha1(const mm_u8 *in, size_t len, mm_u8 out[20]);
mm_bool mm_host_sha256(const mm_u8 *in, size_t len, mm_u8 out[32]);

/* -------------------------------------------------------------------------
 * Streaming SHA-256
 * The opaque[] field is large enough to hold wolfSSL's wc_Sha256 struct
 * (a compile-time assert in the .c file validates this).
 * ------------------------------------------------------------------------- */
struct mm_host_sha256_ctx {
    /* Must be 16-byte aligned: wolfSSL's wc_Sha256 uses SIMD loads/stores
     * that fault on misaligned memory.  _Alignof(wc_Sha256) == 16. */
    mm_u8 opaque[256] __attribute__((aligned(16)));
};

mm_bool mm_host_sha256_stream_init(struct mm_host_sha256_ctx *ctx);
mm_bool mm_host_sha256_stream_update(struct mm_host_sha256_ctx *ctx,
                                     const mm_u8 *in, size_t len);
mm_bool mm_host_sha256_stream_final(struct mm_host_sha256_ctx *ctx,
                                    mm_u8 out[32]);

/* -------------------------------------------------------------------------
 * RNG
 * ------------------------------------------------------------------------- */
mm_bool mm_host_rng_get(mm_u8 *out, size_t len);

#endif /* MM_HOST_CRYPTO_H */
