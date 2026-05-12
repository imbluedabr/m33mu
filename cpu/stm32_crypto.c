#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "m33mu/types.h"
#include "stm32_crypto.h"
#include "stm32_crypto_priv.h"

/* Shared STM32H5/L5/U5 AES/HASH emulation */

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
#define AES_CR_KEYPROT  (1u << 19)
#define AES_CR_GCMPH_SHIFT 13u
#define AES_CR_NPBLB_SHIFT 20u
#define AES_CR_KEYSEL_SHIFT 28u
#define AES_CR_KEYSEL_MASK (0x7u << AES_CR_KEYSEL_SHIFT)
#define AES_CR_IPRST    (1u << 31)

#define AES_SR_CCF      (1u << 0)
#define AES_SR_WRERR    (1u << 2)
#define AES_SR_BUSY     (1u << 3)
#define AES_SR_KEYVALID (1u << 7)

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

#define SAES_KEYSEL_SOFTWARE 0x0u
#define SAES_KEYSEL_DHUK     0x1u
#define SAES_KEYSEL_SBK      0x2u
#define SAES_KEYSEL_DHUK_XOR_SBK 0x4u

struct saes_key_config {
    mm_bool puf_seed_set;
    mm_u64 puf_seed;
    mm_u8 sbkload_key[32];
    mm_u32 sbkload_key_len;
};

static struct saes_key_config g_saes_key_config;

static mm_u32 aes_key_len_from_cr(mm_u32 cr)
{
    return (cr & AES_CR_KEYSIZE) ? 32u : 16u;
}

#ifndef M33MU_HAS_WOLFSSL
static mm_u64 saes_splitmix64_next(mm_u64 *state)
{
    mm_u64 z;
    *state += 0x9e3779b97f4a7c15ull;
    z = *state;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31);
}
#endif

static void saes_hash32(mm_u8 out[32], const mm_u8 *data, mm_u32 len,
                        const char *label)
{
#ifdef M33MU_HAS_WOLFSSL
    wc_Sha256 sha;
    wc_InitSha256(&sha);
    if (label != NULL) {
        wc_Sha256Update(&sha, (const mm_u8 *)label, (word32)strlen(label));
    }
    if (data != NULL && len != 0u) {
        wc_Sha256Update(&sha, data, (word32)len);
    }
    wc_Sha256Final(&sha, out);
#else
    mm_u64 state = 0x243f6a8885a308d3ull;
    mm_u32 i;
    if (label != NULL) {
        const unsigned char *p = (const unsigned char *)label;
        while (*p != '\0') {
            state ^= (mm_u64)(*p++);
            state = saes_splitmix64_next(&state);
        }
    }
    for (i = 0u; i < len; ++i) {
        state ^= (mm_u64)data[i] << ((i & 7u) * 8u);
        state = saes_splitmix64_next(&state);
    }
    for (i = 0u; i < 4u; ++i) {
        mm_u64 v = saes_splitmix64_next(&state);
        out[i * 8u] = (mm_u8)(v >> 56);
        out[i * 8u + 1u] = (mm_u8)(v >> 48);
        out[i * 8u + 2u] = (mm_u8)(v >> 40);
        out[i * 8u + 3u] = (mm_u8)(v >> 32);
        out[i * 8u + 4u] = (mm_u8)(v >> 24);
        out[i * 8u + 5u] = (mm_u8)(v >> 16);
        out[i * 8u + 6u] = (mm_u8)(v >> 8);
        out[i * 8u + 7u] = (mm_u8)v;
    }
#endif
}

static void saes_derive_huk(mm_u8 out[32])
{
    mm_u8 seed_buf[8];
    mm_u32 i;
    for (i = 0u; i < 8u; ++i) {
        seed_buf[i] = (mm_u8)((g_saes_key_config.puf_seed >> (56u - (i * 8u))) & 0xffu);
    }
    saes_hash32(out, seed_buf, sizeof(seed_buf), "m33mu:stm32:saes:huk:v1");
}

static void saes_derive_dhuk(mm_u8 out[32])
{
    mm_u8 buf[64];
    mm_u8 huk[32];
    static const char dhuk_ctx[] = "m33mu:stm32:saes:dhuk:v1";
    saes_derive_huk(huk);
    memcpy(buf, huk, sizeof(huk));
    memcpy(buf + sizeof(huk), dhuk_ctx, sizeof(dhuk_ctx) - 1u);
    saes_hash32(out, buf, sizeof(huk) + (sizeof(dhuk_ctx) - 1u), NULL);
}

static void saes_expand_sbk(mm_u8 out[32])
{
    if (g_saes_key_config.sbkload_key_len == 32u) {
        memcpy(out, g_saes_key_config.sbkload_key, 32u);
        return;
    }
    saes_hash32(out, g_saes_key_config.sbkload_key,
                g_saes_key_config.sbkload_key_len,
                "m33mu:stm32:saes:sbkload:v1");
}

static void aes_sync_key_bytes_from_words(struct aes_state *a, mm_u32 key_len)
{
    mm_u32 i;
    mm_u32 words = key_len / 4u;
    a->key_len_bytes = key_len;
    memset(a->key_bytes, 0, sizeof(a->key_bytes));
    for (i = 0u; i < words; ++i) {
        mm_u32 w = a->key_words[words - 1u - i];
        a->key_bytes[i * 4u] = (mm_u8)((w >> 24) & 0xffu);
        a->key_bytes[i * 4u + 1u] = (mm_u8)((w >> 16) & 0xffu);
        a->key_bytes[i * 4u + 2u] = (mm_u8)((w >> 8) & 0xffu);
        a->key_bytes[i * 4u + 3u] = (mm_u8)(w & 0xffu);
    }
}

static void aes_update_software_key_valid(struct aes_state *a, mm_u32 key_len)
{
    mm_u32 words = key_len / 4u;
    mm_u32 mask = (words >= 8u) ? 0xFFu : ((1u << words) - 1u);
    a->key_valid = ((a->key_written & mask) == mask) ? MM_TRUE : MM_FALSE;
    if (a->key_valid) {
        aes_sync_key_bytes_from_words(a, key_len);
    } else {
        a->key_len_bytes = 0u;
        memset(a->key_bytes, 0, sizeof(a->key_bytes));
    }
}

static mm_bool saes_key_is_hidden(mm_u8 keysel)
{
    return keysel != SAES_KEYSEL_SOFTWARE;
}

static void saes_refresh_selected_key(struct aes_ctx *ctx, struct aes_state *a)
{
    mm_u32 key_len = aes_key_len_from_cr(a->regs[AES_CR / 4u]);
    mm_u8 dhuk[32];
    mm_u8 sbk[32];
    memset(a->key_bytes, 0, sizeof(a->key_bytes));
    a->key_len_bytes = key_len;
    a->saes_hidden_key = saes_key_is_hidden(a->saes_keysel);
    if (!a->saes_hidden_key) {
        aes_update_software_key_valid(a, key_len);
        if (a->key_valid && a->saes_keyprot) {
            a->saes_key_owner_secure = ctx->secure_alias;
        }
        return;
    }
    a->key_valid = MM_FALSE;
    switch (a->saes_keysel) {
    case SAES_KEYSEL_DHUK:
        if (!g_saes_key_config.puf_seed_set) return;
        saes_derive_dhuk(dhuk);
        memcpy(a->key_bytes, dhuk, key_len);
        a->key_valid = MM_TRUE;
        break;
    case SAES_KEYSEL_SBK:
        if (g_saes_key_config.sbkload_key_len == 0u) return;
        saes_expand_sbk(sbk);
        memcpy(a->key_bytes, sbk, key_len);
        a->key_valid = MM_TRUE;
        break;
    case SAES_KEYSEL_DHUK_XOR_SBK:
        if (!g_saes_key_config.puf_seed_set ||
            g_saes_key_config.sbkload_key_len == 0u) return;
        saes_derive_dhuk(dhuk);
        saes_expand_sbk(sbk);
        {
            mm_u32 i;
            for (i = 0u; i < key_len; ++i) {
                a->key_bytes[i] = dhuk[i] ^ sbk[i];
            }
        }
        a->key_valid = MM_TRUE;
        break;
    default:
        return;
    }
    if (a->key_valid && a->saes_keyprot) {
        a->saes_key_owner_secure = ctx->secure_alias;
    }
}

static mm_bool saes_access_denied(const struct aes_ctx *ctx, const struct aes_state *a)
{
    if (!ctx->is_saes || !a->saes_keyprot || !a->key_valid) {
        return MM_FALSE;
    }
    return (ctx->secure_alias != a->saes_key_owner_secure) ? MM_TRUE : MM_FALSE;
}

void mm_stm32_saes_set_key_material(mm_bool puf_seed_set, mm_u64 puf_seed,
                                    const mm_u8 *sbkload_key,
                                    mm_u32 sbkload_key_len)
{
    memset(&g_saes_key_config, 0, sizeof(g_saes_key_config));
    g_saes_key_config.puf_seed_set = puf_seed_set;
    g_saes_key_config.puf_seed = puf_seed;
    if (sbkload_key != NULL && sbkload_key_len <= sizeof(g_saes_key_config.sbkload_key)) {
        memcpy(g_saes_key_config.sbkload_key, sbkload_key, sbkload_key_len);
        g_saes_key_config.sbkload_key_len = sbkload_key_len;
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

#ifdef M33MU_HAS_WOLFSSL
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
#endif

static void aes_reset_auth_state(struct aes_state *a)
{
    a->aad_len = 0u;
    a->payload_len = 0u;
    a->tag_ready = MM_FALSE;
    a->gcm_inited = MM_FALSE;
    a->gcm_use_icb = MM_FALSE;
    a->gcm_ctr_inited = MM_FALSE;
    a->ccm_inited = MM_FALSE;
    a->ccm_ctr_valid = MM_FALSE;
    a->gcm_aad_bits = 0u;
    a->gcm_payload_bits = 0u;
    a->gcm_len_valid = MM_FALSE;
    a->gcm_capture_ok = MM_TRUE;
}

#ifdef M33MU_HAS_WOLFSSL
static void aes_build_iv_rev(const struct aes_state *a, mm_u8 *iv_out)
{
    mm_u32 i;
    for (i = 0u; i < 4u; ++i) {
        mm_u32 w = a->iv_words[3u - i];
        iv_out[i * 4u] = (mm_u8)((w >> 24) & 0xffu);
        iv_out[i * 4u + 1u] = (mm_u8)((w >> 16) & 0xffu);
        iv_out[i * 4u + 2u] = (mm_u8)((w >> 8) & 0xffu);
        iv_out[i * 4u + 3u] = (mm_u8)(w & 0xffu);
    }
}

static void aes_gcm_shift_right(mm_u8 *block)
{
    int i;
    mm_u8 carry = 0u;
    for (i = 0; i < 16; ++i) {
        mm_u8 next_carry = (mm_u8)(block[i] & 1u);
        block[i] = (mm_u8)((block[i] >> 1) | (carry << 7));
        carry = next_carry;
    }
}

static void aes_gcm_mul(mm_u8 *x, const mm_u8 *y)
{
    mm_u8 z[16] = {0};
    mm_u8 v[16];
    mm_u32 bit;
    memcpy(v, y, sizeof(v));
    for (bit = 0u; bit < 128u; ++bit) {
        mm_u32 byte_idx = bit / 8u;
        mm_u32 bit_idx = 7u - (bit % 8u);
        mm_u8 lsb;
        if (((x[byte_idx] >> bit_idx) & 1u) != 0u) {
            mm_u32 i;
            for (i = 0u; i < 16u; ++i) {
                z[i] ^= v[i];
            }
        }
        lsb = (mm_u8)(v[15] & 1u);
        aes_gcm_shift_right(v);
        if (lsb != 0u) {
            v[0] ^= 0xe1u;
        }
    }
    memcpy(x, z, sizeof(z));
}

static void aes_gcm_ghash_update(mm_u8 *state, const mm_u8 *h,
                                 const mm_u8 *data, mm_u32 len)
{
    while (len >= 16u) {
        mm_u32 i;
        for (i = 0u; i < 16u; ++i) {
            state[i] ^= data[i];
        }
        aes_gcm_mul(state, h);
        data += 16u;
        len -= 16u;
    }
    if (len > 0u) {
        mm_u8 tail[16] = {0};
        mm_u32 i;
        memcpy(tail, data, len);
        for (i = 0u; i < 16u; ++i) {
            state[i] ^= tail[i];
        }
        aes_gcm_mul(state, h);
    }
}

static void aes_gcm_ghash(Aes *aes, const mm_u8 *aad, mm_u32 aad_len,
                          const mm_u8 *payload, mm_u32 payload_len,
                          mm_u8 *tag_out)
{
    mm_u8 h[16];
    mm_u8 zero[16] = {0};
    mm_u8 lens[16] = {0};
    mm_u64 aad_bits = (mm_u64)aad_len * 8u;
    mm_u64 payload_bits = (mm_u64)payload_len * 8u;
    int i;
    (void)wc_AesEcbEncrypt(aes, h, zero, 16u);
    memset(tag_out, 0, 16u);
    aes_gcm_ghash_update(tag_out, h, aad, aad_len);
    aes_gcm_ghash_update(tag_out, h, payload, payload_len);
    for (i = 0; i < 8; ++i) {
        lens[7 - i] = (mm_u8)((aad_bits >> (i * 8)) & 0xffu);
        lens[15 - i] = (mm_u8)((payload_bits >> (i * 8)) & 0xffu);
    }
    aes_gcm_ghash_update(tag_out, h, lens, sizeof(lens));
}
#endif

#ifdef M33MU_HAS_WOLFSSL
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
#endif

void hash_reset_state(struct hash_state *h, mm_bool full_reset)
{
    if (full_reset) {
        h->msg_len = 0u;
        h->pending_clear = MM_FALSE;
        h->saved_valid = MM_FALSE;
        h->saved_len = 0u;
    }
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
    dst[0] = (mm_u8)((word >> 24) & 0xffu);
    dst[1] = (mm_u8)((word >> 16) & 0xffu);
    dst[2] = (mm_u8)((word >> 8) & 0xffu);
    dst[3] = (mm_u8)(word & 0xffu);
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
    h->digest_len = 0u;
#ifdef M33MU_HAS_WOLFSSL
    {
        mm_u32 nblw = h->nblw & HASH_STR_NBLW_MASK;
        const mm_u8 *data = h->msg;
        mm_u32 len = h->msg_len;
        mm_u8 last_buf[4];
        mm_u32 last_len = 0u;
        if (nblw != 0u && len > 0u) {
            mm_u32 valid_bits = nblw;
            mm_u32 valid_bytes = (valid_bits + 7u) / 8u;
            mm_u32 bytes_before = (len >= 4u) ? (len - 4u) : 0u;
            mm_u32 rem_bits = valid_bits % 8u;
            memcpy(last_buf, h->msg + bytes_before, 4u);
            if (valid_bytes < 4u) {
                memset(last_buf + valid_bytes, 0, 4u - valid_bytes);
            }
            if (rem_bits != 0u && valid_bytes > 0u) {
                mm_u8 mask = (mm_u8)((1u << rem_bits) - 1u);
                last_buf[valid_bytes - 1u] &= mask;
            }
            data = h->msg;
            len = bytes_before;
            last_len = valid_bytes;
        }
        switch (algo) {
        case 0x0u: {
            wc_Sha sha;
            wc_InitSha(&sha);
            wc_ShaUpdate(&sha, data, len);
            if (last_len != 0u) wc_ShaUpdate(&sha, last_buf, last_len);
            wc_ShaFinal(&sha, h->digest);
            h->digest_len = 20u;
            break;
        }
        case 0x2u: {
            wc_Sha224 sha;
            wc_InitSha224(&sha);
            wc_Sha224Update(&sha, data, len);
            if (last_len != 0u) wc_Sha224Update(&sha, last_buf, last_len);
            wc_Sha224Final(&sha, h->digest);
            h->digest_len = 28u;
            break;
        }
        case 0x3u: {
            wc_Sha256 sha;
            wc_InitSha256(&sha);
            wc_Sha256Update(&sha, data, len);
            if (last_len != 0u) wc_Sha256Update(&sha, last_buf, last_len);
            wc_Sha256Final(&sha, h->digest);
            h->digest_len = 32u;
            break;
        }
        case 0xCu: {
            wc_Sha384 sha;
            wc_InitSha384(&sha);
            wc_Sha384Update(&sha, data, len);
            if (last_len != 0u) wc_Sha384Update(&sha, last_buf, last_len);
            wc_Sha384Final(&sha, h->digest);
            h->digest_len = 48u;
            break;
        }
        case 0xDu: {
            wc_Sha512_224 sha;
            wc_InitSha512_224(&sha);
            wc_Sha512_224Update(&sha, data, len);
            if (last_len != 0u) wc_Sha512_224Update(&sha, last_buf, last_len);
            wc_Sha512_224Final(&sha, h->digest);
            h->digest_len = 28u;
            break;
        }
        case 0xEu: {
            wc_Sha512_256 sha;
            wc_InitSha512_256(&sha);
            wc_Sha512_256Update(&sha, data, len);
            if (last_len != 0u) wc_Sha512_256Update(&sha, last_buf, last_len);
            wc_Sha512_256Final(&sha, h->digest);
            h->digest_len = 32u;
            break;
        }
        case 0xFu: {
            wc_Sha512 sha;
            wc_InitSha512(&sha);
            wc_Sha512Update(&sha, data, len);
            if (last_len != 0u) wc_Sha512Update(&sha, last_buf, last_len);
            wc_Sha512Final(&sha, h->digest);
            h->digest_len = 64u;
            break;
        }
        default:
            break;
        }
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

mm_bool hash_read(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 *value_out)
{
    struct hash_ctx *ctx = (struct hash_ctx *)opaque;
    struct hash_state *h = ctx->state;
    if (value_out == 0 || size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if ((offset + size_bytes) > HASH_SIZE) return MM_FALSE;
    if (ctx->clock_enabled == NULL || !ctx->clock_enabled(ctx->rcc)) {
        *value_out = 0u;
        return MM_TRUE;
    }
    if (!ctx->secure_alias &&
        ctx->requires_secure != NULL &&
        ctx->requires_secure(ctx->tzsc)) {
        *value_out = 0u;
        return MM_TRUE;
    }
    if (offset == HASH_SR) {
        mm_u32 sr = hash_status_word(h);
        memcpy(value_out, &sr, size_bytes);
        return MM_TRUE;
    }
    if (offset >= HASH_CSR0) {
        h->saved_len = h->msg_len;
        h->saved_valid = MM_TRUE;
    }
    memcpy(value_out, (mm_u8 *)h->regs + offset, size_bytes);
    return MM_TRUE;
}


mm_bool hash_write(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 value)
{
    struct hash_ctx *ctx = (struct hash_ctx *)opaque;
    struct hash_state *h = ctx->state;
    mm_u32 datatype;
    mm_u32 algo;
    if (size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if ((offset + size_bytes) > HASH_SIZE) return MM_FALSE;
    if (ctx->clock_enabled == NULL || !ctx->clock_enabled(ctx->rcc)) {
        return MM_TRUE;
    }
    if (!ctx->secure_alias &&
        ctx->requires_secure != NULL &&
        ctx->requires_secure(ctx->tzsc)) {
        return MM_TRUE;
    }
    if (offset == HASH_CR) {
        datatype = (value >> HASH_CR_DATATYPE_SHIFT) & 0x3u;
        algo = (value >> HASH_CR_ALGO_SHIFT) & 0xFu;
        h->regs[HASH_CR / 4u] = value & ~(HASH_CR_INIT);
        if ((value & HASH_CR_INIT) != 0u) {
            h->pending_clear = MM_TRUE;
            hash_reset_state(h, MM_FALSE);
            h->regs[HASH_CR / 4u] = value & ~(HASH_CR_INIT);
            h->regs[HASH_CR / 4u] = (h->regs[HASH_CR / 4u] & ~(0xFu << HASH_CR_ALGO_SHIFT)) |
                                    ((algo & 0xFu) << HASH_CR_ALGO_SHIFT);
        }
        h->regs[HASH_CR / 4u] = (h->regs[HASH_CR / 4u] & ~(0x3u << HASH_CR_DATATYPE_SHIFT)) |
                                ((datatype & 0x3u) << HASH_CR_DATATYPE_SHIFT);
        return MM_TRUE;
    }
    if (offset == HASH_DIN) {
        if (h->pending_clear) {
            h->msg_len = 0u;
            h->pending_clear = MM_FALSE;
            h->saved_valid = MM_FALSE;
            h->saved_len = 0u;
        }
        datatype = (h->regs[HASH_CR / 4u] >> HASH_CR_DATATYPE_SHIFT) & 0x3u;
        hash_append_word(h, value, datatype);
        return MM_TRUE;
    }
    if (offset == HASH_STR) {
        h->regs[HASH_STR / 4u] = value;
        h->nblw = value & HASH_STR_NBLW_MASK;
        if ((value & HASH_STR_DCAL) != 0u) {
            if (h->pending_clear) {
                h->msg_len = 0u;
                h->pending_clear = MM_FALSE;
                h->saved_valid = MM_FALSE;
                h->saved_len = 0u;
            }
            algo = (h->regs[HASH_CR / 4u] >> HASH_CR_ALGO_SHIFT) & 0xFu;
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
        if (offset >= HASH_CSR0 && h->pending_clear) {
            h->pending_clear = MM_FALSE;
            if (h->saved_valid) {
                h->msg_len = h->saved_len;
            }
        }
        memcpy((mm_u8 *)h->regs + offset, &value, size_bytes);
        return MM_TRUE;
    }
    memcpy((mm_u8 *)h->regs + offset, &value, size_bytes);
    return MM_TRUE;
}
mm_bool aes_read(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 *value_out)
{
    struct aes_ctx *ctx = (struct aes_ctx *)opaque;
    struct aes_state *a = ctx->state;
    mm_u32 val;
    if (value_out == 0 || size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if ((offset + size_bytes) > AES_SIZE) return MM_FALSE;
    if (ctx->clock_enabled == NULL ||
        !ctx->clock_enabled(ctx->rcc, ctx->is_saes)) {
        *value_out = 0u;
        return MM_TRUE;
    }
    if (!ctx->secure_alias &&
        ctx->requires_secure != NULL &&
        ctx->requires_secure(ctx->tzsc, ctx->is_saes)) {
        *value_out = 0u;
        return MM_TRUE;
    }
    if (offset == AES_SR) {
        val = a->regs[AES_SR / 4u] & ~(AES_SR_KEYVALID);
        if (a->key_valid) val |= AES_SR_KEYVALID;
        memcpy(value_out, &val, size_bytes);
        return MM_TRUE;
    }
    if (offset == AES_ISR) {
        val = a->regs[AES_SR / 4u] & AES_SR_CCF;
        if ((a->regs[AES_SR / 4u] & AES_SR_WRERR) != 0u) {
            val |= (1u << 1);
        }
        memcpy(value_out, &val, size_bytes);
        return MM_TRUE;
    }
    if (saes_access_denied(ctx, a)) {
        *value_out = 0u;
        return MM_TRUE;
    }
    if (ctx->is_saes &&
        (offset == AES_KEYR0 || offset == AES_KEYR1 || offset == AES_KEYR2 || offset == AES_KEYR3 ||
         offset == AES_KEYR4 || offset == AES_KEYR5 || offset == AES_KEYR6 || offset == AES_KEYR7) &&
        a->saes_hidden_key) {
        *value_out = 0u;
        return MM_TRUE;
    }
    if (offset == AES_DOUTR) {
        mm_u32 datatype = (a->regs[AES_CR / 4u] >> AES_CR_DATATYPE_SHIFT) & 0x3u;
        if (!a->out_ready || a->out_word >= 4u) {
            *value_out = 0u;
            return MM_TRUE;
        }
        val = ((mm_u32)a->out_block[a->out_word * 4u] << 24) |
              ((mm_u32)a->out_block[a->out_word * 4u + 1u] << 16) |
              ((mm_u32)a->out_block[a->out_word * 4u + 2u] << 8) |
              (mm_u32)a->out_block[a->out_word * 4u + 3u];
        val = apply_datatype(val, datatype);
        a->out_word++;
        if (a->out_word >= 4u) {
            a->out_ready = MM_FALSE;
        }
        memcpy(value_out, &val, size_bytes);
        return MM_TRUE;
    }
    memcpy(value_out, (mm_u8 *)a->regs + offset, size_bytes);
    return MM_TRUE;
}

#ifdef M33MU_HAS_WOLFSSL
static void aes_build_key(struct aes_state *a, mm_u8 *key_out, mm_u32 key_len)
{
    memset(key_out, 0, key_len);
    if (a->key_len_bytes >= key_len) {
        memcpy(key_out, a->key_bytes, key_len);
    }
}

static void aes_build_iv(struct aes_state *a, mm_u8 *iv_out)
{
    mm_u32 i;
    for (i = 0u; i < 4u; ++i) {
        mm_u32 w = a->iv_words[3u - i];
        iv_out[i * 4u] = (mm_u8)((w >> 24) & 0xffu);
        iv_out[i * 4u + 1u] = (mm_u8)((w >> 16) & 0xffu);
        iv_out[i * 4u + 2u] = (mm_u8)((w >> 8) & 0xffu);
        iv_out[i * 4u + 3u] = (mm_u8)(w & 0xffu);
    }
}

static mm_u32 aes_gcm_iv_len(const mm_u8 *iv)
{
    if (iv[12] == 0u && iv[13] == 0u && iv[14] == 0u &&
        (iv[15] == 1u || iv[15] == 2u)) {
        return 12u;
    }
    return 16u;
}
#endif

#if defined(M33MU_HAS_WOLFSSL) && !defined(WOLFSSL_AESGCM_STREAM)
static void aes_unreverse_words(mm_u8 *buf)
{
    mm_u32 i;
    for (i = 0u; i < 4u; ++i) {
        mm_u8 *b = buf + i * 4u;
        mm_u8 t;
        t = b[0]; b[0] = b[3]; b[3] = t;
        t = b[1]; b[1] = b[2]; b[2] = t;
    }
}
#endif

#ifdef M33MU_HAS_WOLFSSL
static void aes_store_iv(struct aes_state *a, const mm_u8 *iv_in)
{
    mm_u32 i;
    for (i = 0u; i < 4u; ++i) {
        a->iv_words[3u - i] = ((mm_u32)iv_in[i * 4u] << 24) |
                              ((mm_u32)iv_in[i * 4u + 1u] << 16) |
                              ((mm_u32)iv_in[i * 4u + 2u] << 8) |
                              (mm_u32)iv_in[i * 4u + 3u];
    }
}
#endif

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
    (void)chmod;
    (void)decrypt;
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

#if defined(M33MU_HAS_WOLFSSL) && defined(WOLFSSL_AESGCM_STREAM)
static void aes_prepare_gcm(struct aes_state *a, mm_bool decrypt)
{
    mm_u8 key[32];
    mm_u8 iv[16];
    mm_u32 iv_len;
    mm_u32 key_len = (a->regs[AES_CR / 4u] & AES_CR_KEYSIZE) ? 32u : 16u;
    aes_build_key(a, key, key_len);
    aes_build_iv_rev(a, iv);
    iv_len = aes_gcm_iv_len(iv);
    if (iv_len == 16u) {
        a->gcm_use_icb = MM_TRUE;
        memcpy(a->gcm_icb, iv, sizeof(a->gcm_icb));
        wc_AesGcmSetKey(&a->gcm_aes, key, key_len);
        wc_AesInit(&a->gcm_ctr_aes, NULL, INVALID_DEVID);
        wc_AesSetKeyDirect(&a->gcm_ctr_aes, key, key_len, a->gcm_icb,
                           AES_ENCRYPTION);
        a->gcm_ctr_inited = MM_TRUE;
        a->gcm_inited = MM_TRUE;
        return;
    }
    if (decrypt) {
        wc_AesGcmDecryptInit(&a->gcm_aes, key, key_len, iv, iv_len);
    } else {
        wc_AesGcmEncryptInit(&a->gcm_aes, key, key_len, iv, iv_len);
    }
    a->gcm_inited = MM_TRUE;
}
#endif

static void aes_handle_gcm_block(struct aes_state *a, mm_u32 phase, mm_bool decrypt, const mm_u8 *in, mm_u32 len)
{
#ifdef M33MU_HAS_WOLFSSL
#ifdef WOLFSSL_AESGCM_STREAM
    if (!a->gcm_inited) {
        aes_prepare_gcm(a, decrypt);
    }
    if (phase == 1u) {
        if (a->gcm_use_icb) {
            if (a->gcm_capture_ok &&
                !aes_buf_append(&a->aad, &a->aad_len, &a->aad_cap, in, len)) {
                a->gcm_capture_ok = MM_FALSE;
            }
            memset(a->out_block, 0, sizeof(a->out_block));
            a->out_ready = MM_TRUE;
            a->out_word = 0u;
            return;
        }
        if (decrypt) {
            wc_AesGcmDecryptUpdate(&a->gcm_aes, 0, 0, 0, in, len);
        } else {
            wc_AesGcmEncryptUpdate(&a->gcm_aes, 0, 0, 0, in, len);
        }
        if (a->gcm_capture_ok &&
            !aes_buf_append(&a->aad, &a->aad_len, &a->aad_cap, in, len)) {
            a->gcm_capture_ok = MM_FALSE;
        }
        memset(a->out_block, 0, sizeof(a->out_block));
        a->out_ready = MM_TRUE;
        a->out_word = 0u;
        return;
    }
    if (phase == 2u) {
        if (a->gcm_use_icb) {
            const mm_u8 *payload_src = in;
            if (a->gcm_ctr_inited) {
                wc_AesCtrEncrypt(&a->gcm_ctr_aes, a->out_block, in, len);
            } else {
                memcpy(a->out_block, in, len);
            }
            if (!decrypt) {
                payload_src = a->out_block;
            }
            if (a->gcm_capture_ok &&
                !aes_buf_append(&a->payload, &a->payload_len, &a->payload_cap,
                                payload_src, len)) {
                a->gcm_capture_ok = MM_FALSE;
            }
            if (len < 16u) {
                memset(a->out_block + len, 0, 16u - len);
            }
            a->out_ready = MM_TRUE;
            a->out_word = 0u;
            return;
        }
        if (decrypt) {
            wc_AesGcmDecryptUpdate(&a->gcm_aes, a->out_block, in, len, 0, 0);
        } else {
            wc_AesGcmEncryptUpdate(&a->gcm_aes, a->out_block, in, len, 0, 0);
        }
        if (a->gcm_capture_ok &&
            !aes_buf_append(&a->payload, &a->payload_len, &a->payload_cap, in, len)) {
            a->gcm_capture_ok = MM_FALSE;
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
        memset(a->out_block, 0, sizeof(a->out_block));
        a->out_ready = MM_TRUE;
        a->out_word = 0u;
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
    (void)a;
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
    if (a->gcm_use_icb) {
        if (a->gcm_len_valid && a->gcm_capture_ok) {
            Aes tmp;
            mm_u8 key[32];
            mm_u8 j0[16];
            mm_u8 scratch[16];
            mm_u32 key_len = (a->regs[AES_CR / 4u] & AES_CR_KEYSIZE) ? 32u : 16u;
            mm_u32 aad_len = (mm_u32)(a->gcm_aad_bits / 8u);
            mm_u32 payload_len = (mm_u32)(a->gcm_payload_bits / 8u);
            aes_build_key(a, key, key_len);
            if (aad_len > a->aad_len) aad_len = a->aad_len;
            if (payload_len > a->payload_len) payload_len = a->payload_len;
            memcpy(j0, a->gcm_icb, sizeof(j0));
            {
                mm_u32 ctr = ((mm_u32)j0[12] << 24) |
                             ((mm_u32)j0[13] << 16) |
                             ((mm_u32)j0[14] << 8) |
                             (mm_u32)j0[15];
                ctr -= 1u;
                j0[12] = (mm_u8)((ctr >> 24) & 0xffu);
                j0[13] = (mm_u8)((ctr >> 16) & 0xffu);
                j0[14] = (mm_u8)((ctr >> 8) & 0xffu);
                j0[15] = (mm_u8)(ctr & 0xffu);
            }
            wc_AesInit(&tmp, NULL, INVALID_DEVID);
            wc_AesGcmSetKey(&tmp, key, key_len);
            aes_gcm_ghash(&tmp, a->aad, aad_len, a->payload, payload_len, a->tag);
            (void)wc_AesEcbEncrypt(&tmp, scratch, j0, 16u);
            {
                mm_u32 i;
                for (i = 0u; i < 16u; ++i) {
                    a->tag[i] ^= scratch[i];
                }
            }
            wc_AesFree(&tmp);
        } else {
            memset(a->tag, 0, sizeof(a->tag));
        }
        memcpy(a->out_block, a->tag, 16u);
        a->tag_ready = MM_TRUE;
        a->out_ready = MM_TRUE;
        a->out_word = 0u;
        return;
    }
    if (a->gcm_len_valid) {
        a->gcm_aes.aSz = (mm_u32)(a->gcm_aad_bits / 8u);
        a->gcm_aes.cSz = (mm_u32)(a->gcm_payload_bits / 8u);
    }
    (void)decrypt;
    wc_AesGcmEncryptFinal(&a->gcm_aes, a->tag, 16u);
    if (a->gcm_len_valid && a->gcm_capture_ok) {
        Aes tmp;
        mm_u8 key[32];
        mm_u8 iv[16];
        mm_u32 iv_len;
        mm_u32 key_len = (a->regs[AES_CR / 4u] & AES_CR_KEYSIZE) ? 32u : 16u;
        mm_u32 aad_len = (mm_u32)(a->gcm_aad_bits / 8u);
        mm_u32 payload_len = (mm_u32)(a->gcm_payload_bits / 8u);
        mm_u32 offset = 0u;
        mm_u8 scratch[16];
        aes_build_key(a, key, key_len);
        aes_build_iv_rev(a, iv);
        iv_len = aes_gcm_iv_len(iv);
        if (aad_len > a->aad_len) aad_len = a->aad_len;
        if (payload_len > a->payload_len) payload_len = a->payload_len;
        wc_AesInit(&tmp, NULL, INVALID_DEVID);
        if (decrypt) {
            wc_AesGcmDecryptInit(&tmp, key, key_len, iv, iv_len);
            if (aad_len > 0u) {
                (void)wc_AesGcmDecryptUpdate(&tmp, 0, 0, 0, a->aad, aad_len);
            }
            while (offset < payload_len) {
                mm_u32 chunk = payload_len - offset;
                if (chunk > sizeof(scratch)) chunk = sizeof(scratch);
                (void)wc_AesGcmDecryptUpdate(&tmp, scratch, a->payload + offset, chunk, 0, 0);
                offset += chunk;
            }
        } else {
            wc_AesGcmEncryptInit(&tmp, key, key_len, iv, iv_len);
        if (aad_len > 0u) {
            (void)wc_AesGcmEncryptUpdate(&tmp, 0, 0, 0, a->aad, aad_len);
        }
        while (offset < payload_len) {
            mm_u32 chunk = payload_len - offset;
            if (chunk > sizeof(scratch)) chunk = sizeof(scratch);
            (void)wc_AesGcmEncryptUpdate(&tmp, scratch, a->payload + offset, chunk, 0, 0);
            offset += chunk;
        }
        }
        (void)wc_AesGcmEncryptFinal(&tmp, a->tag, 16u);
        wc_AesFree(&tmp);
    }
#else
    {
        mm_u8 key[32];
        mm_u8 iv[16];
        mm_u32 iv_len;
        mm_u32 aad_len = a->aad_len;
        mm_u32 payload_len = a->payload_len;
        mm_u32 key_len = (a->regs[AES_CR / 4u] & AES_CR_KEYSIZE) ? 32u : 16u;
        aes_build_key(a, key, key_len);
        aes_build_iv_rev(a, iv);
        aes_unreverse_words(iv);
        iv_len = aes_gcm_iv_len(iv);
        wc_AesGcmSetKey(&a->gcm_aes, key, key_len);
        if (decrypt) {
            wc_AesGcmDecrypt(&a->gcm_aes, a->payload, a->payload, payload_len,
                             iv, iv_len, a->tag, 16u, a->aad, aad_len);
        } else {
            wc_AesGcmEncrypt(&a->gcm_aes, a->payload, a->payload, payload_len,
                             iv, iv_len, a->tag, 16u, a->aad, aad_len);
        }
    }
#endif
    memcpy(a->out_block, a->tag, 16u);
    a->tag_ready = MM_TRUE;
    a->out_ready = MM_TRUE;
    a->out_word = 0u;
#else
    (void)a;
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
        memset(a->out_block, 0, sizeof(a->out_block));
        a->out_ready = MM_TRUE;
        a->out_word = 0u;
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
    (void)a;
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
    (void)a;
    (void)decrypt;
#endif
}

mm_bool aes_write(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 value)
{
    struct aes_ctx *ctx = (struct aes_ctx *)opaque;
    struct aes_state *a = ctx->state;
    mm_u32 datatype;
    if (size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if ((offset + size_bytes) > AES_SIZE) return MM_FALSE;
    if (ctx->clock_enabled == NULL ||
        !ctx->clock_enabled(ctx->rcc, ctx->is_saes)) {
        return MM_TRUE;
    }
    if (!ctx->secure_alias &&
        ctx->requires_secure != NULL &&
        ctx->requires_secure(ctx->tzsc, ctx->is_saes)) {
        return MM_TRUE;
    }
    if (offset != AES_ICR && saes_access_denied(ctx, a)) {
        a->regs[AES_SR / 4u] |= AES_SR_WRERR;
        return MM_TRUE;
    }
    if (offset == AES_CR) {
        mm_u32 prev = a->regs[AES_CR / 4u];
        mm_u32 mode = (value >> AES_CR_MODE_SHIFT) & 0x3u;
        if ((value & AES_CR_IPRST) != 0u) {
            memset(a, 0, sizeof(*a));
        }
        a->regs[AES_CR / 4u] = value;
        a->npblb = (value >> AES_CR_NPBLB_SHIFT) & 0xFu;
        if (ctx->is_saes) {
            a->saes_keysel = (mm_u8)((value & AES_CR_KEYSEL_MASK) >> AES_CR_KEYSEL_SHIFT);
            a->saes_keyprot = ((value & AES_CR_KEYPROT) != 0u) ? MM_TRUE : MM_FALSE;
            saes_refresh_selected_key(ctx, a);
            a->regs[AES_SR / 4u] = (a->regs[AES_SR / 4u] & ~AES_SR_KEYVALID) |
                                   (a->key_valid ? AES_SR_KEYVALID : 0u);
        }
        if (((prev ^ value) & (AES_CR_CHMOD2 | AES_CR_CHMOD_MASK)) != 0u) {
            aes_reset_auth_state(a);
        }
        if (((prev ^ value) & (0x3u << AES_CR_MODE_SHIFT)) != 0u) {
            aes_reset_auth_state(a);
        }
        if (((prev & AES_CR_EN) == 0u) && ((value & AES_CR_EN) != 0u)) {
            aes_reset_auth_state(a);
            if (aes_algo_mode(a) >= 3u && aes_phase(a) == 0u) {
                memset(a->out_block, 0, sizeof(a->out_block));
                a->out_ready = MM_TRUE;
                a->out_word = 0u;
                a->regs[AES_SR / 4u] |= AES_SR_CCF;
                a->regs[AES_SR / 4u] &= ~AES_SR_BUSY;
            } else if (mode == 1u) {
                a->regs[AES_SR / 4u] |= AES_SR_CCF;
                a->regs[AES_SR / 4u] &= ~AES_SR_BUSY;
            }
        }
        if (((prev ^ value) & AES_CR_KEYSIZE) != 0u) {
            mm_u32 key_len = aes_key_len_from_cr(value);
            if (ctx->is_saes) {
                saes_refresh_selected_key(ctx, a);
            } else {
                aes_update_software_key_valid(a, key_len);
            }
            a->regs[AES_SR / 4u] = (a->regs[AES_SR / 4u] & ~AES_SR_KEYVALID) |
                                   (a->key_valid ? AES_SR_KEYVALID : 0u);
        }
        return MM_TRUE;
    }
    if (offset == AES_KEYR0 || offset == AES_KEYR1 || offset == AES_KEYR2 || offset == AES_KEYR3 ||
        offset == AES_KEYR4 || offset == AES_KEYR5 || offset == AES_KEYR6 || offset == AES_KEYR7) {
        mm_u32 idx;
        mm_u32 key_len = aes_key_len_from_cr(a->regs[AES_CR / 4u]);
        mm_u32 words = key_len / 4u;
        if (ctx->is_saes && a->saes_hidden_key) {
            a->regs[AES_SR / 4u] |= AES_SR_WRERR;
            return MM_TRUE;
        }
        if (offset >= AES_KEYR4) {
            idx = 4u + (offset - AES_KEYR4) / 4u;
        } else {
            idx = (offset - AES_KEYR0) / 4u;
        }
        if (idx < 8u) {
            a->key_words[idx] = value;
            a->regs[offset / 4u] = value;
        }
        if (idx < words) {
            a->key_written |= (1u << idx);
        }
        aes_update_software_key_valid(a, key_len);
        if (ctx->is_saes && a->key_valid && a->saes_keyprot) {
            a->saes_key_owner_secure = ctx->secure_alias;
        }
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
        a->in_raw[a->in_words] = value;
        a->in_block[a->in_words * 4u] = (mm_u8)((word >> 24) & 0xffu);
        a->in_block[a->in_words * 4u + 1u] = (mm_u8)((word >> 16) & 0xffu);
        a->in_block[a->in_words * 4u + 2u] = (mm_u8)((word >> 8) & 0xffu);
        a->in_block[a->in_words * 4u + 3u] = (mm_u8)(word & 0xffu);
        a->in_words++;
        if (a->in_words >= 4u) {
            algo = aes_algo_mode(a);
            phase = aes_phase(a);
            if ((algo == 3u || algo == 4u) && phase == 2u &&
                a->npblb != 0u && a->npblb < 16u) {
                valid_len = 16u - a->npblb;
            }
            a->regs[AES_SR / 4u] |= AES_SR_BUSY;
            if (algo == 3u) {
                mm_bool decrypt = ((a->regs[AES_CR / 4u] >> AES_CR_MODE_SHIFT) & 0x3u) != 0u;
                if (phase == 3u) {
                    a->gcm_aad_bits = ((mm_u64)a->in_raw[0] << 32) |
                                      (mm_u64)a->in_raw[1];
                    a->gcm_payload_bits = ((mm_u64)a->in_raw[2] << 32) |
                                          (mm_u64)a->in_raw[3];
                    a->gcm_len_valid = MM_TRUE;
                    aes_finalize_gcm(a, decrypt);
                } else {
                    aes_handle_gcm_block(a, phase, decrypt, a->in_block, valid_len);
                }
                a->regs[AES_SR / 4u] |= AES_SR_CCF;
                a->regs[AES_SR / 4u] &= ~AES_SR_BUSY;
            } else if (algo == 4u) {
                mm_bool decrypt = ((a->regs[AES_CR / 4u] >> AES_CR_MODE_SHIFT) & 0x3u) != 0u;
                if (phase == 3u) {
                    aes_finalize_ccm(a, decrypt);
                } else {
                    aes_handle_ccm_block(a, phase, decrypt, a->in_block, valid_len);
                }
                a->regs[AES_SR / 4u] |= AES_SR_CCF;
                a->regs[AES_SR / 4u] &= ~AES_SR_BUSY;
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
        }
        a->regs[AES_ICR / 4u] = value;
        return MM_TRUE;
    }
    memcpy((mm_u8 *)a->regs + offset, &value, size_bytes);
    return MM_TRUE;
}

mm_bool pka_write(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 value)
{
    (void)opaque;
    (void)offset;
    (void)value;
    if (size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    /* PKA emulation disabled. */
    return MM_TRUE;
}

mm_bool pka_read(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 *value_out)
{
    (void)opaque;
    (void)offset;
    if (value_out == 0 || size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    /* PKA emulation disabled. */
    *value_out = 0u;
    return MM_TRUE;
}
