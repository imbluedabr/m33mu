/* iotsafe_uart.c -- IoTSAFE modem + SIM card UART simulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "m33mu/iotsafe_uart.h"
#include "m33mu/target_hal.h"

#ifdef M33MU_HAS_WOLFSSL
#include <wolfssl/options.h>
#define USE_CERT_BUFFERS_256
#include <wolfssl/certs_test.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#endif

#define MM_IOTSAFE_UART_MAX_MODEMS 4
#define MM_IOTSAFE_RX_FIFO_SIZE 8192u
#define MM_IOTSAFE_LINE_MAX 4096u
#define MM_IOTSAFE_FILES_MAX 16u
#define MM_IOTSAFE_KEYS_MAX 16u
#define MM_IOTSAFE_FILE_DATA_MAX 2048u
#define MM_IOTSAFE_READ_FILE_CHUNK_MAX 240u
#define MM_IOTSAFE_ECC_PRIV_SZ 32u
#define MM_IOTSAFE_ECC_RAW_PUB_SZ 64u
#define MM_IOTSAFE_ECC_X963_SZ 65u

#define IOTSAFE_CLASS             0x81u
#define IOTSAFE_INS_PUT_PUBLIC_INIT   0x24u
#define IOTSAFE_INS_PUT_PUBLIC_UPDATE 0xD8u
#define IOTSAFE_INS_SIGN_INIT     0x2Au
#define IOTSAFE_INS_SIGN_UPDATE   0x2Bu
#define IOTSAFE_INS_VERIFY_INIT   0x2Cu
#define IOTSAFE_INS_VERIFY_UPDATE 0x2Du
#define IOTSAFE_INS_COMPUTE_DH    0x46u
#define IOTSAFE_INS_HKDF_EXTRACT  0x4Au
#define IOTSAFE_INS_GETRANDOM     0x84u
#define IOTSAFE_INS_READ_FILE     0xB0u
#define IOTSAFE_INS_GEN_KEYPAIR   0xB9u
#define IOTSAFE_INS_GETRESPONSE   0xC0u
#define IOTSAFE_INS_GETDATA       0xCBu
#define IOTSAFE_INS_READ_KEY      0xCDu

#define IOTSAFE_TAG_ECC_KEY_FIELD     0x34u
#define IOTSAFE_TAG_ECC_KEY_TYPE      0x49u
#define IOTSAFE_TAG_ECC_KEY_XY        0x86u
#define IOTSAFE_TAG_HASH_FIELD        0x9Eu
#define IOTSAFE_TAG_SIGNATURE_FIELD   0x33u
#define IOTSAFE_TAG_FILE_ID           0x83u
#define IOTSAFE_TAG_PRIVKEY_ID        0x84u
#define IOTSAFE_TAG_PUBKEY_ID         0x85u
#define IOTSAFE_TAG_HASH_ALGO         0x91u
#define IOTSAFE_TAG_SIGN_ALGO         0x92u
#define IOTSAFE_TAG_MODE_OF_OPERATION 0xA1u
#define IOTSAFE_TAG_SECRET            0xD1u
#define IOTSAFE_TAG_SALT              0xD5u

#define IOTSAFE_HASH_SHA256           0x0001u
#define IOTSAFE_HASH_SHA384           0x0002u
#define IOTSAFE_HASH_SHA512           0x0004u
#define IOTSAFE_SIGN_ECDSA            0x04u
#define IOTSAFE_GETDATA_FILE          0xC3u
#define IOTSAFE_DATA_LAST             0x80u

#define IOTSAFE_DEFAULT_PRIVKEY_ID     0x0001u
#define IOTSAFE_DEFAULT_CLIENT_CERT_ID 0x0002u
#define IOTSAFE_DEFAULT_SERVER_CERT_ID 0x0003u
#define IOTSAFE_DEFAULT_ECDH_ID        0x0004u
#define IOTSAFE_DEFAULT_PEER_PUB_ID    0x0005u

enum mm_iotsafe_apdu_mode {
    MM_IOTSAFE_APDU_CSIM = 0,
    MM_IOTSAFE_APDU_OK_ASYNC = 1
};

struct mm_iotsafe_file_slot {
    mm_u8 used;
    mm_u16 id;
    mm_u16 len;
    mm_u8 data[MM_IOTSAFE_FILE_DATA_MAX];
};

struct mm_iotsafe_key_slot {
    mm_u8 used;
    mm_u16 id;
    mm_u8 has_private;
    mm_u8 has_public;
    mm_u8 priv[MM_IOTSAFE_ECC_PRIV_SZ];
    mm_u8 pub[MM_IOTSAFE_ECC_X963_SZ];
};

struct mm_iotsafe_nv {
    char magic[8];
    mm_u32 version;
    struct mm_iotsafe_file_slot files[MM_IOTSAFE_FILES_MAX];
    struct mm_iotsafe_key_slot keys[MM_IOTSAFE_KEYS_MAX];
};

struct mm_iotsafe_modem {
    mm_bool used;
    mm_u32 base;
    mm_bool has_nv_path;
    char nv_path[256];
    mm_bool echo_enabled;
    mm_bool applet_selected;
    char line_buf[MM_IOTSAFE_LINE_MAX];
    size_t line_len;
    mm_u8 rx_fifo[MM_IOTSAFE_RX_FIFO_SIZE];
    size_t rx_head;
    size_t rx_tail;
    int pending_ok_polls;
    mm_bool sign_active;
    mm_bool verify_active;
    mm_bool put_pub_active;
    mm_u16 sign_key_id;
    mm_u16 verify_key_id;
    mm_u16 put_pub_key_id;
    mm_bool rng_initialized;
#ifdef M33MU_HAS_WOLFSSL
    WC_RNG rng;
#endif
    struct mm_iotsafe_file_slot files[MM_IOTSAFE_FILES_MAX];
    struct mm_iotsafe_key_slot keys[MM_IOTSAFE_KEYS_MAX];
};

static struct mm_iotsafe_modem g_iotsafe_modems[MM_IOTSAFE_UART_MAX_MODEMS];

static size_t iotsafe_uart_write_tx(void *opaque, const mm_u8 *data, size_t len);
static mm_bool iotsafe_uart_read_rx(void *opaque, mm_u8 *byte_out);
static void iotsafe_uart_close(void *opaque);

static const struct mm_uart_backend_ops g_iotsafe_uart_ops = {
    iotsafe_uart_write_tx,
    iotsafe_uart_read_rx,
    iotsafe_uart_close
};

static void iotsafe_modem_reset(struct mm_iotsafe_modem *modem)
{
    if (modem == 0) {
        return;
    }
    modem->echo_enabled = MM_TRUE;
    modem->applet_selected = MM_FALSE;
    modem->line_len = 0;
    modem->rx_head = 0;
    modem->rx_tail = 0;
    modem->pending_ok_polls = 0;
    modem->sign_active = MM_FALSE;
    modem->verify_active = MM_FALSE;
    modem->put_pub_active = MM_FALSE;
    modem->sign_key_id = 0;
    modem->verify_key_id = 0;
    modem->put_pub_key_id = 0;
}

static mm_bool rx_fifo_push(struct mm_iotsafe_modem *modem, mm_u8 byte)
{
    size_t next_tail;
    next_tail = (modem->rx_tail + 1u) % MM_IOTSAFE_RX_FIFO_SIZE;
    if (next_tail == modem->rx_head) {
        return MM_FALSE;
    }
    modem->rx_fifo[modem->rx_tail] = byte;
    modem->rx_tail = next_tail;
    return MM_TRUE;
}

static void rx_fifo_write_str(struct mm_iotsafe_modem *modem, const char *s)
{
    size_t i;
    if (modem == 0 || s == 0) {
        return;
    }
    for (i = 0; s[i] != '\0'; ++i) {
        if (!rx_fifo_push(modem, (mm_u8)s[i])) {
            return;
        }
    }
}

static mm_bool rx_fifo_pop(struct mm_iotsafe_modem *modem, mm_u8 *byte_out)
{
    if (modem == 0 || byte_out == 0 || modem->rx_head == modem->rx_tail) {
        return MM_FALSE;
    }
    *byte_out = modem->rx_fifo[modem->rx_head];
    modem->rx_head = (modem->rx_head + 1u) % MM_IOTSAFE_RX_FIFO_SIZE;
    return MM_TRUE;
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static mm_bool hex_to_bytes(const char *hex, size_t hex_len, mm_u8 *out, size_t out_cap,
                            size_t *out_len)
{
    size_t i;
    size_t nbytes;
    if ((hex_len & 1u) != 0u) {
        return MM_FALSE;
    }
    nbytes = hex_len / 2u;
    if (nbytes > out_cap) {
        return MM_FALSE;
    }
    for (i = 0; i < nbytes; ++i) {
        int hi = hex_nibble(hex[i * 2u]);
        int lo = hex_nibble(hex[i * 2u + 1u]);
        if (hi < 0 || lo < 0) {
            return MM_FALSE;
        }
        out[i] = (mm_u8)((hi << 4) | lo);
    }
    if (out_len != 0) {
        *out_len = nbytes;
    }
    return MM_TRUE;
}

static void bytes_to_hex(const mm_u8 *data, size_t len, char *out)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t i;
    for (i = 0; i < len; ++i) {
        out[i * 2u] = hex[(data[i] >> 4) & 0x0Fu];
        out[i * 2u + 1u] = hex[data[i] & 0x0Fu];
    }
    out[len * 2u] = '\0';
}

static struct mm_iotsafe_key_slot *find_key_slot(struct mm_iotsafe_modem *modem,
                                                 mm_u16 id, mm_bool create)
{
    size_t i;
    struct mm_iotsafe_key_slot *free_slot = 0;
    for (i = 0; i < MM_IOTSAFE_KEYS_MAX; ++i) {
        if (modem->keys[i].used && modem->keys[i].id == id) {
            return &modem->keys[i];
        }
        if (!modem->keys[i].used && free_slot == 0) {
            free_slot = &modem->keys[i];
        }
    }
    if (!create || free_slot == 0) {
        return 0;
    }
    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->used = 1u;
    free_slot->id = id;
    return free_slot;
}

static struct mm_iotsafe_file_slot *find_file_slot(struct mm_iotsafe_modem *modem,
                                                   mm_u16 id, mm_bool create)
{
    size_t i;
    struct mm_iotsafe_file_slot *free_slot = 0;
    for (i = 0; i < MM_IOTSAFE_FILES_MAX; ++i) {
        if (modem->files[i].used && modem->files[i].id == id) {
            return &modem->files[i];
        }
        if (!modem->files[i].used && free_slot == 0) {
            free_slot = &modem->files[i];
        }
    }
    if (!create || free_slot == 0) {
        return 0;
    }
    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->used = 1u;
    free_slot->id = id;
    return free_slot;
}

#ifdef M33MU_HAS_WOLFSSL
static mm_bool file_slot_store(struct mm_iotsafe_modem *modem, mm_u16 id,
                               const mm_u8 *data, size_t len)
{
    struct mm_iotsafe_file_slot *slot;
    if (len > MM_IOTSAFE_FILE_DATA_MAX) {
        return MM_FALSE;
    }
    slot = find_file_slot(modem, id, MM_TRUE);
    if (slot == 0) {
        return MM_FALSE;
    }
    memcpy(slot->data, data, len);
    slot->len = (mm_u16)len;
    return MM_TRUE;
}
#endif

#ifdef M33MU_HAS_WOLFSSL
static mm_bool ensure_rng(struct mm_iotsafe_modem *modem)
{
    if (modem->rng_initialized) {
        return MM_TRUE;
    }
    if (wc_InitRng(&modem->rng) != 0) {
        return MM_FALSE;
    }
    modem->rng_initialized = MM_TRUE;
    return MM_TRUE;
}

static int import_private_slot(const struct mm_iotsafe_key_slot *slot, ecc_key *key)
{
    return wc_ecc_import_private_key_ex(slot->priv, MM_IOTSAFE_ECC_PRIV_SZ,
                                        slot->pub, MM_IOTSAFE_ECC_X963_SZ,
                                        key, ECC_SECP256R1);
}

static int import_public_slot(const struct mm_iotsafe_key_slot *slot, ecc_key *key)
{
    return wc_ecc_import_x963_ex(slot->pub, MM_IOTSAFE_ECC_X963_SZ,
                                 key, ECC_SECP256R1);
}

static mm_bool key_slot_store_from_ecc(struct mm_iotsafe_key_slot *slot,
                                       ecc_key *key, mm_bool keep_private)
{
    word32 priv_len = MM_IOTSAFE_ECC_PRIV_SZ;
    word32 pub_len = MM_IOTSAFE_ECC_X963_SZ;
    mm_u8 priv[MM_IOTSAFE_ECC_PRIV_SZ];
    mm_u8 pub[MM_IOTSAFE_ECC_X963_SZ];
    if (wc_ecc_export_x963(key, pub, &pub_len) != 0) {
        return MM_FALSE;
    }
    if (pub_len != MM_IOTSAFE_ECC_X963_SZ || pub[0] != 0x04u) {
        return MM_FALSE;
    }
    memcpy(slot->pub, pub, sizeof(pub));
    slot->has_public = 1u;
    if (keep_private) {
        memset(priv, 0, sizeof(priv));
        if (wc_ecc_export_private_only(key, priv, &priv_len) != 0) {
            return MM_FALSE;
        }
        if (priv_len == 0u || priv_len > MM_IOTSAFE_ECC_PRIV_SZ) {
            return MM_FALSE;
        }
        memset(slot->priv, 0, sizeof(slot->priv));
        memcpy(slot->priv + (MM_IOTSAFE_ECC_PRIV_SZ - priv_len), priv, priv_len);
        slot->has_private = 1u;
    }
    return MM_TRUE;
}

static int hash_type_from_iotsafe(mm_u16 hash_algo)
{
    switch (hash_algo) {
        case IOTSAFE_HASH_SHA256: return WC_SHA256;
        case IOTSAFE_HASH_SHA384: return WC_SHA384;
        case IOTSAFE_HASH_SHA512: return WC_SHA512;
        default: return -1;
    }
}
#endif

static void init_default_store(struct mm_iotsafe_modem *modem)
{
    memset(modem->files, 0, sizeof(modem->files));
    memset(modem->keys, 0, sizeof(modem->keys));
#ifdef M33MU_HAS_WOLFSSL
    {
        struct mm_iotsafe_key_slot *slot;
        ecc_key key;
        word32 idx = 0;

        (void)file_slot_store(modem, IOTSAFE_DEFAULT_CLIENT_CERT_ID,
                              cliecc_cert_der_256, sizeof_cliecc_cert_der_256);
        (void)file_slot_store(modem, IOTSAFE_DEFAULT_SERVER_CERT_ID,
                              serv_ecc_der_256, sizeof_serv_ecc_der_256);

        slot = find_key_slot(modem, IOTSAFE_DEFAULT_PRIVKEY_ID, MM_TRUE);
        if (slot != 0) {
            memset(&key, 0, sizeof(key));
            if (wc_ecc_init(&key) == 0 &&
                wc_EccPrivateKeyDecode(ecc_clikey_der_256, &idx, &key,
                                       sizeof_ecc_clikey_der_256) == 0) {
                (void)key_slot_store_from_ecc(slot, &key, MM_TRUE);
            }
            wc_ecc_free(&key);
        }
        (void)find_key_slot(modem, IOTSAFE_DEFAULT_ECDH_ID, MM_TRUE);
        (void)find_key_slot(modem, IOTSAFE_DEFAULT_PEER_PUB_ID, MM_TRUE);
    }
#endif
}

static void sync_nv(struct mm_iotsafe_modem *modem)
{
    struct mm_iotsafe_nv nv;
    FILE *fp;
    if (modem == 0 || !modem->has_nv_path) {
        return;
    }
    memset(&nv, 0, sizeof(nv));
    memcpy(nv.magic, "IOTSAFE1", 8u);
    nv.version = 1u;
    memcpy(nv.files, modem->files, sizeof(nv.files));
    memcpy(nv.keys, modem->keys, sizeof(nv.keys));
    fp = fopen(modem->nv_path, "wb");
    if (fp == 0) {
        fprintf(stderr, "iotsafe-uart: failed to open %s for write\n", modem->nv_path);
        return;
    }
    if (fwrite(&nv, 1u, sizeof(nv), fp) != sizeof(nv)) {
        fprintf(stderr, "iotsafe-uart: short write for %s\n", modem->nv_path);
    }
    fclose(fp);
}

static void load_or_init_nv(struct mm_iotsafe_modem *modem)
{
    struct mm_iotsafe_nv nv;
    FILE *fp;
    if (modem->has_nv_path) {
        fp = fopen(modem->nv_path, "rb");
        if (fp != 0) {
            if (fread(&nv, 1u, sizeof(nv), fp) == sizeof(nv) &&
                memcmp(nv.magic, "IOTSAFE1", 8u) == 0 &&
                nv.version == 1u) {
                memcpy(modem->files, nv.files, sizeof(modem->files));
                memcpy(modem->keys, nv.keys, sizeof(modem->keys));
                fclose(fp);
                return;
            }
            fclose(fp);
        }
    }
    init_default_store(modem);
    sync_nv(modem);
}

static const mm_u8 *find_tlv_value(const mm_u8 *buf, size_t len, mm_u8 tag,
                                   size_t *value_len)
{
    size_t off = 0;
    while (off + 2u <= len) {
        mm_u8 cur_tag;
        size_t cur_len;
        cur_tag = buf[off++];
        cur_len = buf[off++];
        if (cur_len == 0u && off < len) {
            cur_len = buf[off++];
        }
        if (off + cur_len > len) {
            return 0;
        }
        if (cur_tag == tag) {
            if (value_len != 0) {
                *value_len = cur_len;
            }
            return &buf[off];
        }
        off += cur_len;
    }
    return 0;
}

#ifdef M33MU_HAS_WOLFSSL
static mm_u16 read_be16(const mm_u8 *p)
{
    return (mm_u16)(((mm_u16)p[0] << 8) | (mm_u16)p[1]);
}
#endif

static mm_u16 read_slot_id16(const mm_u8 *p)
{
    return (mm_u16)(((mm_u16)p[1] << 8) | (mm_u16)p[0]);
}

static void append_status_9000(char *hex_out, size_t *hex_len)
{
    memcpy(hex_out + *hex_len, "9000", 4u);
    *hex_len += 4u;
    hex_out[*hex_len] = '\0';
}

static void build_pubkey_tlv_from_slot(const struct mm_iotsafe_key_slot *slot,
                                       mm_u8 *out, size_t *out_len)
{
    size_t idx = 0;
    out[idx++] = IOTSAFE_TAG_ECC_KEY_FIELD;
    out[idx++] = 0x45u;
    out[idx++] = IOTSAFE_TAG_ECC_KEY_TYPE;
    out[idx++] = 0x43u;
    out[idx++] = IOTSAFE_TAG_ECC_KEY_XY;
    out[idx++] = 0x41u;
    out[idx++] = 0x04u;
    memcpy(&out[idx], &slot->pub[1], MM_IOTSAFE_ECC_RAW_PUB_SZ);
    idx += MM_IOTSAFE_ECC_RAW_PUB_SZ;
    *out_len = idx;
}

static int process_apdu(struct mm_iotsafe_modem *modem,
                        const mm_u8 *apdu, size_t apdu_len,
                        char *hex_out, size_t hex_cap, size_t *hex_len,
                        enum mm_iotsafe_apdu_mode *mode_out)
{
    mm_u8 cla;
    mm_u8 ins;
    mm_u8 p1;
    mm_u8 p2;
    mm_u8 lc;
    const mm_u8 *body;
    size_t body_len;
    if (mode_out == 0 || hex_out == 0 || hex_len == 0) {
        return -1;
    }
    *mode_out = MM_IOTSAFE_APDU_CSIM;
    *hex_len = 0;
    hex_out[0] = '\0';
    if (apdu_len < 5u) {
        return -1;
    }
    cla = apdu[0];
    ins = apdu[1];
    p1 = apdu[2];
    p2 = apdu[3];
    lc = apdu[4];
    body = &apdu[5];
    body_len = apdu_len - 5u;
    if (ins != IOTSAFE_INS_GETRANDOM && body_len != lc) {
        return -1;
    }

    if (cla == 0x01u && ins == 0xA4u) {
        static const mm_u8 applet_aid[] = { 0xA0u, 0x00u, 0x00u, 0x05u, 0x59u, 0x00u, 0x10u };
        if (p1 != 0x04u || p2 != 0x00u || lc != sizeof(applet_aid) ||
            memcmp(body, applet_aid, sizeof(applet_aid)) != 0) {
            return -1;
        }
        modem->applet_selected = MM_TRUE;
        append_status_9000(hex_out, hex_len);
        return 0;
    }

    if (!modem->applet_selected || cla != IOTSAFE_CLASS) {
        return -1;
    }

    if (ins == IOTSAFE_INS_GETRESPONSE) {
        append_status_9000(hex_out, hex_len);
        return 0;
    }

    if (ins == IOTSAFE_INS_GETRANDOM) {
#ifdef M33MU_HAS_WOLFSSL
        mm_u8 rnd[255];
        if (!ensure_rng(modem) || lc == 0u || body_len != 0u ||
            wc_RNG_GenerateBlock(&modem->rng, rnd, lc) != 0) {
            return -1;
        }
        if (hex_cap < (size_t)lc * 2u + 5u) {
            return -1;
        }
        bytes_to_hex(rnd, lc, hex_out);
        *hex_len = (size_t)lc * 2u;
        append_status_9000(hex_out, hex_len);
        return 0;
#else
        return -1;
#endif
    }

    if (ins == IOTSAFE_INS_GETDATA) {
        size_t id_len = 0;
        const mm_u8 *id_val;
        struct mm_iotsafe_file_slot *file;
        mm_u8 resp[8];
        if (p1 != IOTSAFE_GETDATA_FILE) {
            return -1;
        }
        id_val = find_tlv_value(body, body_len, IOTSAFE_TAG_FILE_ID, &id_len);
        if (id_val == 0 || id_len != 2u) {
            return -1;
        }
        file = find_file_slot(modem, read_slot_id16(id_val), MM_FALSE);
        if (file == 0) {
            return -1;
        }
        /* IoTSAFE GETDATA(C3): file-id TLV (echoed wire bytes) followed by
         * the file-size TLV (tag 0x20). wolfSSL's GetCert parser walks the
         * TLV stream to find the size descriptor. */
        resp[0] = IOTSAFE_TAG_FILE_ID;
        resp[1] = 0x02u;
        resp[2] = id_val[0];
        resp[3] = id_val[1];
        resp[4] = 0x20u;
        resp[5] = 0x02u;
        resp[6] = (mm_u8)((file->len >> 8) & 0xFFu);
        resp[7] = (mm_u8)(file->len & 0xFFu);
        bytes_to_hex(resp, sizeof(resp), hex_out);
        *hex_len = sizeof(resp) * 2u;
        append_status_9000(hex_out, hex_len);
        return 0;
    }

    if (ins == IOTSAFE_INS_READ_FILE) {
        size_t id_len = 0;
        const mm_u8 *id_val;
        struct mm_iotsafe_file_slot *file;
        mm_u16 off;
        size_t avail;
        id_val = find_tlv_value(body, body_len, IOTSAFE_TAG_FILE_ID, &id_len);
        if (id_val == 0 || id_len != 2u) {
            return -1;
        }
        file = find_file_slot(modem, read_slot_id16(id_val), MM_FALSE);
        if (file == 0) {
            return -1;
        }
        off = (mm_u16)(((mm_u16)p1 << 8) | p2);
        if (off > file->len) {
            return -1;
        }
        avail = (size_t)(file->len - off);
        if (avail > MM_IOTSAFE_READ_FILE_CHUNK_MAX) {
            avail = MM_IOTSAFE_READ_FILE_CHUNK_MAX;
        }
        if (hex_cap < avail * 2u + 5u) {
            return -1;
        }
        bytes_to_hex(&file->data[off], avail, hex_out);
        *hex_len = avail * 2u;
        append_status_9000(hex_out, hex_len);
        return 0;
    }

    if (ins == IOTSAFE_INS_GEN_KEYPAIR) {
#ifdef M33MU_HAS_WOLFSSL
        size_t id_len = 0;
        const mm_u8 *id_val;
        struct mm_iotsafe_key_slot *slot;
        ecc_key key;
        mm_u8 resp[80];
        size_t resp_len = 0;
        id_val = find_tlv_value(body, body_len, IOTSAFE_TAG_PRIVKEY_ID, &id_len);
        if (id_val == 0 || id_len != 2u) {
            return -1;
        }
        if (!ensure_rng(modem)) {
            return -1;
        }
        slot = find_key_slot(modem, read_slot_id16(id_val), MM_TRUE);
        if (slot == 0) {
            return -1;
        }
        memset(&key, 0, sizeof(key));
        if (wc_ecc_init(&key) != 0 ||
            wc_ecc_make_key_ex(&modem->rng, 32, &key, ECC_SECP256R1) != 0 ||
            !key_slot_store_from_ecc(slot, &key, MM_TRUE)) {
            wc_ecc_free(&key);
            return -1;
        }
        wc_ecc_free(&key);
        build_pubkey_tlv_from_slot(slot, resp, &resp_len);
        bytes_to_hex(resp, resp_len, hex_out);
        *hex_len = resp_len * 2u;
        append_status_9000(hex_out, hex_len);
        return 0;
#else
        return -1;
#endif
    }

    if (ins == IOTSAFE_INS_READ_KEY) {
        size_t id_len = 0;
        const mm_u8 *id_val;
        struct mm_iotsafe_key_slot *slot;
        mm_u8 resp[80];
        size_t resp_len = 0;
        id_val = find_tlv_value(body, body_len, IOTSAFE_TAG_PUBKEY_ID, &id_len);
        if (id_val == 0 || id_len != 2u) {
            return -1;
        }
        slot = find_key_slot(modem, read_slot_id16(id_val), MM_FALSE);
        if (slot == 0 || !slot->has_public) {
            return -1;
        }
        build_pubkey_tlv_from_slot(slot, resp, &resp_len);
        bytes_to_hex(resp, resp_len, hex_out);
        *hex_len = resp_len * 2u;
        append_status_9000(hex_out, hex_len);
        return 0;
    }

    if (ins == IOTSAFE_INS_PUT_PUBLIC_INIT) {
        if (p1 == 0u) {
            size_t id_len = 0;
            const mm_u8 *id_val;
            id_val = find_tlv_value(body, body_len, IOTSAFE_TAG_PUBKEY_ID, &id_len);
            if (id_val == 0 || id_len != 2u) {
                return -1;
            }
            modem->put_pub_key_id = read_slot_id16(id_val);
            modem->put_pub_active = MM_TRUE;
        } else if (p1 == 1u) {
            modem->put_pub_active = MM_FALSE;
            modem->put_pub_key_id = 0;
        } else {
            return -1;
        }
        *mode_out = MM_IOTSAFE_APDU_OK_ASYNC;
        modem->pending_ok_polls++;
        return 0;
    }

    if (ins == IOTSAFE_INS_PUT_PUBLIC_UPDATE) {
#ifdef M33MU_HAS_WOLFSSL
        size_t field_len = 0;
        const mm_u8 *field;
        size_t inner_len = 0;
        const mm_u8 *inner;
        size_t xy_len = 0;
        const mm_u8 *xy;
        struct mm_iotsafe_key_slot *slot;
        if (!modem->put_pub_active) {
            return -1;
        }
        field = find_tlv_value(body, body_len, IOTSAFE_TAG_ECC_KEY_FIELD, &field_len);
        if (field == 0) {
            return -1;
        }
        xy = find_tlv_value(field, field_len, IOTSAFE_TAG_ECC_KEY_XY, &xy_len);
        if (xy == 0) {
            inner = find_tlv_value(field, field_len, IOTSAFE_TAG_ECC_KEY_TYPE, &inner_len);
            if (inner != 0) {
                xy = find_tlv_value(inner, inner_len, IOTSAFE_TAG_ECC_KEY_XY, &xy_len);
            }
        }
        if (xy == 0 || xy_len != 65u || xy[0] != 0x04u) {
            return -1;
        }
        slot = find_key_slot(modem, modem->put_pub_key_id, MM_TRUE);
        if (slot == 0) {
            return -1;
        }
        memcpy(slot->pub, xy, 65u);
        slot->has_public = 1u;
        append_status_9000(hex_out, hex_len);
        return 0;
#else
        return -1;
#endif
    }

    if (ins == IOTSAFE_INS_SIGN_INIT) {
        if (p1 == 0u) {
            size_t id_len = 0;
            const mm_u8 *id_val;
            id_val = find_tlv_value(body, body_len, IOTSAFE_TAG_PRIVKEY_ID, &id_len);
            if (id_val == 0 || id_len != 2u) {
                return -1;
            }
            modem->sign_key_id = read_slot_id16(id_val);
            modem->sign_active = MM_TRUE;
        } else if (p1 == 1u) {
            modem->sign_active = MM_FALSE;
            modem->sign_key_id = 0;
        } else {
            return -1;
        }
        *mode_out = MM_IOTSAFE_APDU_OK_ASYNC;
        modem->pending_ok_polls++;
        return 0;
    }

    if (ins == IOTSAFE_INS_SIGN_UPDATE) {
#ifdef M33MU_HAS_WOLFSSL
        size_t hash_len = 0;
        const mm_u8 *hash_val;
        struct mm_iotsafe_key_slot *slot;
        ecc_key key;
        mm_u8 sig_der[80];
        mm_u8 rs[64];
        mm_u8 r_raw[32];
        mm_u8 s_raw[32];
        word32 sig_der_len = sizeof(sig_der);
        word32 r_len = 32u;
        word32 s_len = 32u;
        mm_u8 resp[70];
        if (!modem->sign_active) {
            return -1;
        }
        hash_val = find_tlv_value(body, body_len, IOTSAFE_TAG_HASH_FIELD, &hash_len);
        if (hash_val == 0) {
            return -1;
        }
        slot = find_key_slot(modem, modem->sign_key_id, MM_FALSE);
        if (slot == 0 || !slot->has_private) {
            return -1;
        }
        memset(&key, 0, sizeof(key));
        if (!ensure_rng(modem)) {
            return -1;
        }
        if (wc_ecc_init(&key) != 0) {
            return -1;
        }
        if (import_private_slot(slot, &key) != 0) {
            wc_ecc_free(&key);
            return -1;
        }
        if (wc_ecc_sign_hash(hash_val, (word32)hash_len, sig_der, &sig_der_len,
                             &modem->rng, &key) != 0) {
            wc_ecc_free(&key);
            return -1;
        }
        memset(rs, 0, sizeof(rs));
        memset(r_raw, 0, sizeof(r_raw));
        memset(s_raw, 0, sizeof(s_raw));
        if (wc_ecc_sig_to_rs(sig_der, sig_der_len, r_raw, &r_len, s_raw, &s_len) != 0 ||
            r_len == 0u || r_len > 32u || s_len == 0u || s_len > 32u) {
            wc_ecc_free(&key);
            return -1;
        }
        memcpy(rs + (32u - r_len), r_raw, r_len);
        memcpy(rs + 32u + (32u - s_len), s_raw, s_len);
        wc_ecc_free(&key);
        resp[0] = IOTSAFE_TAG_SIGNATURE_FIELD;
        resp[1] = 0x00u;
        resp[2] = 0x40u;
        memcpy(&resp[3], rs, 64u);
        bytes_to_hex(resp, 67u, hex_out);
        *hex_len = 134u;
        append_status_9000(hex_out, hex_len);
        return 0;
#else
        return -1;
#endif
    }

    if (ins == IOTSAFE_INS_VERIFY_INIT) {
        if (p1 == 0u) {
            size_t id_len = 0;
            const mm_u8 *id_val;
            id_val = find_tlv_value(body, body_len, IOTSAFE_TAG_PUBKEY_ID, &id_len);
            if (id_val == 0 || id_len != 2u) {
                return -1;
            }
            modem->verify_key_id = read_slot_id16(id_val);
            modem->verify_active = MM_TRUE;
        } else if (p1 == 1u) {
            modem->verify_active = MM_FALSE;
            modem->verify_key_id = 0;
        } else {
            return -1;
        }
        *mode_out = MM_IOTSAFE_APDU_OK_ASYNC;
        modem->pending_ok_polls++;
        return 0;
    }

    if (ins == IOTSAFE_INS_VERIFY_UPDATE) {
#ifdef M33MU_HAS_WOLFSSL
        size_t hash_len = 0;
        size_t sig_len = 0;
        const mm_u8 *hash_val;
        const mm_u8 *sig_val;
        struct mm_iotsafe_key_slot *slot;
        ecc_key key;
        mm_u8 sig_der[80];
        word32 sig_der_len = sizeof(sig_der);
        int verified = 0;
        if (!modem->verify_active) {
            return -1;
        }
        hash_val = find_tlv_value(body, body_len, IOTSAFE_TAG_HASH_FIELD, &hash_len);
        sig_val = find_tlv_value(body, body_len, IOTSAFE_TAG_SIGNATURE_FIELD, &sig_len);
        if (hash_val == 0 || sig_val == 0 || sig_len != 64u) {
            return -1;
        }
        slot = find_key_slot(modem, modem->verify_key_id, MM_FALSE);
        if (slot == 0 || !slot->has_public) {
            return -1;
        }
        if (wc_ecc_rs_raw_to_sig(sig_val, 32u, sig_val + 32u, 32u,
                                 sig_der, &sig_der_len) != 0) {
            return -1;
        }
        memset(&key, 0, sizeof(key));
        if (wc_ecc_init(&key) != 0 || import_public_slot(slot, &key) != 0 ||
            wc_ecc_verify_hash(sig_der, sig_der_len, hash_val, (word32)hash_len,
                               &verified, &key) != 0) {
            wc_ecc_free(&key);
            return -1;
        }
        wc_ecc_free(&key);
        if (verified) {
            append_status_9000(hex_out, hex_len);
        } else {
            memcpy(hex_out, "6D01", 4u);
            *hex_len = 4u;
            hex_out[*hex_len] = '\0';
        }
        return 0;
#else
        return -1;
#endif
    }

    if (ins == IOTSAFE_INS_COMPUTE_DH) {
#ifdef M33MU_HAS_WOLFSSL
        size_t priv_len = 0;
        size_t pub_len = 0;
        const mm_u8 *priv_val;
        const mm_u8 *pub_val;
        struct mm_iotsafe_key_slot *priv_slot;
        struct mm_iotsafe_key_slot *pub_slot;
        ecc_key priv_key;
        ecc_key pub_key;
        mm_u8 secret[80];
        word32 secret_len = sizeof(secret);
        priv_val = find_tlv_value(body, body_len, IOTSAFE_TAG_PRIVKEY_ID, &priv_len);
        pub_val = find_tlv_value(body, body_len, IOTSAFE_TAG_PUBKEY_ID, &pub_len);
        if (priv_val == 0 || pub_val == 0 || priv_len != 2u || pub_len != 2u) {
            return -1;
        }
        priv_slot = find_key_slot(modem, read_slot_id16(priv_val), MM_FALSE);
        pub_slot = find_key_slot(modem, read_slot_id16(pub_val), MM_FALSE);
        if (priv_slot == 0 || pub_slot == 0 || !priv_slot->has_private || !pub_slot->has_public) {
            return -1;
        }
        memset(&priv_key, 0, sizeof(priv_key));
        memset(&pub_key, 0, sizeof(pub_key));
        if (wc_ecc_init(&priv_key) != 0 || wc_ecc_init(&pub_key) != 0 ||
            import_private_slot(priv_slot, &priv_key) != 0 ||
            import_public_slot(pub_slot, &pub_key) != 0 ||
            wc_ecc_shared_secret(&priv_key, &pub_key, secret, &secret_len) != 0) {
            wc_ecc_free(&priv_key);
            wc_ecc_free(&pub_key);
            return -1;
        }
        wc_ecc_free(&priv_key);
        wc_ecc_free(&pub_key);
        bytes_to_hex(secret, secret_len, hex_out);
        *hex_len = secret_len * 2u;
        append_status_9000(hex_out, hex_len);
        return 0;
#else
        return -1;
#endif
    }

    if (ins == IOTSAFE_INS_HKDF_EXTRACT) {
#ifdef M33MU_HAS_WOLFSSL
        size_t secret_len = 0;
        size_t salt_len = 0;
        size_t algo_len = 0;
        const mm_u8 *secret;
        const mm_u8 *salt;
        const mm_u8 *algo;
        mm_u8 prk[64];
        int hash_type;
        size_t prk_len;
        secret = find_tlv_value(body, body_len, IOTSAFE_TAG_SECRET, &secret_len);
        salt = find_tlv_value(body, body_len, IOTSAFE_TAG_SALT, &salt_len);
        algo = find_tlv_value(body, body_len, IOTSAFE_TAG_HASH_ALGO, &algo_len);
        if (secret == 0 || salt == 0 || algo == 0 || algo_len != 2u) {
            return -1;
        }
        hash_type = hash_type_from_iotsafe(read_be16(algo));
        if (hash_type < 0 || wc_HKDF_Extract(hash_type, salt, (word32)salt_len,
                                             secret, (word32)secret_len, prk) != 0) {
            return -1;
        }
        switch (hash_type) {
            case WC_SHA256: prk_len = 32u; break;
            case WC_SHA384: prk_len = 48u; break;
            case WC_SHA512: prk_len = 64u; break;
            default: return -1;
        }
        bytes_to_hex(prk, prk_len, hex_out);
        *hex_len = prk_len * 2u;
        append_status_9000(hex_out, hex_len);
        return 0;
#else
        return -1;
#endif
    }

    return -1;
}

static void queue_ok(struct mm_iotsafe_modem *modem)
{
    rx_fifo_write_str(modem, "\r\nOK\r\n");
}

static void queue_error(struct mm_iotsafe_modem *modem)
{
    rx_fifo_write_str(modem, "\r\nERROR\r\n");
}

static void queue_csim_reply(struct mm_iotsafe_modem *modem, const char *hex_payload)
{
    char line[4608];
    int n;
    size_t payload_len;
    payload_len = strlen(hex_payload);
    n = snprintf(line, sizeof(line), "\r\n+CSIM: %lu,\"%s\"\r\n\r\nOK\r\n",
                 (unsigned long)payload_len, hex_payload);
    if (n > 0 && (size_t)n < sizeof(line)) {
        rx_fifo_write_str(modem, line);
    } else {
        queue_error(modem);
    }
}

static void process_at_line(struct mm_iotsafe_modem *modem, const char *line)
{
    char cmd[MM_IOTSAFE_LINE_MAX];
    size_t len;
    size_t i;
    if (modem == 0 || line == 0) {
        return;
    }
    while (*line == ' ' || *line == '\t') {
        ++line;
    }
    len = strlen(line);
    while (len > 0u && (line[len - 1u] == '\r' || line[len - 1u] == '\n' ||
                        line[len - 1u] == ' ' || line[len - 1u] == '\t')) {
        --len;
    }
    if (len == 0u) {
        return;
    }
    if (len >= sizeof(cmd)) {
        queue_error(modem);
        return;
    }
    for (i = 0; i < len; ++i) {
        cmd[i] = (char)toupper((unsigned char)line[i]);
    }
    cmd[len] = '\0';

    if (modem->echo_enabled) {
        rx_fifo_write_str(modem, line);
        rx_fifo_write_str(modem, "\r\n");
    }

    if (strcmp(cmd, "AT") == 0) {
        if (modem->pending_ok_polls > 0) {
            modem->pending_ok_polls--;
        }
        queue_ok(modem);
        return;
    }
    if (strcmp(cmd, "ATE0") == 0) {
        modem->echo_enabled = MM_FALSE;
        queue_ok(modem);
        return;
    }
    if (strcmp(cmd, "ATE1") == 0) {
        modem->echo_enabled = MM_TRUE;
        queue_ok(modem);
        return;
    }
    if (strncmp(cmd, "AT+CSIM=", 8) == 0) {
        const char *p = line + 8;
        unsigned long declared_len;
        char *endp;
        const char *q0;
        const char *q1;
        mm_u8 apdu[512];
        size_t apdu_len = 0;
        char resp_hex[4096];
        size_t resp_hex_len = 0;
        enum mm_iotsafe_apdu_mode mode;
        while (*p == ' ' || *p == '\t') {
            ++p;
        }
        declared_len = strtoul(p, &endp, 10);
        if (endp == p) {
            queue_error(modem);
            return;
        }
        q0 = strchr(endp, '"');
        if (q0 == 0) {
            queue_error(modem);
            return;
        }
        q1 = strchr(q0 + 1, '"');
        if (q1 == 0 || (unsigned long)(q1 - (q0 + 1)) != declared_len) {
            queue_error(modem);
            return;
        }
        if (!hex_to_bytes(q0 + 1, (size_t)(q1 - (q0 + 1)), apdu, sizeof(apdu), &apdu_len)) {
            queue_error(modem);
            return;
        }
        if (process_apdu(modem, apdu, apdu_len, resp_hex, sizeof(resp_hex),
                         &resp_hex_len, &mode) != 0) {
            queue_error(modem);
            return;
        }
        if (mode == MM_IOTSAFE_APDU_OK_ASYNC) {
            queue_ok(modem);
        } else {
            (void)resp_hex_len;
            queue_csim_reply(modem, resp_hex);
        }
        return;
    }
    queue_error(modem);
}

static size_t iotsafe_uart_write_tx(void *opaque, const mm_u8 *data, size_t len)
{
    struct mm_iotsafe_modem *modem = (struct mm_iotsafe_modem *)opaque;
    size_t i;
    if (modem == 0 || data == 0) {
        return 0;
    }
    for (i = 0; i < len; ++i) {
        char c = (char)data[i];
        if (c == '\r' || c == '\n') {
            if (modem->line_len > 0u) {
                modem->line_buf[modem->line_len] = '\0';
                process_at_line(modem, modem->line_buf);
                modem->line_len = 0u;
            }
        } else if (modem->line_len + 1u < sizeof(modem->line_buf)) {
            modem->line_buf[modem->line_len++] = c;
        } else {
            modem->line_len = 0u;
            queue_error(modem);
        }
    }
    return len;
}

static mm_bool iotsafe_uart_read_rx(void *opaque, mm_u8 *byte_out)
{
    return rx_fifo_pop((struct mm_iotsafe_modem *)opaque, byte_out);
}

static void iotsafe_uart_close(void *opaque)
{
    (void)opaque;
}

mm_bool mm_iotsafe_uart_parse_spec(const char *spec,
                                   struct mm_iotsafe_uart_cfg *out)
{
    char tmp[512];
    char *tok;
    char *endp;
    unsigned long base;
    if (spec == 0 || out == 0) {
        return MM_FALSE;
    }
    memset(out, 0, sizeof(*out));
    snprintf(tmp, sizeof(tmp), "%s", spec);
    tok = strtok(tmp, ":");
    if (tok == 0) {
        return MM_FALSE;
    }
    base = strtoul(tok, &endp, 0);
    if (*endp != '\0' || base > 0xFFFFFFFFul) {
        return MM_FALSE;
    }
    out->base = (mm_u32)base;
    while ((tok = strtok(0, ":")) != 0) {
        if (strncmp(tok, "file=", 5) == 0) {
            snprintf(out->nv_path, sizeof(out->nv_path), "%s", tok + 5);
            out->has_nv_path = MM_TRUE;
        } else {
            return MM_FALSE;
        }
    }
    return MM_TRUE;
}

mm_bool mm_iotsafe_uart_register_cfg(const struct mm_iotsafe_uart_cfg *cfg)
{
    size_t i;
    struct mm_iotsafe_modem *modem = 0;
    char name[64];
    if (cfg == 0) {
        return MM_FALSE;
    }
#ifndef M33MU_HAS_WOLFSSL
    fprintf(stderr, "iotsafe-uart: wolfSSL support not built in\n");
    return MM_FALSE;
#endif
    for (i = 0; i < MM_IOTSAFE_UART_MAX_MODEMS; ++i) {
        if (g_iotsafe_modems[i].used && g_iotsafe_modems[i].base == cfg->base) {
            fprintf(stderr, "iotsafe-uart: UART 0x%08lx already attached\n",
                    (unsigned long)cfg->base);
            return MM_FALSE;
        }
        if (!g_iotsafe_modems[i].used && modem == 0) {
            modem = &g_iotsafe_modems[i];
        }
    }
    if (modem == 0) {
        fprintf(stderr, "iotsafe-uart: max modems reached\n");
        return MM_FALSE;
    }
    memset(modem, 0, sizeof(*modem));
    modem->used = MM_TRUE;
    modem->base = cfg->base;
    modem->has_nv_path = cfg->has_nv_path;
    if (cfg->has_nv_path) {
        snprintf(modem->nv_path, sizeof(modem->nv_path), "%s", cfg->nv_path);
    }
    load_or_init_nv(modem);
    iotsafe_modem_reset(modem);
    snprintf(name, sizeof(name), "iotsafe-uart@0x%08lx", (unsigned long)cfg->base);
    if (!mm_uart_backend_attach(cfg->base, name, &g_iotsafe_uart_ops, modem)) {
        modem->used = MM_FALSE;
        fprintf(stderr, "iotsafe-uart: failed to attach UART backend\n");
        return MM_FALSE;
    }
    fprintf(stderr, "[IOTSAFE-UART] Registered on UART 0x%08lx",
            (unsigned long)cfg->base);
    if (modem->has_nv_path) {
        fprintf(stderr, " file=%s", modem->nv_path);
    }
    fprintf(stderr, "\n");
    return MM_TRUE;
}

void mm_iotsafe_uart_reset_all(void)
{
    size_t i;
    for (i = 0; i < MM_IOTSAFE_UART_MAX_MODEMS; ++i) {
        if (g_iotsafe_modems[i].used) {
            iotsafe_modem_reset(&g_iotsafe_modems[i]);
        }
    }
}

void mm_iotsafe_uart_shutdown_all(void)
{
    size_t i;
    for (i = 0; i < MM_IOTSAFE_UART_MAX_MODEMS; ++i) {
        if (!g_iotsafe_modems[i].used) {
            continue;
        }
        sync_nv(&g_iotsafe_modems[i]);
#ifdef M33MU_HAS_WOLFSSL
        if (g_iotsafe_modems[i].rng_initialized) {
            wc_FreeRng(&g_iotsafe_modems[i].rng);
            g_iotsafe_modems[i].rng_initialized = MM_FALSE;
        }
#endif
        mm_uart_backend_detach(g_iotsafe_modems[i].base);
        memset(&g_iotsafe_modems[i], 0, sizeof(g_iotsafe_modems[i]));
    }
}
