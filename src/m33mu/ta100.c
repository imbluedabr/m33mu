/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "m33mu/ta100.h"
#include "m33mu/spi_bus.h"
#include "m33mu/gpio.h"

#ifdef M33MU_HAS_WOLFSSL
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#endif

#define TA100_MAX 4
#define TA100_CMD_MAX 512u
#define TA100_RSP_MAX 512u

#define TA100_NV_SIZE 4096u
#define TA100_CONFIG_ZONE_SIZE 128u
#define TA100_DATA_ZONE_SIZE 1024u
#define TA100_KEY_SLOTS 16
#define TA100_KEY_SLOT_SIZE 72u

#define TA100_CMD_INFO 0x30
#define TA100_CMD_READ 0x02
#define TA100_CMD_WRITE 0x12
#define TA100_CMD_LOCK 0x17
#define TA100_CMD_RANDOM 0x1B
#define TA100_CMD_NONCE 0x16
#define TA100_CMD_GENKEY 0x40
#define TA100_CMD_SIGN 0x41
#define TA100_CMD_SHA256 0x47
#define TA100_CMD_MAC 0x08

#define TA100_ZONE_CONFIG 0x00
#define TA100_ZONE_OTP 0x01
#define TA100_ZONE_DATA 0x02
#define TA100_ZONE_KEY 0x02

#define TA100_STATUS_SUCCESS 0x00
#define TA100_STATUS_CHECKMAC_FAILED 0x01
#define TA100_STATUS_PARSE_ERROR 0x03
#define TA100_STATUS_EXEC_ERROR 0x0F
#define TA100_STATUS_WAKE_OK 0x11
#define TA100_STATUS_CRC_ERROR 0xFF

enum ta100_state {
    TA100_RESET = 0,
    TA100_SLEEP,
    TA100_IDLE,
    TA100_BUSY,
    TA100_RESP_READY
};

struct mm_ta100 {
    int bus;
    mm_bool cs_valid;
    int cs_bank;
    int cs_pin;
    mm_u32 cs_mask;
    mm_u8 cs_level;
    mm_bool has_nv_path;
    char nv_path[256];
    mm_bool has_profile;
    char profile[64];
    mm_bool has_serial;
    char serial[32];
    enum ta100_state state;
    mm_u8 cmd_buf[TA100_CMD_MAX];
    mm_u32 cmd_len;
    mm_u8 rsp_buf[TA100_RSP_MAX];
    mm_u32 rsp_len;
    mm_u32 rsp_read;
    mm_u32 busy_cycles;
    mm_u8 *nv_data;
    mm_u32 nv_size;
    mm_bool nv_dirty;
    mm_bool config_locked;
    mm_bool data_locked;
    mm_u8 slot_locked[TA100_KEY_SLOTS];
#ifdef M33MU_HAS_WOLFSSL
    WC_RNG rng;
    mm_bool rng_initialized;
#endif
    mm_u8 temp_nonce[32];
    mm_bool temp_nonce_valid;
};

static struct mm_ta100 g_ta100[TA100_MAX];
static size_t g_ta100_count = 0;

static mm_bool ta100_trace_enabled(void)
{
    static mm_bool init = MM_FALSE;
    static mm_bool enabled = MM_FALSE;
    if (!init) {
        const char *env = getenv("M33MU_TA100_TRACE");
        enabled = (env != 0 && env[0] != '\0') ? MM_TRUE : MM_FALSE;
        init = MM_TRUE;
    }
    return enabled;
}

static mm_bool ta100_spi_trace_enabled(void)
{
    static mm_bool init = MM_FALSE;
    static mm_bool enabled = MM_FALSE;
    if (!init) {
        const char *env = getenv("M33MU_SPI_TRACE");
        enabled = (env != 0 && env[0] != '\0') ? MM_TRUE : MM_FALSE;
        init = MM_TRUE;
    }
    return enabled;
}

static mm_bool ta100_ecc_enabled(void)
{
    static mm_bool init = MM_FALSE;
    static mm_bool enabled = MM_FALSE;
    if (!init) {
        const char *env = getenv("M33MU_TA100_ECC");
        enabled = (env != 0 && env[0] != '\0') ? MM_TRUE : MM_FALSE;
        init = MM_TRUE;
    }
    return enabled;
}

static void ta100_trace_dump(const char *tag, const mm_u8 *buf, mm_u32 len)
{
    mm_u32 i;
    mm_u32 max_len = len;
    if (!ta100_trace_enabled()) {
        return;
    }
    if (buf == 0) {
        fprintf(stderr, "[TA100_TRACE] %s len=%lu (null)\n",
                tag, (unsigned long)len);
        return;
    }
    if (max_len > 256u) {
        max_len = 256u;
    }
    fprintf(stderr, "[TA100_TRACE] %s len=%lu\n", tag, (unsigned long)len);
    for (i = 0; i < max_len; i += 16u) {
        mm_u32 j;
        mm_u32 line_len = max_len - i;
        if (line_len > 16u) line_len = 16u;
        fprintf(stderr, "[TA100_TRACE]   %04lx:", (unsigned long)i);
        for (j = 0; j < line_len; ++j) {
            fprintf(stderr, " %02x", buf[i + j]);
        }
        fprintf(stderr, "\n");
    }
    if (max_len < len) {
        fprintf(stderr, "[TA100_TRACE]   ... (%lu bytes omitted)\n",
                (unsigned long)(len - max_len));
    }
}

static mm_u8 ta100_sample_cs(struct mm_ta100 *ta)
{
    mm_u8 level = 1u;
    mm_u32 moder;
    mm_u32 mode_bits;
    if (ta == 0 || !ta->cs_valid) {
        return 0u;
    }
    if (!mm_gpio_bank_reader_present()) {
        return 1u;
    }
    moder = mm_gpio_bank_read_moder(ta->cs_bank);
    mode_bits = (moder >> (ta->cs_pin * 2)) & 0x3u;
    if (mode_bits != 1u) {
        level = 1u;
    } else {
        level = (mm_gpio_bank_read(ta->cs_bank) & ta->cs_mask) ? 1u : 0u;
    }
    return level;
}

static mm_u16 ta100_calculate_crc(const mm_u8 *data, mm_u32 len)
{
    mm_u32 i;
    mm_u16 crc = 0;
    const mm_u16 polynom = 0x8005;
    mm_u8 bit;
    
    for (i = 0; i < len; i++) {
        mm_u8 byte = data[i];
        mm_u8 j;
        for (j = 0; j < 8; j++) {
            bit = (crc >> 15) ^ ((byte >> (7 - j)) & 1);
            crc <<= 1;
            if (bit) {
                crc ^= polynom;
            }
        }
    }
    return crc;
}

static mm_bool ta100_verify_crc(const mm_u8 *packet, mm_u32 len)
{
    mm_u16 packet_crc;
    mm_u16 calc_crc;
    if (len < 2) {
        return MM_FALSE;
    }
    packet_crc = ((mm_u16)packet[len - 2] << 8) | packet[len - 1];
    calc_crc = ta100_calculate_crc(packet, len - 2);
    return (packet_crc == calc_crc) ? MM_TRUE : MM_FALSE;
}

static void ta100_init_nv_layout(struct mm_ta100 *ta)
{
    mm_u32 i;
    if (ta == 0 || ta->nv_data == 0) {
        return;
    }
    
    memset(ta->nv_data, 0x00, TA100_CONFIG_ZONE_SIZE);
    ta->nv_data[0] = 0x01;
    ta->nv_data[1] = 0x23;
    ta->nv_data[2] = 0x45;
    ta->nv_data[3] = 0x67;
    ta->nv_data[4] = 0x00;
    ta->nv_data[5] = 0x00;
    ta->nv_data[6] = 0x50;
    ta->nv_data[7] = 0x00;
    ta->nv_data[12] = 0xC0;
    ta->nv_data[13] = 0x00;
    ta->nv_data[14] = 0x55;
    ta->nv_data[15] = 0x00;
    ta->nv_data[16] = 0x83;
    ta->nv_data[17] = 0x20;
    ta->nv_data[18] = 0x87;
    ta->nv_data[87] = 0x55;
    
    for (i = TA100_CONFIG_ZONE_SIZE; i < ta->nv_size; i++) {
        ta->nv_data[i] = 0xFF;
    }
    
    ta->config_locked = MM_FALSE;
    ta->data_locked = MM_FALSE;
    memset(ta->slot_locked, 0, sizeof(ta->slot_locked));
}

static mm_u32 ta100_get_zone_offset(mm_u8 zone, mm_u16 addr)
{
    mm_u32 offset;
    
    if (zone == TA100_ZONE_CONFIG) {
        offset = (mm_u32)addr;
        if (offset >= TA100_CONFIG_ZONE_SIZE) {
            offset = TA100_CONFIG_ZONE_SIZE - 1;
        }
    } else if (zone == TA100_ZONE_DATA || zone == TA100_ZONE_KEY) {
        offset = TA100_CONFIG_ZONE_SIZE + (mm_u32)addr;
        if (offset >= TA100_NV_SIZE) {
            offset = TA100_NV_SIZE - 1;
        }
    } else {
        offset = 0;
    }
    
    return offset;
}

static void ta100_cmd_read(struct mm_ta100 *ta, const mm_u8 *cmd, mm_u32 cmd_len)
{
    mm_u8 zone;
    mm_u16 addr;
    mm_u8 count;
    mm_u32 offset;
    mm_u32 i;
    mm_u16 crc;
    
    if (cmd_len < 7) {
        ta->rsp_buf[0] = TA100_STATUS_PARSE_ERROR;
        ta->rsp_len = 1;
        return;
    }
    
    zone = cmd[1] & 0x03;
    addr = ((mm_u16)cmd[2] << 8) | cmd[3];
    count = cmd[4];
    
    if (count == 0 || count > 32) {
        count = 4;
    }
    
    offset = ta100_get_zone_offset(zone, addr);
    
    ta->rsp_buf[0] = TA100_STATUS_SUCCESS;
    for (i = 0; i < count && (offset + i) < ta->nv_size; i++) {
        ta->rsp_buf[1 + i] = ta->nv_data[offset + i];
    }
    ta->rsp_len = 1 + count;
    crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
}

static void ta100_cmd_write(struct mm_ta100 *ta, const mm_u8 *cmd, mm_u32 cmd_len)
{
    mm_u8 zone;
    mm_u16 addr;
    mm_u8 count;
    mm_u32 offset;
    mm_u32 i;
    mm_u16 crc;
    
    if (cmd_len < 8) {
        ta->rsp_buf[0] = TA100_STATUS_PARSE_ERROR;
        ta->rsp_len = 1;
        return;
    }
    
    zone = cmd[1] & 0x03;
    addr = ((mm_u16)cmd[2] << 8) | cmd[3];
    count = cmd[4];
    
    if (zone == TA100_ZONE_CONFIG && ta->config_locked) {
        ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
        ta->rsp_len = 1;
        return;
    }
    
    if ((zone == TA100_ZONE_DATA || zone == TA100_ZONE_KEY) && ta->data_locked) {
        ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
        ta->rsp_len = 1;
        return;
    }
    
    if (count == 0 || count > 32) {
        count = 4;
    }
    
    if (cmd_len < (mm_u32)(7 + count)) {
        ta->rsp_buf[0] = TA100_STATUS_PARSE_ERROR;
        ta->rsp_len = 1;
        return;
    }
    
    offset = ta100_get_zone_offset(zone, addr);
    
    for (i = 0; i < count && (offset + i) < ta->nv_size; i++) {
        ta->nv_data[offset + i] = cmd[5 + i];
    }
    ta->nv_dirty = MM_TRUE;
    
    ta->rsp_buf[0] = TA100_STATUS_SUCCESS;
    ta->rsp_len = 1;
    crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
}

static void ta100_cmd_lock(struct mm_ta100 *ta, const mm_u8 *cmd, mm_u32 cmd_len)
{
    mm_u8 zone;
    mm_u16 crc;
    
    if (cmd_len < 7) {
        ta->rsp_buf[0] = TA100_STATUS_PARSE_ERROR;
        ta->rsp_len = 1;
        return;
    }
    
    zone = cmd[1] & 0x03;
    
    if (zone == TA100_ZONE_CONFIG) {
        ta->config_locked = MM_TRUE;
    } else if (zone == TA100_ZONE_DATA || zone == TA100_ZONE_KEY) {
        ta->data_locked = MM_TRUE;
    }
    
    ta->rsp_buf[0] = TA100_STATUS_SUCCESS;
    ta->rsp_len = 1;
    crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
}

#ifdef M33MU_HAS_WOLFSSL
static void ta100_cmd_random(struct mm_ta100 *ta, const mm_u8 *cmd, mm_u32 cmd_len)
{
    mm_u16 crc;
    mm_u8 count = 32;
    int ret;
    
    (void)cmd;
    
    if (cmd_len < 5) {
        ta->rsp_buf[0] = TA100_STATUS_PARSE_ERROR;
        ta->rsp_len = 1;
        return;
    }
    
    if (!ta->rng_initialized) {
        ret = wc_InitRng(&ta->rng);
        if (ret != 0) {
            ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
            ta->rsp_len = 1;
            crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
            ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
            ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
            return;
        }
        ta->rng_initialized = MM_TRUE;
    }
    
    ret = wc_RNG_GenerateBlock(&ta->rng, &ta->rsp_buf[1], count);
    if (ret != 0) {
        ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
        ta->rsp_len = 1;
    } else {
        ta->rsp_buf[0] = TA100_STATUS_SUCCESS;
        ta->rsp_len = 1 + count;
    }
    
    crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
}

static void ta100_cmd_nonce(struct mm_ta100 *ta, const mm_u8 *cmd, mm_u32 cmd_len)
{
    mm_u16 crc;
    mm_u8 mode;
    
    if (cmd_len < 5) {
        ta->rsp_buf[0] = TA100_STATUS_PARSE_ERROR;
        ta->rsp_len = 1;
        return;
    }
    
    mode = cmd[1];
    
    if (mode == 0x00) {
        if (cmd_len < 27) {
            ta->rsp_buf[0] = TA100_STATUS_PARSE_ERROR;
            ta->rsp_len = 1;
            return;
        }
        memcpy(ta->temp_nonce, &cmd[5], 20);
        memset(ta->temp_nonce + 20, 0, 12);
        ta->temp_nonce_valid = MM_TRUE;
        ta->rsp_buf[0] = TA100_STATUS_SUCCESS;
        ta->rsp_len = 1;
    } else if (mode == 0x03) {
        if (!ta->rng_initialized) {
            int ret = wc_InitRng(&ta->rng);
            if (ret != 0) {
                ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
                ta->rsp_len = 1;
                crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
                ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
                ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
                return;
            }
            ta->rng_initialized = MM_TRUE;
        }
        wc_RNG_GenerateBlock(&ta->rng, ta->temp_nonce, 32);
        ta->temp_nonce_valid = MM_TRUE;
        ta->rsp_buf[0] = TA100_STATUS_SUCCESS;
        ta->rsp_len = 1;
    } else {
        ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
        ta->rsp_len = 1;
    }
    
    crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
}

static mm_u32 ta100_get_slot_offset(mm_u8 slot_id)
{
    mm_u32 offset = TA100_CONFIG_ZONE_SIZE + (slot_id * TA100_KEY_SLOT_SIZE);
    return offset;
}

static void ta100_cmd_genkey(struct mm_ta100 *ta, const mm_u8 *cmd, mm_u32 cmd_len)
{
    mm_u16 crc;
    mm_u8 mode;
    mm_u8 slot_id;
#ifdef M33MU_HAS_WOLFSSL
    ecc_key key;
    int ret;
    mm_u32 x_len = 32;
    mm_u32 y_len = 32;
#endif
    mm_u32 offset;
    
    if (cmd_len < 6) {
        ta->rsp_buf[0] = TA100_STATUS_PARSE_ERROR;
        ta->rsp_len = 1;
        return;
    }
    
    mode = cmd[1];
    slot_id = ((mm_u16)cmd[2] << 8) | cmd[3];
    
    if (slot_id >= TA100_KEY_SLOTS) {
        ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
    (void)mode;
        ta->rsp_len = 1;
        crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
        return;
    }
    
    if (ta->data_locked || ta->slot_locked[slot_id]) {
        ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
        ta->rsp_len = 1;
        crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
        return;
    }
    
#ifdef M33MU_HAS_WOLFSSL
    if (!ta100_ecc_enabled()) {
        mm_u8 *priv;
        mm_u8 *pub_x;
        mm_u8 *pub_y;
        if (ta->nv_data == 0) {
            ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
            ta->rsp_len = 1;
            crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
            ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
            ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
            return;
        }
        if (!ta->rng_initialized) {
            ret = wc_InitRng(&ta->rng);
            if (ret != 0) {
                ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
                ta->rsp_len = 1;
                crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
                ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
                ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
                return;
            }
            ta->rng_initialized = MM_TRUE;
        }
        offset = ta100_get_slot_offset(slot_id);
        priv = &ta->nv_data[offset];
        pub_y = &ta->nv_data[offset + 4];
        pub_x = &ta->nv_data[offset + 36];
        wc_RNG_GenerateBlock(&ta->rng, priv, 32);
        wc_RNG_GenerateBlock(&ta->rng, pub_x, 32);
        wc_RNG_GenerateBlock(&ta->rng, pub_y, 32);
        ta->nv_dirty = MM_TRUE;
        memcpy(&ta->rsp_buf[1], pub_x, 32);
        memcpy(&ta->rsp_buf[33], pub_y, 32);
        ta->rsp_buf[0] = TA100_STATUS_SUCCESS;
        ta->rsp_len = 65;
        crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
        return;
    }
#endif

#ifdef M33MU_HAS_WOLFSSL
    if (!ta->rng_initialized) {
        ret = wc_InitRng(&ta->rng);
        if (ret != 0) {
            ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
            ta->rsp_len = 1;
            crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
            ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
            ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
            return;
        }
        ta->rng_initialized = MM_TRUE;
    }
    
    wc_ecc_init(&key);
    ret = wc_ecc_make_key(&ta->rng, 32, &key);
    if (ret != 0) {
        wc_ecc_free(&key);
        ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
        ta->rsp_len = 1;
        crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
        return;
    }
    
    offset = ta100_get_slot_offset(slot_id);
    
    wc_ecc_export_public_raw(&key, &ta->nv_data[offset + 36], &x_len,
                             &ta->nv_data[offset + 4], &y_len);
    wc_ecc_export_private_only(&key, &ta->nv_data[offset], &x_len);
    
    ta->nv_dirty = MM_TRUE;
    
    memcpy(&ta->rsp_buf[1], &ta->nv_data[offset + 36], 32);
    memcpy(&ta->rsp_buf[33], &ta->nv_data[offset + 4], 32);
    
    wc_ecc_free(&key);
    
    ta->rsp_buf[0] = TA100_STATUS_SUCCESS;
    ta->rsp_len = 65;
    crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
#endif
}

static void ta100_cmd_sign(struct mm_ta100 *ta, const mm_u8 *cmd, mm_u32 cmd_len)
{
    mm_u16 crc;
    mm_u8 mode;
    mm_u8 slot_id;
#ifdef M33MU_HAS_WOLFSSL
    ecc_key key;
    int ret;
    mm_u8 hash[32];
    mm_u8 sig[64];
    word32 sig_len = sizeof(sig);
#endif
    mm_u32 offset;
#ifdef M33MU_HAS_WOLFSSL
    wc_Sha256 sha;
#endif
    
    if (cmd_len < 6) {
        ta->rsp_buf[0] = TA100_STATUS_PARSE_ERROR;
        ta->rsp_len = 1;
        return;
    }
    
    (void)mode;
    mode = cmd[1];
    slot_id = ((mm_u16)cmd[2] << 8) | cmd[3];
    
    if (slot_id >= TA100_KEY_SLOTS) {
        ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
        ta->rsp_len = 1;
        crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
        return;
    }
    
    if (!ta->temp_nonce_valid) {
        ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
        ta->rsp_len = 1;
        crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
        return;
    }
    
#ifdef M33MU_HAS_WOLFSSL
    if (!ta100_ecc_enabled()) {
        mm_u8 digest[32];
        wc_InitSha256(&sha);
        wc_Sha256Update(&sha, ta->temp_nonce, 32);
        if (ta->nv_data != 0) {
            offset = ta100_get_slot_offset(slot_id);
            wc_Sha256Update(&sha, &ta->nv_data[offset], 32);
        }
        wc_Sha256Final(&sha, digest);
        wc_Sha256Free(&sha);
        memset(sig, 0, sizeof(sig));
        memcpy(sig, digest, 32);
        memcpy(sig + 32, digest, 32);
        ta->rsp_buf[0] = TA100_STATUS_SUCCESS;
        memcpy(&ta->rsp_buf[1], sig, sizeof(sig));
        ta->rsp_len = 1 + (mm_u32)sizeof(sig);
        crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
        return;
    }

    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, ta->temp_nonce, 32);
    wc_Sha256Final(&sha, hash);
    wc_Sha256Free(&sha);
    
    offset = ta100_get_slot_offset(slot_id);
    
    wc_ecc_init(&key);
    
    {
        mm_u8 pubkey[64];
        memcpy(pubkey, &ta->nv_data[offset + 36], 32);
        memcpy(pubkey + 32, &ta->nv_data[offset + 4], 32);
        ret = wc_ecc_import_private_key(&ta->nv_data[offset], 32,
                                         pubkey, 64,
                                         &key);
    }
    
    if (ret != 0) {
        wc_ecc_free(&key);
        ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
        ta->rsp_len = 1;
        crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
        return;
    }
    
    if (!ta->rng_initialized) {
        ret = wc_InitRng(&ta->rng);
        if (ret != 0) {
            wc_ecc_free(&key);
            ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
            ta->rsp_len = 1;
            crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
            ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
            ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
            return;
        }
        ta->rng_initialized = MM_TRUE;
    }
    
    ret = wc_ecc_sign_hash(hash, 32, sig, &sig_len, &ta->rng, &key);
    
    wc_ecc_free(&key);
    
    if (ret != 0) {
        ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
        ta->rsp_len = 1;
        crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
        return;
    }
    
    ta->rsp_buf[0] = TA100_STATUS_SUCCESS;
    memcpy(&ta->rsp_buf[1], sig, sig_len);
    ta->rsp_len = 1 + sig_len;
    crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
#endif
}

static void ta100_cmd_sha256(struct mm_ta100 *ta, const mm_u8 *cmd, mm_u32 cmd_len)
{
    mm_u16 crc;
    wc_Sha256 sha;
    mm_u8 hash[32];
    mm_u32 data_len;
    
    if (cmd_len < 7) {
        ta->rsp_buf[0] = TA100_STATUS_PARSE_ERROR;
        ta->rsp_len = 1;
        return;
    }
    
    data_len = cmd[4];
    
    if (cmd_len < (7 + data_len)) {
        ta->rsp_buf[0] = TA100_STATUS_PARSE_ERROR;
        ta->rsp_len = 1;
        return;
    }
    
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, &cmd[5], data_len);
    wc_Sha256Final(&sha, hash);
    wc_Sha256Free(&sha);
    
    ta->rsp_buf[0] = TA100_STATUS_SUCCESS;
    memcpy(&ta->rsp_buf[1], hash, 32);
    ta->rsp_len = 33;
    crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
}
#endif

static void ta100_cmd_info(struct mm_ta100 *ta)
{
    mm_u16 crc;
    
    ta->rsp_buf[0] = TA100_STATUS_SUCCESS;
    ta->rsp_buf[1] = 0x00;
    ta->rsp_buf[2] = 0x00;
    ta->rsp_buf[3] = 0x04;
    ta->rsp_buf[4] = 0x11;
    ta->rsp_len = 5;
    crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
}

static void ta100_process_command(struct mm_ta100 *ta)
{
    mm_u8 opcode;
    mm_u16 crc;
    
    if (ta == 0 || ta->cmd_len == 0) {
        return;
    }
    
    ta->rsp_len = 0;
    ta->rsp_read = 0;
    ta->busy_cycles = 100;
    
    fprintf(stderr, "[TA100_DEBUG] Processing command, len=%u bytes\n", (unsigned)ta->cmd_len);
    
    if (ta100_trace_enabled()) {
        fprintf(stderr, "[TA100_TRACE] Processing command, len=%lu\n",
                (unsigned long)ta->cmd_len);
        ta100_trace_dump("cmd", ta->cmd_buf, ta->cmd_len);
    }
    
    if (ta->cmd_len < 1) {
        ta->rsp_buf[0] = TA100_STATUS_PARSE_ERROR;
        ta->rsp_len = 1;
        ta->state = TA100_RESP_READY;
        return;
    }
    
    opcode = ta->cmd_buf[0];
    
    if (ta->cmd_len >= 3 && !ta100_verify_crc(ta->cmd_buf, ta->cmd_len)) {
        if (ta100_trace_enabled()) {
            fprintf(stderr, "[TA100_TRACE] CRC error\n");
        }
        ta->rsp_buf[0] = TA100_STATUS_CRC_ERROR;
        ta->rsp_len = 1;
        ta->state = TA100_RESP_READY;
        return;
    }
    
    switch (opcode) {
    case TA100_CMD_INFO:
        ta100_cmd_info(ta);
        break;
    case TA100_CMD_READ:
        ta100_cmd_read(ta, ta->cmd_buf, ta->cmd_len);
        break;
    case TA100_CMD_WRITE:
        ta100_cmd_write(ta, ta->cmd_buf, ta->cmd_len);
        break;
    case TA100_CMD_LOCK:
        ta100_cmd_lock(ta, ta->cmd_buf, ta->cmd_len);
        break;
#ifdef M33MU_HAS_WOLFSSL
    case TA100_CMD_RANDOM:
        ta100_cmd_random(ta, ta->cmd_buf, ta->cmd_len);
        break;
    case TA100_CMD_NONCE:
        ta100_cmd_nonce(ta, ta->cmd_buf, ta->cmd_len);
        break;
    case TA100_CMD_GENKEY:
        ta100_cmd_genkey(ta, ta->cmd_buf, ta->cmd_len);
        break;
    case TA100_CMD_SIGN:
        ta100_cmd_sign(ta, ta->cmd_buf, ta->cmd_len);
        break;
    case TA100_CMD_SHA256:
        ta100_cmd_sha256(ta, ta->cmd_buf, ta->cmd_len);
        break;
#endif
    default:
        if (ta100_trace_enabled()) {
            fprintf(stderr, "[TA100_TRACE] Unknown opcode 0x%02x\n", opcode);
        }
        ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
        ta->rsp_len = 1;
        crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
        ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
        break;
    }
    
    if (ta100_trace_enabled()) {
        fprintf(stderr, "[TA100_TRACE] Response ready, len=%lu\n",
                (unsigned long)ta->rsp_len);
        ta100_trace_dump("rsp", ta->rsp_buf, ta->rsp_len);
    }
    
    ta->state = TA100_RESP_READY;
}

static void ta100_reset_transaction(struct mm_ta100 *ta)
{
    if (ta == 0) {
        return;
    }
    ta->cmd_len = 0;
    ta->rsp_len = 0;
    ta->rsp_read = 0;
    ta->busy_cycles = 0;
}

static mm_u8 ta100_spi_xfer(void *opaque, mm_u8 out)
{
    struct mm_ta100 *ta = (struct mm_ta100 *)opaque;
    mm_u8 in = 0x00u;
    mm_u8 cs_level;
    
    if (ta == 0) {
        return 0xFFu;
    }
    
    cs_level = ta100_sample_cs(ta);
    
    if (ta->cs_valid && cs_level != ta->cs_level) {
        ta->cs_level = cs_level;
        if (cs_level != 0u) {
            if (ta100_spi_trace_enabled()) {
                fprintf(stderr, "[SPI] TA100 SPI%d CS deasserted (P%c%d)\n",
                        ta->bus,
                        (char)('A' + ta->cs_bank),
                        ta->cs_pin);
            }
            ta100_process_command(ta);
            /* Only reset cmd buffer - preserve response for next CS cycle */
            ta->cmd_len = 0;
            return 0xFFu;
        } else {
            if (ta100_spi_trace_enabled()) {
                fprintf(stderr, "[SPI] TA100 SPI%d CS asserted (P%c%d)\n",
                        ta->bus,
                        (char)('A' + ta->cs_bank),
                        ta->cs_pin);
            }
        }
    }
    
    if (ta->cs_valid && cs_level != 0u) {
        return 0xFFu;
    }
    
    /* Detect missed CS deassert: if we have a complete pending command in IDLE state
     * and receive dummy 0xFF (response poll), process the command now.
     * This handles the case where GPIO toggles happen between SPI transactions
     * and we miss the CS transition.
     * Minimum command is 5 bytes: opcode(1) + params(>=0) + CRC(2), typical ~5 bytes */
    if (ta->state == TA100_IDLE && ta->cmd_len >= 5 && out == 0xFFu) {
        ta100_process_command(ta);
        ta->cmd_len = 0;
    }
    
    if (ta->state == TA100_RESP_READY && ta->rsp_read < ta->rsp_len) {
        in = ta->rsp_buf[ta->rsp_read++];
        if (ta->rsp_read >= ta->rsp_len) {
            ta->state = TA100_IDLE;
            ta->cmd_len = 0;
        }
        return in;
    }
    
    if (ta->state == TA100_IDLE || ta->state == TA100_SLEEP) {
        if (ta->cmd_len < TA100_CMD_MAX) {
            ta->cmd_buf[ta->cmd_len++] = out;
        }
        in = 0x00u;
    } else if (ta->state == TA100_BUSY) {
        in = 0x00u;
    }
    
    return in;
}

static void ta100_spi_end(void *opaque)
{
    struct mm_ta100 *ta = (struct mm_ta100 *)opaque;
    if (ta == 0) {
        return;
    }
    if (ta->cs_valid) {
        return;
    }
    ta100_process_command(ta);
    ta100_reset_transaction(ta);
}

static mm_u8 ta100_spi_cs_level(void *opaque)
{
    struct mm_ta100 *ta = (struct mm_ta100 *)opaque;
    mm_u8 cs_level;
    if (ta == 0) {
        return 1u;
    }
    cs_level = ta100_sample_cs(ta);
    
    /* Handle CS transitions when polled */
    if (ta->cs_valid && cs_level != ta->cs_level) {
        ta->cs_level = cs_level;
        if (cs_level != 0u) {
            /* CS deasserted - process pending command */
            if (ta100_spi_trace_enabled()) {
                fprintf(stderr, "[SPI] TA100 SPI%d CS deasserted via poll (P%c%d)\n",
                        ta->bus,
                        (char)('A' + ta->cs_bank),
                        ta->cs_pin);
            }
            ta100_process_command(ta);
            ta->cmd_len = 0;
        } else {
            if (ta100_spi_trace_enabled()) {
                fprintf(stderr, "[SPI] TA100 SPI%d CS asserted via poll (P%c%d)\n",
                        ta->bus,
                        (char)('A' + ta->cs_bank),
                        ta->cs_pin);
            }
        }
    }
    
    return cs_level;
}

static void ta100_sync_nv(struct mm_ta100 *ta)
{
    FILE *f;
    if (ta == 0 || !ta->nv_dirty || !ta->has_nv_path) {
        return;
    }
    f = fopen(ta->nv_path, "wb");
    if (f == 0) {
        fprintf(stderr, "ta100: failed to open %s for write\n", ta->nv_path);
        return;
    }
    if (ta->nv_size > 0u) {
        size_t n = fwrite(ta->nv_data, 1u, (size_t)ta->nv_size, f);
        if (n != (size_t)ta->nv_size) {
            fprintf(stderr, "ta100: short write for %s\n", ta->nv_path);
        }
    }
    fclose(f);
    ta->nv_dirty = MM_FALSE;
}

static mm_bool ta100_load_nv(struct mm_ta100 *ta)
{
    FILE *f;
    size_t n = 0;
    mm_bool fresh = MM_FALSE;
    
    if (ta == 0 || !ta->has_nv_path) {
        return MM_FALSE;
    }
    
    ta->nv_size = TA100_NV_SIZE;
    ta->nv_data = (mm_u8 *)malloc((size_t)ta->nv_size);
    if (ta->nv_data == 0) {
        fprintf(stderr, "ta100: out of memory for NV\n");
        return MM_FALSE;
    }
    memset(ta->nv_data, 0xFF, (size_t)ta->nv_size);
    
    f = fopen(ta->nv_path, "rb");
    if (f != 0) {
        n = fread(ta->nv_data, 1u, (size_t)ta->nv_size, f);
        fclose(f);
        if (n < (size_t)ta->nv_size) {
            ta->nv_dirty = MM_TRUE;
        }
        
        ta->config_locked = (ta->nv_data[87] == 0x00) ? MM_TRUE : MM_FALSE;
        ta->data_locked = (ta->nv_data[86] == 0x00) ? MM_TRUE : MM_FALSE;
        
        return MM_TRUE;
    }
    
    ta100_init_nv_layout(ta);
    ta->nv_dirty = MM_TRUE;
    fresh = MM_TRUE;
    
    if (fresh) {
        ta100_sync_nv(ta);
    }
    
    return MM_TRUE;
}

static void ta100_device_reset(struct mm_ta100 *ta)
{
    if (ta == 0) {
        return;
    }
    ta->state = TA100_IDLE;
    ta->cs_level = 1u;
    ta100_reset_transaction(ta);
}

static int parse_bus_index(const char *s)
{
    if (s == 0) return -1;
    if (strncmp(s, "SPI", 3) == 0) {
        char *end = 0;
        long n = strtol(s + 3, &end, 10);
        if (end != s + 3 && *end == '\0' && n >= 1 && n <= 99) {
            return (int)n;
        }
    }
    return -1;
}

static mm_bool parse_gpio_name(const char *s, int *bank_out, int *pin_out)
{
    if (s == 0 || bank_out == 0 || pin_out == 0) return MM_FALSE;
    if (s[0] == 'P' || s[0] == 'p') {
        char bank_char = s[1];
        int bank = 0;
        int pin = 0;
        char *end = 0;
        if (bank_char >= 'A' && bank_char <= 'Z') {
            bank = bank_char - 'A';
        } else if (bank_char >= 'a' && bank_char <= 'z') {
            bank = bank_char - 'a';
        } else {
            return MM_FALSE;
        }
        pin = (int)strtol(s + 2, &end, 10);
        if (end == s + 2 || *end != '\0' || pin < 0 || pin > 15) {
            return MM_FALSE;
        }
        *bank_out = bank;
        *pin_out = pin;
        return MM_TRUE;
    }
    return MM_FALSE;
}

mm_bool mm_ta100_parse_spec(const char *spec, struct mm_ta100_cfg *out)
{
    char tmp[512];
    char *tok;
    if (spec == 0 || out == 0) return MM_FALSE;
    memset(out, 0, sizeof(*out));
    strncpy(tmp, spec, sizeof(tmp) - 1u);
    tmp[sizeof(tmp) - 1u] = '\0';
    tok = strtok(tmp, ":");
    if (tok == 0) return MM_FALSE;
    out->bus = parse_bus_index(tok);
    if (out->bus < 0) return MM_FALSE;
    while ((tok = strtok(0, ":")) != 0) {
        if (strncmp(tok, "cs=", 3) == 0) {
            if (!parse_gpio_name(tok + 3, &out->cs_bank, &out->cs_pin)) return MM_FALSE;
            out->cs_valid = MM_TRUE;
        } else if (strncmp(tok, "file=", 5) == 0) {
            strncpy(out->nv_path, tok + 5, sizeof(out->nv_path) - 1u);
            out->nv_path[sizeof(out->nv_path) - 1u] = '\0';
            out->has_nv_path = MM_TRUE;
        } else if (strncmp(tok, "profile=", 8) == 0) {
            strncpy(out->profile, tok + 8, sizeof(out->profile) - 1u);
            out->profile[sizeof(out->profile) - 1u] = '\0';
            out->has_profile = MM_TRUE;
        } else if (strncmp(tok, "serial=", 7) == 0) {
            strncpy(out->serial, tok + 7, sizeof(out->serial) - 1u);
            out->serial[sizeof(out->serial) - 1u] = '\0';
            out->has_serial = MM_TRUE;
        } else {
            return MM_FALSE;
        }
    }
    return MM_TRUE;
}

mm_bool mm_ta100_register_cfg(const struct mm_ta100_cfg *cfg)
{
    struct mm_ta100 *ta;
    struct mm_spi_device dev;
    if (cfg == 0) {
        return MM_FALSE;
    }
    if (g_ta100_count >= TA100_MAX) {
        fprintf(stderr, "ta100: max devices reached\n");
        return MM_FALSE;
    }
    ta = &g_ta100[g_ta100_count];
    memset(ta, 0, sizeof(*ta));
    ta->bus = cfg->bus;
    ta->cs_valid = cfg->cs_valid;
    ta->cs_bank = cfg->cs_bank;
    ta->cs_pin = cfg->cs_pin;
    ta->cs_mask = (cfg->cs_valid && cfg->cs_pin >= 0) ? (1u << (mm_u32)cfg->cs_pin) : 0u;
    ta->cs_level = 1u;
    ta->has_nv_path = cfg->has_nv_path;
    if (cfg->has_nv_path) {
        size_t n = strlen(cfg->nv_path);
        if (n >= sizeof(ta->nv_path)) {
            n = sizeof(ta->nv_path) - 1u;
        }
        memcpy(ta->nv_path, cfg->nv_path, n);
        ta->nv_path[n] = '\0';
    }
    ta->has_profile = cfg->has_profile;
    if (cfg->has_profile) {
        size_t n = strlen(cfg->profile);
        if (n >= sizeof(ta->profile)) {
            n = sizeof(ta->profile) - 1u;
        }
        memcpy(ta->profile, cfg->profile, n);
        ta->profile[n] = '\0';
    }
    ta->has_serial = cfg->has_serial;
    if (cfg->has_serial) {
        size_t n = strlen(cfg->serial);
        if (n >= sizeof(ta->serial)) {
            n = sizeof(ta->serial) - 1u;
        }
        memcpy(ta->serial, cfg->serial, n);
        ta->serial[n] = '\0';
    }
    
    if (ta->has_nv_path) {
        ta100_load_nv(ta);
    }
    
    ta100_device_reset(ta);
    
    memset(&dev, 0, sizeof(dev));
    dev.bus = ta->bus;
    dev.xfer = ta100_spi_xfer;
    dev.end = ta100_spi_end;
    dev.cs_level = ta100_spi_cs_level;
    dev.opaque = ta;
    if (!mm_spi_bus_register_device(&dev)) {
        fprintf(stderr, "ta100: failed to register SPI device\n");
        return MM_FALSE;
    }
    
    g_ta100_count++;
    fprintf(stderr, "[TA100] Registered on SPI%d", ta->bus);
    if (ta->cs_valid) {
        fprintf(stderr, " CS=P%c%d", (char)('A' + ta->cs_bank), ta->cs_pin);
    }
    if (ta->has_nv_path) {
        fprintf(stderr, " file=%s", ta->nv_path);
    }
    if (ta->has_profile) {
        fprintf(stderr, " profile=%s", ta->profile);
    }
    if (ta->has_serial) {
        fprintf(stderr, " serial=%s", ta->serial);
    }
    fprintf(stderr, "\n");
    
    return MM_TRUE;
}

void mm_ta100_reset_all(void)
{
    size_t i;
    for (i = 0; i < g_ta100_count; ++i) {
        ta100_device_reset(&g_ta100[i]);
    }
}

void mm_ta100_shutdown_all(void)
{
    size_t i;
    for (i = 0; i < g_ta100_count; ++i) {
        ta100_sync_nv(&g_ta100[i]);
#ifdef M33MU_HAS_WOLFSSL
        if (g_ta100[i].rng_initialized) {
            wc_FreeRng(&g_ta100[i].rng);
            g_ta100[i].rng_initialized = MM_FALSE;
        }
#endif
        if (g_ta100[i].nv_data != 0) {
            free(g_ta100[i].nv_data);
            g_ta100[i].nv_data = 0;
        }
    }
}

size_t mm_ta100_count(void)
{
    return g_ta100_count;
}

mm_bool mm_ta100_get_info(size_t index, struct mm_ta100_info *out)
{
    const struct mm_ta100 *ta;
    if (index >= g_ta100_count || out == 0) {
        return MM_FALSE;
    }
    ta = &g_ta100[index];
    memset(out, 0, sizeof(*out));
    out->bus = ta->bus;
    out->cs_valid = ta->cs_valid;
    out->cs_bank = ta->cs_bank;
    out->cs_pin = ta->cs_pin;
    out->has_nv_path = ta->has_nv_path;
    if (ta->has_nv_path) {
        size_t n = strlen(ta->nv_path);
        if (n >= sizeof(out->nv_path)) {
            n = sizeof(out->nv_path) - 1u;
        }
        memcpy(out->nv_path, ta->nv_path, n);
        out->nv_path[n] = '\0';
    }
    out->has_profile = ta->has_profile;
    if (ta->has_profile) {
        size_t n = strlen(ta->profile);
        if (n >= sizeof(out->profile)) {
            n = sizeof(out->profile) - 1u;
        }
        memcpy(out->profile, ta->profile, n);
        out->profile[n] = '\0';
    }
    out->has_serial = ta->has_serial;
    if (ta->has_serial) {
        size_t n = strlen(ta->serial);
        if (n >= sizeof(out->serial)) {
            n = sizeof(out->serial) - 1u;
        }
        memcpy(out->serial, ta->serial, n);
        out->serial[n] = '\0';
    }
    return MM_TRUE;
}
