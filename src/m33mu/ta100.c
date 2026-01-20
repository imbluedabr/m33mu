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
#define TA100_MAX_HANDLES 64

/* ATECC-style opcodes (legacy, for backward compat) */
#define TA100_CMD_INFO_ATECC 0x30
#define TA100_CMD_READ_ATECC 0x02
#define TA100_CMD_WRITE_ATECC 0x12
#define TA100_CMD_LOCK_ATECC 0x17
#define TA100_CMD_RANDOM_ATECC 0x1B
#define TA100_CMD_NONCE_ATECC 0x16
#define TA100_CMD_GENKEY_ATECC 0x40
#define TA100_CMD_SIGN_ATECC 0x41
#define TA100_CMD_SHA256_ATECC 0x47
#define TA100_CMD_MAC_ATECC 0x08

/* TA100-specific opcodes (from TA100 datasheet / cryptoauthlib) */
#define TA100_OP_INFO       0x00
#define TA100_OP_SECBOOT    0x01
#define TA100_OP_FCCONFIG   0x02
#define TA100_OP_POWER      0x03
#define TA100_OP_IMPORT     0x04
#define TA100_OP_EXPORT     0x05
#define TA100_OP_CREATE     0x06
#define TA100_OP_READ       0x07
#define TA100_OP_WRITE      0x08
#define TA100_OP_RANDOM     0x09
#define TA100_OP_MAC        0x0A
#define TA100_OP_DEVUPDATE  0x0B
#define TA100_OP_MANAGECERT 0x0C
#define TA100_OP_LOCK       0x0D
#define TA100_OP_COUNTER    0x0E
#define TA100_OP_SIGN       0x0F
#define TA100_OP_VERIFY     0x10
#define TA100_OP_ECDH       0x11
#define TA100_OP_KEYGEN     0x12
#define TA100_OP_DELETE     0x13
#define TA100_OP_SELFTEST   0x14
#define TA100_OP_SEQUENCE   0x15
#define TA100_OP_AUTHORIZE  0x16
#define TA100_OP_KDF        0x17
#define TA100_OP_RSAENC     0x18
#define TA100_OP_SHA        0x19
#define TA100_OP_AES        0x1A

/* TA100 Info command modes */
#define TA100_INFO_MODE_REV             0x00
#define TA100_INFO_MODE_NV_REMAIN       0x01
#define TA100_INFO_MODE_HANDLE_VALID    0x02
#define TA100_INFO_MODE_HANDLE_INFO     0x03
#define TA100_INFO_MODE_HANDLE_ARRAY    0x04
#define TA100_INFO_MODE_AUTH_STATUS     0x05
#define TA100_INFO_MODE_VOL_REG_STATUS  0x06
#define TA100_INFO_MODE_DED_MEMORY      0x07
#define TA100_INFO_MODE_CHIP_STATUS     0x08

/* TA100 packet format constants */
#define TA100_PKT_INSTR_OFFSET    0
#define TA100_PKT_LENGTH_OFFSET   1
#define TA100_PKT_OPCODE_OFFSET   3
#define TA100_PKT_PARAM1_OFFSET   4
#define TA100_PKT_PARAM2_OFFSET   5
#define TA100_PKT_DATA_OFFSET     9
#define TA100_PKT_MIN_LEN         10  /* instr(1)+len(2)+op(1)+p1(1)+p2(4)+crc(2) = 11, but accept 10 */

/* TA100 instruction codes */
#define TA100_INSTR_WR_CMD  0x00
#define TA100_INSTR_RD_RSP  0x10
#define TA100_INSTR_WR_CCR  0x20
#define TA100_INSTR_RD_CSR  0x30

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
    /* TA100 handle management */
    mm_u16 handles[TA100_MAX_HANDLES];
    mm_u8  handle_attrs[TA100_MAX_HANDLES][8]; /* 8-byte element attributes */
    mm_u32 handle_count;
    /* Current transaction instruction (for inline response handling) */
    mm_u8 cur_instr;
    mm_bool instr_started;
    mm_u8 csr_val;  /* CSR status register value */
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

/* TA100 uses CRC-16 CCITT (polynomial 0x1021, init 0xFFFF) */
static mm_u16 ta100_calculate_crc(const mm_u8 *data, mm_u32 len)
{
    mm_u32 i;
    mm_u16 crc = 0xFFFF;
    const mm_u16 polynom = 0x1021;
    const mm_u16 crchighbit = 0x8000;

    for (i = 0; i < len; i++) {
        mm_u16 c = (mm_u16)data[i];
        mm_u16 j;
        for (j = 0x80; j > 0u; j >>= 1) {
            mm_u16 bit = crc & crchighbit;
            crc <<= 1;
            if ((c & j) != 0u) {
                bit ^= crchighbit;
            }
            if (bit != 0u) {
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

/* Helper to build TA100 response with length prefix and CRC */
static void ta100_build_response(struct mm_ta100 *ta, mm_u8 resp_code,
                                  const mm_u8 *data, mm_u32 data_len)
{
    mm_u16 total_len;
    mm_u16 crc;

    /* Response format: length(2 BE) + resp_code(1) + data[] + CRC(2) */
    total_len = 3 + data_len + 2;  /* length + resp_code + data + crc */
    ta->rsp_buf[0] = (mm_u8)(total_len >> 8);
    ta->rsp_buf[1] = (mm_u8)(total_len & 0xFF);
    ta->rsp_buf[2] = resp_code;
    if (data != 0 && data_len > 0) {
        memcpy(&ta->rsp_buf[3], data, data_len);
    }
    ta->rsp_len = 3 + data_len;
    crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
    ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
}

/* Helper to find a handle */
static int ta100_find_handle(struct mm_ta100 *ta, mm_u16 handle)
{
    mm_u32 i;
    for (i = 0; i < ta->handle_count; i++) {
        if (ta->handles[i] == handle) {
            return (int)i;
        }
    }
    return -1;
}

/* TA100 Info command (opcode 0x00) */
static void ta100_op_info(struct mm_ta100 *ta, mm_u8 mode, mm_u32 param2)
{
    mm_u8 data[16];
    mm_u32 data_len = 0;
    mm_u16 target_handle;
    int idx;

    if (ta100_trace_enabled()) {
        fprintf(stderr, "[TA100_TRACE] INFO mode=0x%02x param2=0x%08x\n", mode, param2);
    }

    switch (mode) {
    case TA100_INFO_MODE_REV:
        /* Return revision info: 4 bytes */
        data[0] = 0x00;  /* Family */
        data[1] = 0x00;  /* Model */
        data[2] = 0x60;  /* Revision (TA100) */
        data[3] = 0x03;  /* Version */
        data_len = 4;
        break;

    case TA100_INFO_MODE_NV_REMAIN:
        /* Return remaining NV memory: 4 bytes */
        data[0] = 0x00;
        data[1] = 0x00;
        data[2] = 0x10;  /* ~4K remaining */
        data[3] = 0x00;
        data_len = 4;
        break;

    case TA100_INFO_MODE_HANDLE_VALID:
        /* Check if handle is valid - return 1 byte: 0x01 if valid, 0x00 if not */
        target_handle = (mm_u16)(param2 & 0xFFFF);
        idx = ta100_find_handle(ta, target_handle);
        data[0] = (idx >= 0) ? 0x01 : 0x00;
        data_len = 1;
        if (ta100_trace_enabled()) {
            fprintf(stderr, "[TA100_TRACE] HANDLE_VALID handle=0x%04x result=%d\n",
                    target_handle, data[0]);
        }
        break;

    case TA100_INFO_MODE_HANDLE_INFO:
        /* Return handle info: 9 bytes (TA_HANDLE_INFO_SIZE) */
        target_handle = (mm_u16)(param2 & 0xFFFF);
        idx = ta100_find_handle(ta, target_handle);
        if (idx >= 0) {
            memcpy(data, ta->handle_attrs[idx], 8);
            data[8] = 0x00;  /* lock status byte */
            data_len = 9;
        } else {
            /* Handle doesn't exist - return zeros (not locked) */
            memset(data, 0, 9);
            data_len = 9;
            if (ta100_trace_enabled()) {
                fprintf(stderr, "[TA100_TRACE] HANDLE_INFO: handle 0x%04x not found, returning zeros\n",
                        target_handle);
            }
        }
        break;

    case TA100_INFO_MODE_CHIP_STATUS:
        /* Return chip status: 4 bytes */
        data[0] = 0x00;  /* No errors */
        data[1] = 0x00;
        data[2] = 0x00;
        data[3] = 0x00;
        data_len = 4;
        break;

    default:
        /* Unknown mode - return empty success */
        data_len = 0;
        break;
    }

    ta100_build_response(ta, TA100_STATUS_SUCCESS, data, data_len);
}

/* TA100 Create command (opcode 0x06) */
static void ta100_op_create(struct mm_ta100 *ta, const mm_u8 *cmd, mm_u32 cmd_len)
{
    mm_u8 mode;
    mm_u16 details;
    mm_u16 handle_in;
    mm_u8 handle_config[8];
    mm_u16 handle_out;
    mm_u8 resp_data[2];

    if (cmd_len < TA100_PKT_DATA_OFFSET + 8 + 2) {
        ta100_build_response(ta, TA100_STATUS_PARSE_ERROR, 0, 0);
        return;
    }

    mode = cmd[TA100_PKT_PARAM1_OFFSET];
    details = ((mm_u16)cmd[TA100_PKT_PARAM2_OFFSET] << 8) |
              cmd[TA100_PKT_PARAM2_OFFSET + 1];
    handle_in = ((mm_u16)cmd[TA100_PKT_PARAM2_OFFSET + 2] << 8) |
                cmd[TA100_PKT_PARAM2_OFFSET + 3];
    memcpy(handle_config, &cmd[TA100_PKT_DATA_OFFSET], 8);

    (void)details;

    if (ta100_trace_enabled()) {
        fprintf(stderr, "[TA100_TRACE] CREATE mode=0x%02x handle_in=0x%04x\n",
                mode, handle_in);
    }

    /* Check if handle already exists */
    if (ta100_find_handle(ta, handle_in) >= 0) {
        /* Handle already exists - return error */
        if (ta100_trace_enabled()) {
            fprintf(stderr, "[TA100_TRACE] CREATE: handle 0x%04x already exists\n", handle_in);
        }
        ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
        return;
    }

    /* Add the handle */
    if (ta->handle_count >= TA100_MAX_HANDLES) {
        ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
        return;
    }

    if (mode & 0x02) {
        /* Handle assigned by device */
        handle_out = 0x8000 + (mm_u16)ta->handle_count;
    } else {
        /* Handle provided by host */
        handle_out = handle_in;
    }

    ta->handles[ta->handle_count] = handle_out;
    memcpy(ta->handle_attrs[ta->handle_count], handle_config, 8);
    ta->handle_count++;

    if (ta100_trace_enabled()) {
        fprintf(stderr, "[TA100_TRACE] CREATE: created handle 0x%04x (count=%u)\n",
                handle_out, (unsigned)ta->handle_count);
    }

    /* Response includes the handle if mode & 0x02 */
    if (mode & 0x02) {
        resp_data[0] = (mm_u8)(handle_out >> 8);
        resp_data[1] = (mm_u8)(handle_out & 0xFF);
        ta100_build_response(ta, TA100_STATUS_SUCCESS, resp_data, 2);
    } else {
        ta100_build_response(ta, TA100_STATUS_SUCCESS, 0, 0);
    }
}

/* TA100 Delete command (opcode 0x13) */
static void ta100_op_delete(struct mm_ta100 *ta, const mm_u8 *cmd, mm_u32 cmd_len)
{
    mm_u16 target_handle;
    int idx;

    (void)cmd_len;

    target_handle = ((mm_u16)cmd[TA100_PKT_PARAM2_OFFSET] << 8) |
                    cmd[TA100_PKT_PARAM2_OFFSET + 1];

    if (ta100_trace_enabled()) {
        fprintf(stderr, "[TA100_TRACE] DELETE handle=0x%04x\n", target_handle);
    }

    idx = ta100_find_handle(ta, target_handle);
    if (idx < 0) {
        ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
        return;
    }

    /* Remove handle by shifting */
    if ((mm_u32)idx < ta->handle_count - 1) {
        memmove(&ta->handles[idx], &ta->handles[idx + 1],
                (ta->handle_count - 1 - (mm_u32)idx) * sizeof(mm_u16));
        memmove(&ta->handle_attrs[idx], &ta->handle_attrs[idx + 1],
                (ta->handle_count - 1 - (mm_u32)idx) * 8);
    }
    ta->handle_count--;

    ta100_build_response(ta, TA100_STATUS_SUCCESS, 0, 0);
}

/* TA100 Random command (opcode 0x09) */
static void ta100_op_random(struct mm_ta100 *ta, const mm_u8 *cmd, mm_u32 cmd_len)
{
    mm_u8 rand_data[32];
    mm_u32 i;

    (void)cmd;
    (void)cmd_len;
    (void)i;

#ifdef M33MU_HAS_WOLFSSL
    if (!ta->rng_initialized) {
        if (wc_InitRng(&ta->rng) != 0) {
            ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
            return;
        }
        ta->rng_initialized = MM_TRUE;
    }
    if (wc_RNG_GenerateBlock(&ta->rng, rand_data, 32) != 0) {
        ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
        return;
    }
#else
    /* Simple PRNG fallback */
    for (i = 0; i < 32; i++) {
        rand_data[i] = (mm_u8)(rand() & 0xFF);
    }
#endif

    ta100_build_response(ta, TA100_STATUS_SUCCESS, rand_data, 32);
}

/* TA100 Read command (opcode 0x07) - simplified */
static void ta100_op_read(struct mm_ta100 *ta, const mm_u8 *cmd, mm_u32 cmd_len)
{
    mm_u8 mode;
    mm_u16 length;
    mm_u16 handle;
    mm_u32 offset;
    mm_u8 data[64];

    (void)cmd_len;

    mode = cmd[TA100_PKT_PARAM1_OFFSET];
    length = ((mm_u16)cmd[TA100_PKT_PARAM2_OFFSET] << 8) |
             cmd[TA100_PKT_PARAM2_OFFSET + 1];
    handle = ((mm_u16)cmd[TA100_PKT_PARAM2_OFFSET + 2] << 8) |
             cmd[TA100_PKT_PARAM2_OFFSET + 3];

    (void)mode;
    (void)handle;

    if (length > 64) {
        length = 64;
    }

    /* For now, return zeros */
    memset(data, 0, length);

    /* If reading from NV, use that data */
    if (handle < TA100_NV_SIZE) {
        offset = handle;
        if (offset + length <= ta->nv_size) {
            memcpy(data, &ta->nv_data[offset], length);
        }
    }

    ta100_build_response(ta, TA100_STATUS_SUCCESS, data, length);
}

/* TA100 Write command (opcode 0x08) - simplified */
static void ta100_op_write(struct mm_ta100 *ta, const mm_u8 *cmd, mm_u32 cmd_len)
{
    mm_u8 mode;
    mm_u16 source_handle;
    mm_u16 target_handle;
    mm_u16 length;
    mm_u16 offset;

    mode = cmd[TA100_PKT_PARAM1_OFFSET];
    /* param2 = source_handle(2 BE) + target_handle(2 BE) */
    source_handle = ((mm_u16)cmd[TA100_PKT_PARAM2_OFFSET] << 8) |
                    cmd[TA100_PKT_PARAM2_OFFSET + 1];
    target_handle = ((mm_u16)cmd[TA100_PKT_PARAM2_OFFSET + 2] << 8) |
                    cmd[TA100_PKT_PARAM2_OFFSET + 3];

    (void)source_handle;
    (void)mode;

    /* For partial write (mode != 0x80), data section has length + offset + data */
    if ((mode & 0x80) == 0) {
        /* Partial write: data = length(2 BE) + offset(2 BE) + actual_data */
        if (cmd_len < TA100_PKT_DATA_OFFSET + 4 + 2) {
            ta100_build_response(ta, TA100_STATUS_PARSE_ERROR, 0, 0);
            return;
        }
        length = ((mm_u16)cmd[TA100_PKT_DATA_OFFSET] << 8) |
                 cmd[TA100_PKT_DATA_OFFSET + 1];
        offset = ((mm_u16)cmd[TA100_PKT_DATA_OFFSET + 2] << 8) |
                 cmd[TA100_PKT_DATA_OFFSET + 3];

        if (cmd_len < (mm_u32)(TA100_PKT_DATA_OFFSET + 4 + length + 2)) {
            ta100_build_response(ta, TA100_STATUS_PARSE_ERROR, 0, 0);
            return;
        }
    } else {
        /* Entire element write: data = actual_data (no length/offset header) */
        length = (mm_u16)(cmd_len - TA100_PKT_DATA_OFFSET - 2);
        offset = 0;
    }

    if (ta100_trace_enabled()) {
        fprintf(stderr, "[TA100_TRACE] WRITE: target=0x%04x offset=%u len=%u\n",
                target_handle, offset, length);
    }

    /* For simplicity, just return success (no actual storage for now) */
    ta100_build_response(ta, TA100_STATUS_SUCCESS, 0, 0);
}

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
    mm_u8 instr_code;
    mm_u16 pkt_len;
    mm_u8 param1;
    mm_u32 param2;
    mm_u16 crc;
    mm_bool is_ta100_format = MM_FALSE;
    mm_u8 first_byte;

    if (ta == 0 || ta->cmd_len == 0) {
        return;
    }

    first_byte = ta->cmd_buf[0];

    /* For RD_RSP, don't clear response - we want to return the buffered response */
    if (first_byte != TA100_INSTR_RD_RSP) {
        ta->rsp_len = 0;
        ta->rsp_read = 0;
    }
    ta->busy_cycles = 100;

    if (ta100_trace_enabled()) {
        fprintf(stderr, "[TA100_TRACE] Processing command, len=%lu\n",
                (unsigned long)ta->cmd_len);
        ta100_trace_dump("cmd", ta->cmd_buf, ta->cmd_len);
    }

    if (ta->cmd_len < 1) {
        ta100_build_response(ta, TA100_STATUS_PARSE_ERROR, 0, 0);
        ta->state = TA100_RESP_READY;
        return;
    }

    instr_code = ta->cmd_buf[0];

    /* Handle TA100 instruction codes */
    switch (instr_code) {
    case TA100_INSTR_RD_CSR:
        /* Read Command Status Register - return device ready status */
        if (ta100_trace_enabled()) {
            fprintf(stderr, "[TA100_TRACE] RD_CSR: returning ready status\n");
        }
        /* CSR format: bit[4]=RRDY (response ready), bits[2:1]=status (0=available) */
        ta->rsp_buf[0] = (ta->state == TA100_RESP_READY) ? 0x10 : 0x00;  /* RRDY=1 if response ready */
        ta->rsp_len = 1;
        /* Don't change state for CSR read */
        return;

    case TA100_INSTR_RD_RSP:
        /* Read Response - return the buffered response if available */
        if (ta100_trace_enabled()) {
            fprintf(stderr, "[TA100_TRACE] RD_RSP: returning response len=%u\n", (unsigned)ta->rsp_len);
        }
        /* Response is already in rsp_buf from previous command execution */
        ta->state = TA100_RESP_READY;
        return;

    case TA100_INSTR_WR_CCR:
        /* Write Command Control Register - just acknowledge */
        if (ta100_trace_enabled()) {
            fprintf(stderr, "[TA100_TRACE] WR_CCR: acknowledged\n");
        }
        ta->rsp_buf[0] = 0x00;
        ta->rsp_len = 1;
        return;

    case TA100_INSTR_WR_CMD:
        /* Write Command - parse TA100 packet format */
        if (ta->cmd_len >= 8) {
            is_ta100_format = MM_TRUE;
            pkt_len = ((mm_u16)ta->cmd_buf[1] << 8) | ta->cmd_buf[2];
            opcode = ta->cmd_buf[TA100_PKT_OPCODE_OFFSET];  /* byte 3 */
            param1 = ta->cmd_buf[TA100_PKT_PARAM1_OFFSET];  /* byte 4 */
            param2 = ((mm_u32)ta->cmd_buf[TA100_PKT_PARAM2_OFFSET] << 24) |
                     ((mm_u32)ta->cmd_buf[TA100_PKT_PARAM2_OFFSET + 1] << 16) |
                     ((mm_u32)ta->cmd_buf[TA100_PKT_PARAM2_OFFSET + 2] << 8) |
                     ta->cmd_buf[TA100_PKT_PARAM2_OFFSET + 3];
            (void)pkt_len;

            if (ta100_trace_enabled()) {
                fprintf(stderr, "[TA100_TRACE] WR_CMD: opcode=0x%02x param1=0x%02x param2=0x%08x\n",
                        opcode, param1, (unsigned)param2);
            }
        } else {
            if (ta100_trace_enabled()) {
                fprintf(stderr, "[TA100_TRACE] WR_CMD: packet too short (%u bytes)\n", (unsigned)ta->cmd_len);
            }
            ta100_build_response(ta, TA100_STATUS_PARSE_ERROR, 0, 0);
            ta->state = TA100_RESP_READY;
            return;
        }
        break;

    default:
        /* Check if this might be an ATECC-style opcode for legacy compatibility */
        if (instr_code >= 0x02 && instr_code <= 0x47 && ta->cmd_len >= 3) {
            /* Treat as ATECC format */
            opcode = instr_code;
            param1 = (ta->cmd_len > 1) ? ta->cmd_buf[1] : 0;
            param2 = 0;
            if (ta->cmd_len >= 4) {
                param2 = ((mm_u32)ta->cmd_buf[2] << 8) | ta->cmd_buf[3];
            }
            if (ta100_trace_enabled()) {
                fprintf(stderr, "[TA100_TRACE] ATECC format: opcode=0x%02x\n", opcode);
            }
        } else {
            if (ta100_trace_enabled()) {
                fprintf(stderr, "[TA100_TRACE] Unknown instruction 0x%02x\n", instr_code);
            }
            ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
            ta->state = TA100_RESP_READY;
            return;
        }
    }

    /* Skip CRC verification for TA100 format for now - trust the data */

    if (is_ta100_format) {
        /* Handle TA100-specific opcodes */
        switch (opcode) {
        case TA100_OP_INFO:
            ta100_op_info(ta, param1, param2);
            break;
        case TA100_OP_CREATE:
            ta100_op_create(ta, ta->cmd_buf, ta->cmd_len);
            break;
        case TA100_OP_DELETE:
            ta100_op_delete(ta, ta->cmd_buf, ta->cmd_len);
            break;
        case TA100_OP_READ:
            ta100_op_read(ta, ta->cmd_buf, ta->cmd_len);
            break;
        case TA100_OP_WRITE:
            ta100_op_write(ta, ta->cmd_buf, ta->cmd_len);
            break;
        case TA100_OP_RANDOM:
            ta100_op_random(ta, ta->cmd_buf, ta->cmd_len);
            break;
        case TA100_OP_VERIFY:
            /* Handle verify - similar to INFO HANDLE_VALID */
            if (ta100_trace_enabled()) {
                fprintf(stderr, "[TA100_TRACE] VERIFY: returning success\n");
            }
            ta100_build_response(ta, TA100_STATUS_SUCCESS, 0, 0);
            break;
        case TA100_OP_KEYGEN:
        case TA100_OP_SIGN:
        case TA100_OP_COUNTER:
        case TA100_OP_AUTHORIZE:
        case TA100_OP_SHA:
        case TA100_OP_MAC:
        case TA100_OP_POWER:
        case TA100_OP_SELFTEST:
        case TA100_OP_IMPORT:
        case TA100_OP_EXPORT:
        case TA100_OP_DEVUPDATE:
        case TA100_OP_LOCK:
            /* Not implemented - return success for now */
            if (ta100_trace_enabled()) {
                fprintf(stderr, "[TA100_TRACE] Opcode 0x%02x not fully implemented, returning success\n", opcode);
            }
            ta100_build_response(ta, TA100_STATUS_SUCCESS, 0, 0);
            break;
        default:
            if (ta100_trace_enabled()) {
                fprintf(stderr, "[TA100_TRACE] Unknown TA100 opcode 0x%02x\n", opcode);
            }
            ta100_build_response(ta, TA100_STATUS_EXEC_ERROR, 0, 0);
            break;
        }
    } else {
        /* Handle ATECC-style opcodes */
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
        case TA100_CMD_INFO_ATECC:
            ta100_cmd_info(ta);
            break;
        case TA100_CMD_READ_ATECC:
            ta100_cmd_read(ta, ta->cmd_buf, ta->cmd_len);
            break;
        case TA100_CMD_WRITE_ATECC:
            ta100_cmd_write(ta, ta->cmd_buf, ta->cmd_len);
            break;
        case TA100_CMD_LOCK_ATECC:
            ta100_cmd_lock(ta, ta->cmd_buf, ta->cmd_len);
            break;
#ifdef M33MU_HAS_WOLFSSL
        case TA100_CMD_RANDOM_ATECC:
            ta100_cmd_random(ta, ta->cmd_buf, ta->cmd_len);
            break;
        case TA100_CMD_NONCE_ATECC:
            ta100_cmd_nonce(ta, ta->cmd_buf, ta->cmd_len);
            break;
        case TA100_CMD_GENKEY_ATECC:
            ta100_cmd_genkey(ta, ta->cmd_buf, ta->cmd_len);
            break;
        case TA100_CMD_SIGN_ATECC:
            ta100_cmd_sign(ta, ta->cmd_buf, ta->cmd_len);
            break;
        case TA100_CMD_SHA256_ATECC:
            ta100_cmd_sha256(ta, ta->cmd_buf, ta->cmd_len);
            break;
#endif
        default:
            if (ta100_trace_enabled()) {
                fprintf(stderr, "[TA100_TRACE] Unknown ATECC opcode 0x%02x\n", opcode);
            }
            ta->rsp_buf[0] = TA100_STATUS_EXEC_ERROR;
            ta->rsp_len = 1;
            crc = ta100_calculate_crc(ta->rsp_buf, ta->rsp_len);
            ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc >> 8);
            ta->rsp_buf[ta->rsp_len++] = (mm_u8)(crc & 0xFF);
            break;
        }
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
            /* CS deasserted */
            if (ta100_spi_trace_enabled()) {
                fprintf(stderr, "[SPI] TA100 SPI%d CS deasserted (P%c%d)\n",
                        ta->bus,
                        (char)('A' + ta->cs_bank),
                        ta->cs_pin);
            }
            /* Only process WR_CMD on CS deassert, RD_* handled inline */
            if (ta->cur_instr == TA100_INSTR_WR_CMD && ta->cmd_len > 0) {
                ta100_process_command(ta);
            }
            ta->cmd_len = 0;
            ta->instr_started = MM_FALSE;
            ta->cur_instr = 0xFF;
            return 0xFFu;
        } else {
            /* CS asserted - start of new transaction */
            if (ta100_spi_trace_enabled()) {
                fprintf(stderr, "[SPI] TA100 SPI%d CS asserted (P%c%d)\n",
                        ta->bus,
                        (char)('A' + ta->cs_bank),
                        ta->cs_pin);
            }
            ta->instr_started = MM_FALSE;
            ta->cur_instr = 0xFF;
            ta->cmd_len = 0;
        }
    }

    if (ta->cs_valid && cs_level != 0u) {
        return 0xFFu;
    }

    /* First byte of transaction is the instruction code */
    if (!ta->instr_started) {
        ta->instr_started = MM_TRUE;
        ta->cur_instr = out;

        switch (out) {
        case TA100_INSTR_RD_CSR:
            /* Read CSR - prepare status for subsequent reads */
            /* CSR format: bit[4]=RRDY (response ready), bits[2:1]=status (0=available) */
            ta->csr_val = (ta->state == TA100_RESP_READY) ? 0x10 : 0x00;
            if (ta100_trace_enabled()) {
                fprintf(stderr, "[TA100_TRACE] RD_CSR: status=0x%02x\n", ta->csr_val);
            }
            return 0x00u;  /* ACK the instruction */

        case TA100_INSTR_RD_RSP:
            /* Read response - response already in rsp_buf */
            ta->rsp_read = 0;
            if (ta100_trace_enabled()) {
                fprintf(stderr, "[TA100_TRACE] RD_RSP: len=%u\n", (unsigned)ta->rsp_len);
            }
            return 0x00u;  /* ACK the instruction */

        case TA100_INSTR_WR_CMD:
            /* Write command - accumulate bytes */
            if (ta->cmd_len < TA100_CMD_MAX) {
                ta->cmd_buf[ta->cmd_len++] = out;
            }
            return 0x00u;

        default:
            /* Unknown instruction or ATECC-style command - accumulate */
            if (ta->cmd_len < TA100_CMD_MAX) {
                ta->cmd_buf[ta->cmd_len++] = out;
            }
            return 0x00u;
        }
    }

    /* Handle subsequent bytes based on current instruction */
    switch (ta->cur_instr) {
    case TA100_INSTR_RD_CSR:
        /* Return CSR value (host sends 0xFF to clock out) */
        if (ta100_trace_enabled()) {
            fprintf(stderr, "[TA100_TRACE] read CSR=0x%02x\n", ta->csr_val);
        }
        return ta->csr_val;

    case TA100_INSTR_RD_RSP:
        /* Return response bytes (host sends 0xFF as clock) */
        if (ta->rsp_read < ta->rsp_len) {
            in = ta->rsp_buf[ta->rsp_read++];
            if (ta100_trace_enabled()) {
                fprintf(stderr, "[TA100_TRACE] read rsp[%u]=0x%02x\n",
                        ta->rsp_read-1, in);
            }
            /* Clear response ready state when last byte is read */
            if (ta->rsp_read >= ta->rsp_len) {
                ta->state = TA100_IDLE;
            }
        } else {
            in = 0x00u;
        }
        return in;

    case TA100_INSTR_WR_CMD:
    default:
        /* Accumulate command bytes */
        if (ta->cmd_len < TA100_CMD_MAX) {
            ta->cmd_buf[ta->cmd_len++] = out;
        }
        return 0x00u;
    }
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
            /* CS asserted - new transaction starting */
            ta->instr_started = MM_FALSE;
            ta->cur_instr = 0;
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
