/* atecc608.c -- ATECC608A secure element simulator (SPI, m33mu integration)
 *
 * Copyright (C) 2026 wolfSSL Inc.                       (ATECC608 simulator)
 * Copyright (C) 2026 Daniele Lacamera <root@danielinux.net> (m33mu integration)
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "m33mu/atecc608.h"
#include "m33mu/spi_bus.h"
#include "m33mu/gpio.h"

/* FFI declarations from atecc608-sim (Rust static lib) */
extern void *atecc608_ffi_create(const char *nv_path);
extern void  atecc608_ffi_destroy(void *ctx);
extern bool  atecc608_ffi_transaction(void *ctx, uint8_t word_addr,
                                      const uint8_t *payload, size_t payload_len,
                                      uint8_t *resp, size_t resp_max,
                                      size_t *resp_len_out);

#define ATECC608_MAX 4
#define ATECC608_CMD_MAX 512u
#define ATECC608_RSP_MAX 512u

/* word_addr values (ATECC SPI protocol) */
#define WA_WAKE    0x00u
#define WA_SLEEP   0x01u
#define WA_IDLE    0x02u
#define WA_COMMAND 0x03u

typedef enum {
    STATE_IDLE,       /* waiting for CS assert */
    STATE_WORD_ADDR,  /* received CS assert, waiting for word_addr byte */
    STATE_CMD_COUNT,  /* word_addr=0x03: waiting for count byte */
    STATE_CMD_DATA,   /* accumulating payload bytes */
    STATE_RESP,       /* serving response bytes one-by-one */
} atecc608_state_t;

struct mm_atecc608 {
    int bus;
    mm_bool cs_valid;
    int cs_bank;
    int cs_pin;
    mm_u32 cs_mask;
    mm_u8 cs_level;
    mm_bool has_nv_path;
    char nv_path[256];
    void *ffi_ctx;
    atecc608_state_t state;
    mm_u8 cmd_buf[ATECC608_CMD_MAX];
    size_t cmd_len;   /* bytes accumulated after word_addr byte */
    size_t cmd_total; /* total expected (from count byte) */
    mm_u8 rsp_buf[ATECC608_RSP_MAX];
    size_t rsp_len;
    size_t rsp_pos;
};

static struct mm_atecc608 g_atecc608[ATECC608_MAX];
static size_t g_atecc608_count;

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

static int parse_spi_bus(const char *s)
{
    char *end;
    long n;
    if (s == 0 || strncmp(s, "SPI", 3) != 0) return -1;
    n = strtol(s + 3, &end, 10);
    if (end == s + 3 || *end != '\0' || n < 1 || n > 99) return -1;
    return (int)n;
}

static mm_bool parse_gpio(const char *s, int *bank, int *pin)
{
    char bch;
    char *end;
    long p;
    if (s == 0 || (s[0] != 'P' && s[0] != 'p')) return MM_FALSE;
    bch = s[1];
    if (bch >= 'A' && bch <= 'Z') *bank = bch - 'A';
    else if (bch >= 'a' && bch <= 'z') *bank = bch - 'a';
    else return MM_FALSE;
    p = strtol(s + 2, &end, 10);
    if (end == s + 2 || *end != '\0' || p < 0 || p > 15) return MM_FALSE;
    *pin = (int)p;
    return MM_TRUE;
}

static mm_u8 atecc608_sample_cs(const struct mm_atecc608 *dev)
{
    mm_u32 odr;
    if (!dev->cs_valid) return 0u;
    if (!mm_gpio_bank_reader_present()) return 0u;
    odr = mm_gpio_bank_read(dev->cs_bank);
    return (odr & dev->cs_mask) ? 1u : 0u;
}

/* ------------------------------------------------------------------ */
/* SPI callbacks                                                        */
/* ------------------------------------------------------------------ */

static void atecc608_process_command(struct mm_atecc608 *dev)
{
    size_t resp_len = 0;
    bool ok;

    ok = atecc608_ffi_transaction(dev->ffi_ctx, WA_COMMAND,
                                  dev->cmd_buf, dev->cmd_len,
                                  dev->rsp_buf, ATECC608_RSP_MAX,
                                  &resp_len);
    if (ok && resp_len > 0) {
        dev->rsp_len = resp_len;
        dev->rsp_pos = 0;
        dev->state = STATE_RESP;
    } else {
        dev->rsp_len = 0;
        dev->rsp_pos = 0;
        dev->state = STATE_IDLE;
    }
    dev->cmd_len = 0;
}

static mm_u8 atecc608_spi_xfer(void *opaque, mm_u8 out)
{
    struct mm_atecc608 *dev = (struct mm_atecc608 *)opaque;
    mm_u8 cs;

    if (dev == 0 || dev->ffi_ctx == 0) return 0xFFu;

    cs = atecc608_sample_cs(dev);

    /* Detect CS edge */
    if (dev->cs_valid && cs != dev->cs_level) {
        dev->cs_level = cs;
        if (cs != 0u) {
            /* CS deasserted — end of transaction */
            if (dev->state == STATE_CMD_DATA && dev->cmd_len > 0) {
                atecc608_process_command(dev);
            } else if (dev->state != STATE_RESP) {
                dev->state = STATE_IDLE;
                dev->cmd_len = 0;
            }
            return 0xFFu;
        } else {
            /* CS asserted — start of new transaction */
            dev->state = STATE_WORD_ADDR;
            dev->cmd_len = 0;
            dev->rsp_len = 0;
            dev->rsp_pos = 0;
        }
    }

    if (dev->cs_valid && cs != 0u) {
        return 0xFFu;
    }

    switch (dev->state) {
    case STATE_IDLE:
        dev->state = STATE_WORD_ADDR;
        /* fall through to handle the byte */
        /* FALLTHROUGH */
    case STATE_WORD_ADDR:
        switch (out) {
        case WA_WAKE:
            /* wake — no response */
            dev->state = STATE_IDLE;
            return 0x00u;
        case WA_SLEEP:
            atecc608_ffi_transaction(dev->ffi_ctx, WA_SLEEP,
                                     0, 0, 0, 0, 0);
            dev->state = STATE_IDLE;
            return 0x00u;
        case WA_IDLE:
            dev->state = STATE_IDLE;
            return 0x00u;
        case WA_COMMAND:
            dev->state = STATE_CMD_COUNT;
            dev->cmd_len = 0;
            return 0x00u;
        default:
            dev->state = STATE_IDLE;
            return 0x00u;
        }

    case STATE_CMD_COUNT:
        /* 'out' is the count byte; payload = count-1 bytes follow */
        if (out < 1u) {
            dev->state = STATE_IDLE;
            return 0x00u;
        }
        dev->cmd_buf[0] = out;
        dev->cmd_len = 1;
        dev->cmd_total = (size_t)(out - 1u);
        if (dev->cmd_total == 0u) {
            atecc608_process_command(dev);
        } else {
            dev->state = STATE_CMD_DATA;
        }
        return 0x00u;

    case STATE_CMD_DATA:
        if (dev->cmd_len < ATECC608_CMD_MAX) {
            dev->cmd_buf[dev->cmd_len++] = out;
        }
        if (dev->cmd_len >= dev->cmd_total + 1u) {
            atecc608_process_command(dev);
        }
        return 0x00u;

    case STATE_RESP:
        if (dev->rsp_pos < dev->rsp_len) {
            mm_u8 b = dev->rsp_buf[dev->rsp_pos++];
            if (dev->rsp_pos >= dev->rsp_len) {
                dev->state = STATE_IDLE;
                dev->rsp_len = 0;
                dev->rsp_pos = 0;
            }
            return b;
        }
        dev->state = STATE_IDLE;
        return 0x00u;
    }
    return 0x00u;
}

static void atecc608_spi_end(void *opaque)
{
    struct mm_atecc608 *dev = (struct mm_atecc608 *)opaque;
    if (dev == 0 || dev->ffi_ctx == 0) return;
    if (dev->cs_valid) return; /* CS-controlled — handled in xfer */
    if (dev->state == STATE_CMD_DATA && dev->cmd_len > 0) {
        atecc608_process_command(dev);
    } else if (dev->state != STATE_RESP) {
        dev->state = STATE_IDLE;
        dev->cmd_len = 0;
    }
}

static mm_u8 atecc608_spi_cs_level(void *opaque)
{
    struct mm_atecc608 *dev = (struct mm_atecc608 *)opaque;
    mm_u8 cs;
    if (dev == 0) return 1u;
    cs = atecc608_sample_cs(dev);
    if (dev->cs_valid && cs != dev->cs_level) {
        dev->cs_level = cs;
        if (cs != 0u) {
            if (dev->state == STATE_CMD_DATA && dev->cmd_len > 0) {
                atecc608_process_command(dev);
            } else if (dev->state != STATE_RESP) {
                dev->state = STATE_IDLE;
                dev->cmd_len = 0;
            }
        } else {
            dev->state = STATE_WORD_ADDR;
            dev->cmd_len = 0;
            dev->rsp_len = 0;
            dev->rsp_pos = 0;
        }
    }
    return cs;
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

mm_bool mm_atecc608_parse_spec(const char *spec, struct mm_atecc608_cfg *out)
{
    char tmp[512];
    char *tok;
    if (spec == 0 || out == 0) return MM_FALSE;
    memset(out, 0, sizeof(*out));
    snprintf(tmp, sizeof(tmp), "%s", spec);
    tok = strtok(tmp, ":");
    if (tok == 0) return MM_FALSE;
    out->bus = parse_spi_bus(tok);
    if (out->bus < 0) return MM_FALSE;
    while ((tok = strtok(0, ":")) != 0) {
        if (strncmp(tok, "cs=", 3) == 0) {
            if (!parse_gpio(tok + 3, &out->cs_bank, &out->cs_pin)) return MM_FALSE;
            out->cs_valid = MM_TRUE;
        } else if (strncmp(tok, "file=", 5) == 0) {
            snprintf(out->nv_path, sizeof(out->nv_path), "%s", tok + 5);
            out->has_nv_path = MM_TRUE;
        } else {
            return MM_FALSE;
        }
    }
    return MM_TRUE;
}

mm_bool mm_atecc608_register_cfg(const struct mm_atecc608_cfg *cfg)
{
    struct mm_atecc608 *dev;
    struct mm_spi_device spi;

    if (cfg == 0) return MM_FALSE;
    if (g_atecc608_count >= ATECC608_MAX) {
        fprintf(stderr, "atecc608: max devices reached\n");
        return MM_FALSE;
    }
    dev = &g_atecc608[g_atecc608_count];
    memset(dev, 0, sizeof(*dev));
    dev->bus = cfg->bus;
    dev->cs_valid = cfg->cs_valid;
    dev->cs_bank = cfg->cs_bank;
    dev->cs_pin = cfg->cs_pin;
    dev->cs_mask = (cfg->cs_valid && cfg->cs_pin >= 0) ? (1u << (mm_u32)cfg->cs_pin) : 0u;
    dev->cs_level = 1u;
    dev->has_nv_path = cfg->has_nv_path;
    if (cfg->has_nv_path) {
        snprintf(dev->nv_path, sizeof(dev->nv_path), "%s", cfg->nv_path);
    }
    dev->state = STATE_IDLE;

    dev->ffi_ctx = atecc608_ffi_create(cfg->has_nv_path ? dev->nv_path : 0);
    if (dev->ffi_ctx == 0) {
        fprintf(stderr, "atecc608: failed to create simulator context\n");
        return MM_FALSE;
    }

    memset(&spi, 0, sizeof(spi));
    spi.bus = dev->bus;
    spi.xfer = atecc608_spi_xfer;
    spi.end = atecc608_spi_end;
    spi.cs_level = atecc608_spi_cs_level;
    spi.opaque = dev;
    if (!mm_spi_bus_register_device(&spi)) {
        fprintf(stderr, "atecc608: failed to register SPI device\n");
        atecc608_ffi_destroy(dev->ffi_ctx);
        dev->ffi_ctx = 0;
        return MM_FALSE;
    }

    g_atecc608_count++;
    fprintf(stderr, "[ATECC608] Registered on SPI%d", dev->bus);
    if (dev->cs_valid) {
        fprintf(stderr, " cs=P%c%d", (char)('A' + dev->cs_bank), dev->cs_pin);
    }
    if (dev->has_nv_path) {
        fprintf(stderr, " file=%s", dev->nv_path);
    }
    fprintf(stderr, "\n");
    return MM_TRUE;
}

void mm_atecc608_reset_all(void)
{
    size_t i;
    /* The ATECC608 protocol does not expose an out-of-band reset line;
     * a soft reset is done via sleep (word_addr=0x01) which the host
     * driver sends itself.  Nothing to do here. */
    (void)i;
}

void mm_atecc608_shutdown_all(void)
{
    size_t i;
    for (i = 0; i < g_atecc608_count; ++i) {
        if (g_atecc608[i].ffi_ctx != 0) {
            atecc608_ffi_destroy(g_atecc608[i].ffi_ctx);
            g_atecc608[i].ffi_ctx = 0;
        }
    }
    g_atecc608_count = 0;
}
