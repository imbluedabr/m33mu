/* se050.c -- NXP SE050 secure element simulator (I2C, m33mu integration)
 *
 * Copyright (C) 2026 wolfSSL Inc.                       (SE050 simulator)
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

#include "m33mu/se050.h"
#include "m33mu/i2c_bus.h"

/* FFI declarations from se050-sim (Rust static lib) */
extern void *se050_ffi_create(const char *nv_path);
extern void  se050_ffi_destroy(void *ctx);
extern bool  se050_ffi_write(void *ctx, const uint8_t *data, size_t len);
extern bool  se050_ffi_read(void *ctx, uint8_t *buf, size_t len);

#define SE050_MAX 4

struct mm_se050 {
    int bus;
    mm_u8 addr;
    mm_bool has_nv_path;
    char nv_path[256];
    void *ffi_ctx;
};

static struct mm_se050 g_se050[SE050_MAX];
static size_t g_se050_count;

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

static int parse_i2c_bus(const char *s)
{
    char *end;
    long v;
    if (s == 0 || strncmp(s, "I2C", 3) != 0 || s[3] == '\0') return -1;
    v = strtol(s + 3, &end, 10);
    if (*end != '\0' || v < 0 || v > 255) return -1;
    return (int)v;
}

/* ------------------------------------------------------------------ */
/* I2C callbacks                                                        */
/* ------------------------------------------------------------------ */

static mm_bool se050_i2c_write(void *opaque, mm_u8 addr,
                               const mm_u8 *data, size_t len)
{
    struct mm_se050 *se = (struct mm_se050 *)opaque;
    (void)addr;
    if (se == 0 || se->ffi_ctx == 0) return MM_FALSE;
    return se050_ffi_write(se->ffi_ctx, data, len) ? MM_TRUE : MM_FALSE;
}

static mm_bool se050_i2c_read(void *opaque, mm_u8 addr,
                              mm_u8 *data, size_t len)
{
    struct mm_se050 *se = (struct mm_se050 *)opaque;
    (void)addr;
    if (se == 0 || se->ffi_ctx == 0) return MM_FALSE;
    return se050_ffi_read(se->ffi_ctx, data, len) ? MM_TRUE : MM_FALSE;
}

static void se050_i2c_reset(void *opaque)
{
    /* The SE050 T=1 state persists across bus resets; the host driver
     * sends a soft-reset S-frame itself when it needs to resync. */
    (void)opaque;
}

static void se050_i2c_shutdown(void *opaque)
{
    struct mm_se050 *se = (struct mm_se050 *)opaque;
    if (se != 0 && se->ffi_ctx != 0) {
        se050_ffi_destroy(se->ffi_ctx);
        se->ffi_ctx = 0;
    }
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

mm_bool mm_se050_parse_spec(const char *spec, struct mm_se050_cfg *out)
{
    char tmp[512];
    char *tok;
    if (spec == 0 || out == 0) return MM_FALSE;
    memset(out, 0, sizeof(*out));
    out->addr = MM_SE050_DEFAULT_ADDR;
    snprintf(tmp, sizeof(tmp), "%s", spec);
    tok = strtok(tmp, ":");
    if (tok == 0) return MM_FALSE;
    out->bus = parse_i2c_bus(tok);
    if (out->bus < 0) return MM_FALSE;
    while ((tok = strtok(0, ":")) != 0) {
        if (strncmp(tok, "addr=", 5) == 0) {
            char *end;
            unsigned long v = strtoul(tok + 5, &end, 16);
            if (*end != '\0' || v > 0x7Fu) return MM_FALSE;
            out->addr = (mm_u8)v;
        } else if (strncmp(tok, "file=", 5) == 0) {
            snprintf(out->nv_path, sizeof(out->nv_path), "%s", tok + 5);
            out->has_nv_path = MM_TRUE;
        } else {
            return MM_FALSE;
        }
    }
    return MM_TRUE;
}

mm_bool mm_se050_register_cfg(const struct mm_se050_cfg *cfg)
{
    struct mm_se050 *se;
    struct mm_i2c_device dev;

    if (cfg == 0) return MM_FALSE;
    if (g_se050_count >= SE050_MAX) {
        fprintf(stderr, "se050: max devices reached\n");
        return MM_FALSE;
    }
    se = &g_se050[g_se050_count];
    memset(se, 0, sizeof(*se));
    se->bus = cfg->bus;
    se->addr = cfg->addr;
    se->has_nv_path = cfg->has_nv_path;
    if (cfg->has_nv_path) {
        snprintf(se->nv_path, sizeof(se->nv_path), "%s", cfg->nv_path);
    }

    se->ffi_ctx = se050_ffi_create(cfg->has_nv_path ? se->nv_path : 0);
    if (se->ffi_ctx == 0) {
        fprintf(stderr, "se050: failed to create simulator context\n");
        return MM_FALSE;
    }

    memset(&dev, 0, sizeof(dev));
    dev.bus = se->bus;
    dev.addr = se->addr;
    dev.write = se050_i2c_write;
    dev.read = se050_i2c_read;
    dev.reset = se050_i2c_reset;
    dev.shutdown = se050_i2c_shutdown;
    dev.opaque = se;
    if (!mm_i2c_bus_register_device(&dev)) {
        fprintf(stderr, "se050: failed to register I2C device\n");
        se050_ffi_destroy(se->ffi_ctx);
        se->ffi_ctx = 0;
        return MM_FALSE;
    }

    g_se050_count++;
    fprintf(stderr, "[SE050] Registered on I2C%d addr=0x%02x", se->bus, se->addr);
    if (se->has_nv_path) {
        fprintf(stderr, " file=%s", se->nv_path);
    }
    fprintf(stderr, "\n");
    return MM_TRUE;
}

void mm_se050_reset_all(void)
{
    /* No-op: see se050_i2c_reset */
}

void mm_se050_shutdown_all(void)
{
    size_t i;
    for (i = 0; i < g_se050_count; ++i) {
        if (g_se050[i].ffi_ctx != 0) {
            se050_ffi_destroy(g_se050[i].ffi_ctx);
            g_se050[i].ffi_ctx = 0;
        }
    }
    g_se050_count = 0;
}
