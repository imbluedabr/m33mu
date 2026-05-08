/* stsafe.c -- STMicro STSAFE-A120 secure element simulator (I2C, m33mu integration)
 *
 * Copyright (C) 2026 wolfSSL Inc.                       (STSAFE-A120 simulator)
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

#include "m33mu/stsafe.h"
#include "m33mu/i2c_bus.h"

/* FFI declarations from stsafe-a120-sim (Rust static lib) */
extern void *stsafe_ffi_create(const char *nv_path);
extern void  stsafe_ffi_destroy(void *ctx);
extern bool  stsafe_ffi_write(void *ctx, const uint8_t *data, size_t len);
extern bool  stsafe_ffi_read(void *ctx, uint8_t *buf, size_t len, size_t *nread_out);

#define STSAFE_MAX 4

struct mm_stsafe {
    int bus;
    mm_u8 addr;
    mm_bool has_nv_path;
    char nv_path[256];
    void *ffi_ctx;
};

static struct mm_stsafe g_stsafe[STSAFE_MAX];
static size_t g_stsafe_count;

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

static mm_bool stsafe_i2c_write(void *opaque, mm_u8 addr,
                                const mm_u8 *data, size_t len)
{
    struct mm_stsafe *st = (struct mm_stsafe *)opaque;
    (void)addr;
    if (st == 0 || st->ffi_ctx == 0) return MM_FALSE;
    return stsafe_ffi_write(st->ffi_ctx, data, len) ? MM_TRUE : MM_FALSE;
}

static mm_bool stsafe_i2c_read(void *opaque, mm_u8 addr,
                               mm_u8 *data, size_t len)
{
    struct mm_stsafe *st = (struct mm_stsafe *)opaque;
    size_t nread = 0;
    mm_bool ok;
    (void)addr;
    if (st == 0 || st->ffi_ctx == 0) return MM_FALSE;
    ok = stsafe_ffi_read(st->ffi_ctx, data, len, &nread) ? MM_TRUE : MM_FALSE;
    return ok;
}

static void stsafe_i2c_reset(void *opaque)
{
    /* STSAFE-A120 internal state is preserved across bus resets;
     * the host driver handles protocol-level soft reset. */
    (void)opaque;
}

static void stsafe_i2c_shutdown(void *opaque)
{
    struct mm_stsafe *st = (struct mm_stsafe *)opaque;
    if (st != 0 && st->ffi_ctx != 0) {
        stsafe_ffi_destroy(st->ffi_ctx);
        st->ffi_ctx = 0;
    }
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

mm_bool mm_stsafe_parse_spec(const char *spec, struct mm_stsafe_cfg *out)
{
    char tmp[512];
    char *tok;
    if (spec == 0 || out == 0) return MM_FALSE;
    memset(out, 0, sizeof(*out));
    out->addr = MM_STSAFE_DEFAULT_ADDR;
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

mm_bool mm_stsafe_register_cfg(const struct mm_stsafe_cfg *cfg)
{
    struct mm_stsafe *st;
    struct mm_i2c_device dev;

    if (cfg == 0) return MM_FALSE;
    if (g_stsafe_count >= STSAFE_MAX) {
        fprintf(stderr, "stsafe: max devices reached\n");
        return MM_FALSE;
    }
    st = &g_stsafe[g_stsafe_count];
    memset(st, 0, sizeof(*st));
    st->bus = cfg->bus;
    st->addr = cfg->addr;
    st->has_nv_path = cfg->has_nv_path;
    if (cfg->has_nv_path) {
        snprintf(st->nv_path, sizeof(st->nv_path), "%s", cfg->nv_path);
    }

    st->ffi_ctx = stsafe_ffi_create(cfg->has_nv_path ? st->nv_path : 0);
    if (st->ffi_ctx == 0) {
        fprintf(stderr, "stsafe: failed to create simulator context\n");
        return MM_FALSE;
    }

    memset(&dev, 0, sizeof(dev));
    dev.bus = st->bus;
    dev.addr = st->addr;
    dev.write = stsafe_i2c_write;
    dev.read = stsafe_i2c_read;
    dev.reset = stsafe_i2c_reset;
    dev.shutdown = stsafe_i2c_shutdown;
    dev.opaque = st;
    if (!mm_i2c_bus_register_device(&dev)) {
        fprintf(stderr, "stsafe: failed to register I2C device\n");
        stsafe_ffi_destroy(st->ffi_ctx);
        st->ffi_ctx = 0;
        return MM_FALSE;
    }

    g_stsafe_count++;
    fprintf(stderr, "[STSAFE-A120] Registered on I2C%d addr=0x%02x", st->bus, st->addr);
    if (st->has_nv_path) {
        fprintf(stderr, " file=%s", st->nv_path);
    }
    fprintf(stderr, "\n");
    return MM_TRUE;
}

void mm_stsafe_reset_all(void)
{
    /* No-op: see stsafe_i2c_reset */
}

void mm_stsafe_shutdown_all(void)
{
    size_t i;
    for (i = 0; i < g_stsafe_count; ++i) {
        if (g_stsafe[i].ffi_ctx != 0) {
            stsafe_ffi_destroy(g_stsafe[i].ffi_ctx);
            g_stsafe[i].ffi_ctx = 0;
        }
    }
    g_stsafe_count = 0;
}
