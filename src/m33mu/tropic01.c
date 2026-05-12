/* tropic01.c -- TROPIC01 secure element simulator (SPI, m33mu integration)
 *
 * Copyright (C) 2026 wolfSSL Inc.                       (TROPIC01 simulator)
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

#include "m33mu/tropic01.h"
#include "m33mu/spi_bus.h"
#include "m33mu/gpio.h"

/* FFI declarations from tropic01-sim (Rust static lib) */
extern void *tropic01_ffi_create(const char *nv_path);
extern void  tropic01_ffi_destroy(void *ctx);
extern void  tropic01_ffi_csn(void *ctx, uint8_t level);
extern uint8_t tropic01_ffi_xfer(void *ctx, uint8_t mosi);

#define TROPIC01_MAX 4

struct mm_tropic01 {
    int bus;
    mm_bool cs_valid;
    int cs_bank;
    int cs_pin;
    mm_u32 cs_mask;
    mm_u8 cs_level;       /* current sampled CSN level (0=asserted, 1=deasserted) */
    mm_bool csn_active;   /* simulator-side latch: whether we last drove csn(0) */
    mm_bool has_nv_path;
    char nv_path[256];
    void *ffi_ctx;
};

static struct mm_tropic01 g_tropic01[TROPIC01_MAX];
static size_t g_tropic01_count;

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

static mm_u8 tropic01_sample_cs(const struct mm_tropic01 *dev)
{
    mm_u32 odr;
    if (!dev->cs_valid) return 0u;
    if (!mm_gpio_bank_reader_present()) return 0u;
    odr = mm_gpio_bank_read(dev->cs_bank);
    return (odr & dev->cs_mask) ? 1u : 0u;
}

static void tropic01_set_csn(struct mm_tropic01 *dev, mm_bool asserted)
{
    if (dev->ffi_ctx == 0) return;
    if (asserted && !dev->csn_active) {
        tropic01_ffi_csn(dev->ffi_ctx, 0u);
        dev->csn_active = MM_TRUE;
    } else if (!asserted && dev->csn_active) {
        tropic01_ffi_csn(dev->ffi_ctx, 1u);
        dev->csn_active = MM_FALSE;
    }
}

/* ------------------------------------------------------------------ */
/* SPI callbacks                                                        */
/* ------------------------------------------------------------------ */

static mm_u8 tropic01_spi_xfer(void *opaque, mm_u8 out)
{
    struct mm_tropic01 *dev = (struct mm_tropic01 *)opaque;
    mm_u8 cs;

    if (dev == 0 || dev->ffi_ctx == 0) return 0xFFu;

    if (dev->cs_valid) {
        /* CS-driven mode: track GPIO edges and drive the FFI CSN line
         * to match. */
        cs = tropic01_sample_cs(dev);
        if (cs != dev->cs_level) {
            dev->cs_level = cs;
            tropic01_set_csn(dev, cs == 0u ? MM_TRUE : MM_FALSE);
        }
        if (cs != 0u) {
            return 0xFFu;
        }
    } else {
        /* CS-less mode: synthesize an always-asserted CSN. The bus
         * driver's `end` callback rises CSN; until then we keep it low. */
        if (!dev->csn_active) {
            tropic01_set_csn(dev, MM_TRUE);
        }
    }

    return tropic01_ffi_xfer(dev->ffi_ctx, out);
}

static void tropic01_spi_end(void *opaque)
{
    struct mm_tropic01 *dev = (struct mm_tropic01 *)opaque;
    if (dev == 0 || dev->ffi_ctx == 0) return;
    if (dev->cs_valid) return; /* CS-controlled — edges handled in xfer */
    tropic01_set_csn(dev, MM_FALSE);
}

static mm_u8 tropic01_spi_cs_level(void *opaque)
{
    struct mm_tropic01 *dev = (struct mm_tropic01 *)opaque;
    mm_u8 cs;
    if (dev == 0) return 1u;
    cs = tropic01_sample_cs(dev);
    if (dev->cs_valid && cs != dev->cs_level) {
        dev->cs_level = cs;
        tropic01_set_csn(dev, cs == 0u ? MM_TRUE : MM_FALSE);
    }
    return cs;
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

mm_bool mm_tropic01_parse_spec(const char *spec, struct mm_tropic01_cfg *out)
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

mm_bool mm_tropic01_register_cfg(const struct mm_tropic01_cfg *cfg)
{
    struct mm_tropic01 *dev;
    struct mm_spi_device spi;

    if (cfg == 0) return MM_FALSE;
    if (g_tropic01_count >= TROPIC01_MAX) {
        fprintf(stderr, "tropic01: max devices reached\n");
        return MM_FALSE;
    }
    dev = &g_tropic01[g_tropic01_count];
    memset(dev, 0, sizeof(*dev));
    dev->bus = cfg->bus;
    dev->cs_valid = cfg->cs_valid;
    dev->cs_bank = cfg->cs_bank;
    dev->cs_pin = cfg->cs_pin;
    dev->cs_mask = (cfg->cs_valid && cfg->cs_pin >= 0) ? (1u << (mm_u32)cfg->cs_pin) : 0u;
    dev->cs_level = 1u;
    dev->csn_active = MM_FALSE;
    dev->has_nv_path = cfg->has_nv_path;
    if (cfg->has_nv_path) {
        snprintf(dev->nv_path, sizeof(dev->nv_path), "%s", cfg->nv_path);
    }

    dev->ffi_ctx = tropic01_ffi_create(cfg->has_nv_path ? dev->nv_path : 0);
    if (dev->ffi_ctx == 0) {
        fprintf(stderr, "tropic01: failed to create simulator context\n");
        return MM_FALSE;
    }

    memset(&spi, 0, sizeof(spi));
    spi.bus = dev->bus;
    spi.xfer = tropic01_spi_xfer;
    spi.end = tropic01_spi_end;
    spi.cs_level = tropic01_spi_cs_level;
    spi.opaque = dev;
    if (!mm_spi_bus_register_device(&spi)) {
        fprintf(stderr, "tropic01: failed to register SPI device\n");
        tropic01_ffi_destroy(dev->ffi_ctx);
        dev->ffi_ctx = 0;
        return MM_FALSE;
    }

    g_tropic01_count++;
    fprintf(stderr, "[TROPIC01] Registered on SPI%d", dev->bus);
    if (dev->cs_valid) {
        fprintf(stderr, " cs=P%c%d", (char)('A' + dev->cs_bank), dev->cs_pin);
    }
    if (dev->has_nv_path) {
        fprintf(stderr, " file=%s", dev->nv_path);
    }
    fprintf(stderr, "\n");
    return MM_TRUE;
}

void mm_tropic01_reset_all(void)
{
    /* TROPIC01 has no out-of-band reset; the host drives the L2 STARTUP
     * request to reinitialise. */
}

void mm_tropic01_shutdown_all(void)
{
    size_t i;
    for (i = 0; i < g_tropic01_count; ++i) {
        if (g_tropic01[i].ffi_ctx != 0) {
            tropic01_ffi_destroy(g_tropic01[i].ffi_ctx);
            g_tropic01[i].ffi_ctx = 0;
        }
    }
    g_tropic01_count = 0;
}
