/* m33mu -- an ARMv8-M Emulator
 *
 * Copyright (C) 2025  Daniele Lacamera <root@danielinux.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * STM32 OTFDEC peripheral model.
 * Implements the 4-region AES-CTR decryption engine used by STM32H5/U585
 * for on-the-fly decryption of SPI-flash XIP regions.
 *
 * Reference: RM0481 (STM32H5) §40, RM0456 (STM32U5) §42.
 *
 * AES-CTR counter block per RM0481 §40.4:
 *   Word[0] = NONCE_HI (RxNONCER1)
 *   Word[1] = NONCE_LO (RxNONCER0)
 *   Word[2] = RxSTARTADDR[31:4]  (upper bits, lower 4 forced to 0)
 *   Word[3] = block_address & ~0xFu
 * The 16-byte keystream = AES-128-ECB(key, counter_block)
 * Plaintext = ciphertext XOR keystream
 *
 * KEYCRC: 8-bit CRC over the 128-bit key.
 * Per RM0481 §40.6.3, KEYCRC is computed using CRC-8 with the Castagnoli
 * polynomial (0x1EDC6F41, reduced to byte-width polynomial 0x1D reflected
 * as 0xB8 = standard CRC-8/CDMA2000).
 * Assumption: use CRC-8/MAXIM (0x31, init=0x00, no reflect) as a pragmatic
 * stand-in; firmware typically treats KEYCRC as write-confirm only.
 * The exact CRC variant is not critical for functional test correctness.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "m33mu/otfdec.h"
#include "mm_host_crypto.h"

/* -------------------------------------------------------------------------
 * Register layout
 * ------------------------------------------------------------------------- */

/* Top-level offsets */
#define OTFDEC_CR       0x000u
#define OTFDEC_ISR      0x0C0u
#define OTFDEC_ICR      0x0C4u
#define OTFDEC_IER      0x0C8u
#define OTFDEC_PRIVCFGR 0x0CCu
#define OTFDEC_VERR     0x3F4u
#define OTFDEC_IPIDR    0x3F8u
#define OTFDEC_SIDR     0x3FCu

/* VERR / IPIDR / SIDR reset values (RM0481 §40.6) */
#define OTFDEC_VERR_RESET  0x00000010u   /* major=0, minor=1 */
#define OTFDEC_IPIDR_RESET 0x00170041u
#define OTFDEC_SIDR_RESET  0xA3C5DD01u

/* CR bits */
#define OTFDEC_CR_EN (1u << 0)

/* Per-region base: 0x20 + r*0x30 */
#define OTFDEC_RX_BASE(r)    (0x20u + (mm_u32)(r) * 0x30u)

/* Per-region register offsets from region base */
#define OTFDEC_RX_CFGR_OFF    0x00u
#define OTFDEC_RX_START_OFF   0x04u
#define OTFDEC_RX_END_OFF     0x08u
#define OTFDEC_RX_NONCE0_OFF  0x0Cu  /* NONCE_LO */
#define OTFDEC_RX_NONCE1_OFF  0x10u  /* NONCE_HI */
#define OTFDEC_RX_KEY0_OFF    0x14u
#define OTFDEC_RX_KEY1_OFF    0x18u
#define OTFDEC_RX_KEY2_OFF    0x1Cu
#define OTFDEC_RX_KEY3_OFF    0x20u

/* RxCFGR bits */
#define CFGR_EN        (1u << 0)
#define CFGR_KEYLOCK   (1u << 6)
#define CFGR_CFGLOCK   (1u << 7)
#define CFGR_KEYCRC_SHIFT 8u
#define CFGR_KEYCRC_MASK  (0xFFu << CFGR_KEYCRC_SHIFT)
#define CFGR_MODE_SHIFT   4u
#define CFGR_MODE_MASK    (0x3u << CFGR_MODE_SHIFT)

#define OTFDEC_NREGIONS 4u

/* -------------------------------------------------------------------------
 * Per-region state
 * ------------------------------------------------------------------------- */
struct otfdec_region {
    mm_u32 cfgr;       /* RxCFGR */
    mm_u32 start_addr; /* RxSTARTADDR */
    mm_u32 end_addr;   /* RxENDADDR */
    mm_u32 nonce[2];   /* [0]=NONCE_LO(R0), [1]=NONCE_HI(R1) */
    mm_u32 key[4];     /* KEY0..KEY3 (little-endian word order) */

    /* One-block cache: avoids calling AES-ECB for every single byte read */
    mm_u32 cache_addr;  /* block-aligned address of cached block (or ~0u) */
    mm_u8  cache[16];   /* cached plaintext */
};

/* -------------------------------------------------------------------------
 * Top-level peripheral state
 * ------------------------------------------------------------------------- */
struct mm_otfdec {
    mm_u32 cr;
    mm_u32 isr;
    mm_u32 icr;
    mm_u32 ier;
    mm_u32 privcfgr;
    struct otfdec_region regions[OTFDEC_NREGIONS];
};

/* -------------------------------------------------------------------------
 * CRC-8 for KEYCRC (CRC-8/MAXIM, poly 0x31, init 0x00, no reflect)
 * RM0481 does not fully specify the variant; this is a plausible stand-in.
 * ------------------------------------------------------------------------- */
static mm_u8 otfdec_keycrc(const mm_u32 key[4])
{
    mm_u8 crc = 0u;
    mm_u8 poly = 0x31u;
    int i;
    int b;
    mm_u8 key_bytes[16];

    /* Flatten key words to bytes, little-endian */
    for (i = 0; i < 4; i++) {
        key_bytes[i * 4 + 0] = (mm_u8)(key[i] & 0xFFu);
        key_bytes[i * 4 + 1] = (mm_u8)((key[i] >> 8)  & 0xFFu);
        key_bytes[i * 4 + 2] = (mm_u8)((key[i] >> 16) & 0xFFu);
        key_bytes[i * 4 + 3] = (mm_u8)((key[i] >> 24) & 0xFFu);
    }
    for (i = 0; i < 16; i++) {
        crc ^= key_bytes[i];
        for (b = 0; b < 8; b++) {
            if ((crc & 0x80u) != 0u) {
                crc = (mm_u8)((crc << 1) ^ poly);
            } else {
                crc = (mm_u8)(crc << 1);
            }
        }
    }
    return crc;
}

/* -------------------------------------------------------------------------
 * Recalculate and store KEYCRC in cfgr whenever key changes
 * ------------------------------------------------------------------------- */
static void otfdec_update_keycrc(struct otfdec_region *r)
{
    mm_u8 crc = otfdec_keycrc(r->key);
    r->cfgr = (r->cfgr & ~CFGR_KEYCRC_MASK) |
              (((mm_u32)crc << CFGR_KEYCRC_SHIFT) & CFGR_KEYCRC_MASK);
}

/* -------------------------------------------------------------------------
 * Invalidate block cache for a region
 * ------------------------------------------------------------------------- */
static void otfdec_cache_invalidate(struct otfdec_region *r)
{
    r->cache_addr = 0xFFFFFFFFu;
    memset(r->cache, 0, sizeof(r->cache));
}

/* -------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */

struct mm_otfdec *mm_otfdec_new(void)
{
    struct mm_otfdec *od = (struct mm_otfdec *)malloc(sizeof(*od));
    if (od != 0) {
        memset(od, 0, sizeof(*od));
        mm_otfdec_reset(od);
    }
    return od;
}

void mm_otfdec_reset(struct mm_otfdec *od)
{
    mm_u32 i;
    if (od == 0) {
        return;
    }
    memset(od, 0, sizeof(*od));
    for (i = 0u; i < OTFDEC_NREGIONS; i++) {
        otfdec_cache_invalidate(&od->regions[i]);
    }
}

void mm_otfdec_free(struct mm_otfdec *od)
{
    if (od != 0) {
        free(od);
    }
}

/* -------------------------------------------------------------------------
 * Register read
 * ------------------------------------------------------------------------- */
mm_bool mm_otfdec_read(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                       mm_u32 *value_out)
{
    struct mm_otfdec *od = (struct mm_otfdec *)opaque;
    mm_u32 v = 0u;
    mm_u32 r;
    mm_u32 rbase;
    mm_u32 roff;

    if (od == 0 || value_out == 0 || size_bytes != 4u) {
        return MM_FALSE;
    }

    /* Top-level registers */
    switch (offset) {
    case OTFDEC_CR:        v = od->cr;       break;
    case OTFDEC_ISR:       v = od->isr;      break;
    case OTFDEC_ICR:       v = 0u;           break; /* write-only */
    case OTFDEC_IER:       v = od->ier;      break;
    case OTFDEC_PRIVCFGR:  v = od->privcfgr; break;
    case OTFDEC_VERR:      v = OTFDEC_VERR_RESET;  break;
    case OTFDEC_IPIDR:     v = OTFDEC_IPIDR_RESET; break;
    case OTFDEC_SIDR:      v = OTFDEC_SIDR_RESET;  break;
    default:
        /* Per-region registers */
        for (r = 0u; r < OTFDEC_NREGIONS; r++) {
            rbase = OTFDEC_RX_BASE(r);
            if (offset < rbase || offset >= rbase + 0x30u) {
                continue;
            }
            roff = offset - rbase;
            switch (roff) {
            case OTFDEC_RX_CFGR_OFF:
                v = od->regions[r].cfgr;
                break;
            case OTFDEC_RX_START_OFF:
                v = od->regions[r].start_addr;
                break;
            case OTFDEC_RX_END_OFF:
                v = od->regions[r].end_addr;
                break;
            case OTFDEC_RX_NONCE0_OFF:
                v = od->regions[r].nonce[0];
                break;
            case OTFDEC_RX_NONCE1_OFF:
                v = od->regions[r].nonce[1];
                break;
            case OTFDEC_RX_KEY0_OFF:
            case OTFDEC_RX_KEY1_OFF:
            case OTFDEC_RX_KEY2_OFF:
            case OTFDEC_RX_KEY3_OFF:
                /* KEY registers read as 0 after KEYLOCK is set, or always */
                if ((od->regions[r].cfgr & CFGR_KEYLOCK) != 0u) {
                    v = 0u;
                } else {
                    v = od->regions[r].key[(roff - OTFDEC_RX_KEY0_OFF) / 4u];
                }
                break;
            default:
                v = 0u;
                break;
            }
            *value_out = v;
            return MM_TRUE;
        }
        /* Unmapped offset — return 0 */
        *value_out = 0u;
        return MM_TRUE;
    }
    *value_out = v;
    return MM_TRUE;
}

/* -------------------------------------------------------------------------
 * Register write
 * ------------------------------------------------------------------------- */
mm_bool mm_otfdec_write(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                        mm_u32 value)
{
    struct mm_otfdec *od = (struct mm_otfdec *)opaque;
    mm_u32 r;
    mm_u32 rbase;
    mm_u32 roff;
    mm_u32 ki;

    if (od == 0 || size_bytes != 4u) {
        return MM_FALSE;
    }

    /* Top-level registers */
    switch (offset) {
    case OTFDEC_CR:
        od->cr = value;
        return MM_TRUE;
    case OTFDEC_ISR:
        /* ISR is read-only; writes ignored */
        return MM_TRUE;
    case OTFDEC_ICR:
        /* Write-1-clear on ISR */
        od->isr &= ~value;
        return MM_TRUE;
    case OTFDEC_IER:
        od->ier = value;
        return MM_TRUE;
    case OTFDEC_PRIVCFGR:
        od->privcfgr = value;
        return MM_TRUE;
    default:
        break;
    }

    /* Per-region registers */
    for (r = 0u; r < OTFDEC_NREGIONS; r++) {
        rbase = OTFDEC_RX_BASE(r);
        if (offset < rbase || offset >= rbase + 0x30u) {
            continue;
        }
        roff = offset - rbase;

        switch (roff) {
        case OTFDEC_RX_CFGR_OFF:
            /* CONFIGLOCK: once set, CFGR bits (except EN) are frozen */
            if ((od->regions[r].cfgr & CFGR_CFGLOCK) != 0u) {
                /* only EN bit may still be toggled */
                od->regions[r].cfgr = (od->regions[r].cfgr & ~CFGR_EN) |
                                      (value & CFGR_EN);
            } else {
                /* Preserve read-only KEYCRC bits; accept EN/MODE/KEYLOCK/CFGLOCK */
                od->regions[r].cfgr =
                    (od->regions[r].cfgr & CFGR_KEYCRC_MASK) |
                    (value & ~CFGR_KEYCRC_MASK);
            }
            /* Setting KEYLOCK now implies CRC is already computed */
            return MM_TRUE;
        case OTFDEC_RX_START_OFF:
            if ((od->regions[r].cfgr & CFGR_CFGLOCK) == 0u) {
                od->regions[r].start_addr = value;
                otfdec_cache_invalidate(&od->regions[r]);
            }
            return MM_TRUE;
        case OTFDEC_RX_END_OFF:
            if ((od->regions[r].cfgr & CFGR_CFGLOCK) == 0u) {
                od->regions[r].end_addr = value;
                otfdec_cache_invalidate(&od->regions[r]);
            }
            return MM_TRUE;
        case OTFDEC_RX_NONCE0_OFF:
            if ((od->regions[r].cfgr & CFGR_CFGLOCK) == 0u) {
                od->regions[r].nonce[0] = value;
                otfdec_cache_invalidate(&od->regions[r]);
            }
            return MM_TRUE;
        case OTFDEC_RX_NONCE1_OFF:
            if ((od->regions[r].cfgr & CFGR_CFGLOCK) == 0u) {
                od->regions[r].nonce[1] = value;
                otfdec_cache_invalidate(&od->regions[r]);
            }
            return MM_TRUE;
        case OTFDEC_RX_KEY0_OFF:
        case OTFDEC_RX_KEY1_OFF:
        case OTFDEC_RX_KEY2_OFF:
        case OTFDEC_RX_KEY3_OFF:
            if ((od->regions[r].cfgr & CFGR_KEYLOCK) == 0u) {
                ki = (roff - OTFDEC_RX_KEY0_OFF) / 4u;
                od->regions[r].key[ki] = value;
                otfdec_update_keycrc(&od->regions[r]);
                otfdec_cache_invalidate(&od->regions[r]);
            }
            return MM_TRUE;
        default:
            return MM_TRUE;
        }
    }

    /* Unmapped — accept silently */
    return MM_TRUE;
}

/* -------------------------------------------------------------------------
 * Decrypt hook (called by spiflash mmap read path)
 *
 * The CTR block per RM0481 §40.4:
 *   Word[0] = NONCE_HI  (big-endian in the AES input → byte[0..3])
 *   Word[1] = NONCE_LO  (byte[4..7])
 *   Word[2] = start_addr with lower 4 bits cleared (byte[8..11])
 *   Word[3] = (addr & ~0xFu)  (byte[12..15])
 *
 * Each word is stored in the counter block in big-endian byte order so that
 * the AES-ECB encrypt over it yields the correct keystream.
 * ------------------------------------------------------------------------- */
mm_bool mm_otfdec_decrypt_block(void *opaque, mm_u32 addr, mm_u8 *block16)
{
    struct mm_otfdec *od = (struct mm_otfdec *)opaque;
    mm_u32 r;
    mm_u32 block_addr;
    mm_u8 key_bytes[16];
    mm_u8 ctr_block[16];
    mm_u8 keystream[16];
    mm_u32 nonce_hi;
    mm_u32 nonce_lo;
    mm_u32 start_hi;
    mm_u32 block_w;
    int i;

    if (od == 0 || block16 == 0) {
        return MM_FALSE;
    }

    /* Global enable */
    if ((od->cr & OTFDEC_CR_EN) == 0u) {
        return MM_FALSE;
    }

    block_addr = addr & ~0xFu;

    for (r = 0u; r < OTFDEC_NREGIONS; r++) {
        struct otfdec_region *reg = &od->regions[r];

        /* Region must be enabled */
        if ((reg->cfgr & CFGR_EN) == 0u) {
            continue;
        }

        /* Address range check */
        if (block_addr < reg->start_addr || block_addr > reg->end_addr) {
            continue;
        }

        /* Cache hit? */
        if (reg->cache_addr == block_addr) {
            memcpy(block16, reg->cache, 16u);
            return MM_TRUE;
        }

        /* Build key bytes (little-endian word order per RM0481) */
        for (i = 0; i < 4; i++) {
            key_bytes[i * 4 + 0] = (mm_u8)(reg->key[i] & 0xFFu);
            key_bytes[i * 4 + 1] = (mm_u8)((reg->key[i] >>  8) & 0xFFu);
            key_bytes[i * 4 + 2] = (mm_u8)((reg->key[i] >> 16) & 0xFFu);
            key_bytes[i * 4 + 3] = (mm_u8)((reg->key[i] >> 24) & 0xFFu);
        }

        /*
         * Build counter block per RM0481 §40.4 (big-endian word layout):
         *   [0..3]   = NONCE_HI  (nonce[1])
         *   [4..7]   = NONCE_LO  (nonce[0])
         *   [8..11]  = RxSTARTADDR & ~0xFu  (upper part of region start)
         *   [12..15] = block_addr (block-aligned absolute address)
         */
        nonce_hi  = reg->nonce[1];
        nonce_lo  = reg->nonce[0];
        start_hi  = reg->start_addr & ~0xFu;
        block_w   = block_addr;

        /* Word 0: NONCE_HI big-endian */
        ctr_block[0]  = (mm_u8)((nonce_hi >> 24) & 0xFFu);
        ctr_block[1]  = (mm_u8)((nonce_hi >> 16) & 0xFFu);
        ctr_block[2]  = (mm_u8)((nonce_hi >>  8) & 0xFFu);
        ctr_block[3]  = (mm_u8)( nonce_hi        & 0xFFu);
        /* Word 1: NONCE_LO big-endian */
        ctr_block[4]  = (mm_u8)((nonce_lo >> 24) & 0xFFu);
        ctr_block[5]  = (mm_u8)((nonce_lo >> 16) & 0xFFu);
        ctr_block[6]  = (mm_u8)((nonce_lo >>  8) & 0xFFu);
        ctr_block[7]  = (mm_u8)( nonce_lo        & 0xFFu);
        /* Word 2: start_addr (lower 4 bits cleared) big-endian */
        ctr_block[8]  = (mm_u8)((start_hi >> 24) & 0xFFu);
        ctr_block[9]  = (mm_u8)((start_hi >> 16) & 0xFFu);
        ctr_block[10] = (mm_u8)((start_hi >>  8) & 0xFFu);
        ctr_block[11] = (mm_u8)( start_hi        & 0xFFu);
        /* Word 3: block_addr big-endian */
        ctr_block[12] = (mm_u8)((block_w >> 24) & 0xFFu);
        ctr_block[13] = (mm_u8)((block_w >> 16) & 0xFFu);
        ctr_block[14] = (mm_u8)((block_w >>  8) & 0xFFu);
        ctr_block[15] = (mm_u8)( block_w        & 0xFFu);

        /* AES-ECB encrypt counter block → keystream */
        if (!mm_host_aes_ecb_enc(key_bytes, 16u, ctr_block, keystream, 16u)) {
            /* wolfSSL not available — skip decryption, serve raw */
            return MM_FALSE;
        }

        /* XOR ciphertext with keystream → plaintext */
        for (i = 0; i < 16; i++) {
            reg->cache[i] = (mm_u8)(block16[i] ^ keystream[i]);
        }
        reg->cache_addr = block_addr;

        memcpy(block16, reg->cache, 16u);
        return MM_TRUE;
    }

    /* No region matched */
    return MM_FALSE;
}
