/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Arm CryptoCell-312 peripheral model for nRF5340.
 *
 * The nRF5340 maps the CryptoCell subsystem as two adjacent regions:
 *  0x50844000  CRYPTOCELL: just the ENABLE register at offset 0x500
 *  0x50845000  CC engines: AES (0x400-0x527), HASH (0x640-0x7EC),
 *              DIN (0xC00-0xC5B), DOUT (0xD00-0xD5B),
 *              CTL (0x900-0x933), HOST_RGF (0xA00-0xA83)
 * Both regions are secure-only (no NS alias).
 *
 * This model implements only what the firmware test exercises:
 *  - AES-128-CBC encrypt/decrypt via mm_host_aes_cbc_enc/dec
 *  - SHA-256 via mm_host_sha256_stream_*
 * Other operation types set IRR.ERROR and return.
 *
 * Register usage modelled (all at 0x50845000 base = "engine" region):
 *  AES:
 *    0x400 AES_KEY_0[8]      -- write AES key (128/192/256 bit)
 *    0x440 AES_IV_0[4]       -- write IV (CBC mode)
 *    0x4BC AES_REMAINING_BYTES -- byte count
 *    0x4C0 AES_CONTROL       -- mode/direction bits
 *  HASH:
 *    0x640 HASH_H[8]         -- initial hash state (for chaining; usually 0)
 *    0x684 HASH_PAD_AUTO     -- trigger auto-pad on final DMA
 *    0x694 HASH_INIT_STATE   -- init state trigger
 *    0x7C0 HASH_CONTROL      -- mode bits (SHA-256=2)
 *    0x7C4 HASH_PAD          -- hardware padding enable
 *  DIN DMA:
 *    0xC28 SRC_MEM_ADDR      -- source address (must be set before size)
 *    0xC2C SRC_MEM_SIZE      -- byte count; write triggers DMA (and operation)
 *  DOUT DMA:
 *    0xD28 DST_MEM_ADDR      -- destination address
 *    0xD2C DST_MEM_SIZE      -- byte count
 *  CTL:
 *    0x900 CRYPTO_CTL        -- selects hash/AES engine flow
 *  HOST_RGF:
 *    0xA00 IRR               -- interrupt request (read-only; cleared via ICR)
 *    0xA04 IMR               -- interrupt mask (0 = unmasked = interrupt enabled)
 *    0xA08 ICR               -- interrupt clear (write-1-to-clear)
 *    0xA0C ENDIANNESS        -- endianness config (stored, not acted on)
 *    0xA24 HOST_SIGNATURE    -- reads 0xDCC63116
 *    0xA28 HOST_BOOT         -- reads 0x01
 *    0xA7C HOST_CC_IS_IDLE   -- reads 1 (always idle in our model)
 *  CRYPTOCELL (0x50844000 region):
 *    0x500 ENABLE            -- write 1 to enable subsystem
 *
 * TODO: align descriptor format with real CC-312 nrfx driver once
 *       full driver source has been studied in detail.
 */

#ifndef NRF5340_CRYPTOCELL_H
#define NRF5340_CRYPTOCELL_H

#include "m33mu/types.h"

struct mm_nvic;
struct mm_memmap;

/* Opaque peripheral state */
struct mm_nrf5340_cryptocell;

/* Lifecycle */
struct mm_nrf5340_cryptocell *mm_nrf5340_cryptocell_new(void);
void mm_nrf5340_cryptocell_reset(struct mm_nrf5340_cryptocell *cc);
void mm_nrf5340_cryptocell_free(struct mm_nrf5340_cryptocell *cc);

/* Dependency injection */
void mm_nrf5340_cryptocell_set_nvic(struct mm_nrf5340_cryptocell *cc,
                                    struct mm_nvic *nvic);

/* Memory access helper - engine reads/writes target address space via memmap */
void mm_nrf5340_cryptocell_set_memmap(struct mm_nrf5340_cryptocell *cc,
                                      struct mm_memmap *map);

/*
 * MMIO callbacks for the CRYPTOCELL control region (0x50844000, size 0x1000).
 * Only ENABLE @ offset 0x500 is meaningful.
 */
mm_bool mm_nrf5340_cryptocell_ctrl_read(void *opaque, mm_u32 offset,
                                        mm_u32 size_bytes, mm_u32 *value_out);
mm_bool mm_nrf5340_cryptocell_ctrl_write(void *opaque, mm_u32 offset,
                                         mm_u32 size_bytes, mm_u32 value);

/*
 * MMIO callbacks for the CC engine region (0x50845000, size 0x2000).
 * Covers AES/HASH/DIN/DOUT/CTL/HOST_RGF sub-blocks.
 */
mm_bool mm_nrf5340_cryptocell_read(void *opaque, mm_u32 offset,
                                   mm_u32 size_bytes, mm_u32 *value_out);
mm_bool mm_nrf5340_cryptocell_write(void *opaque, mm_u32 offset,
                                    mm_u32 size_bytes, mm_u32 value);

#endif /* NRF5340_CRYPTOCELL_H */
