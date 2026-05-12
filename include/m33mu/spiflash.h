/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef M33MU_SPIFLASH_H
#define M33MU_SPIFLASH_H

#include "m33mu/types.h"

struct mmio_bus;
struct mm_prot_ctx;

struct mm_spiflash_cfg {
    int bus; /* 1-based SPI index (SPI1 == 1) */
    mm_u32 size;
    mm_bool mmap;
    mm_u32 mmap_base;
    mm_bool cs_valid;
    int cs_bank;
    int cs_pin;
    char path[256];
};

struct mm_spiflash_info {
    int bus;
    mm_u32 size;
    mm_bool mmap;
    mm_u32 mmap_base;
    mm_bool cs_valid;
    int cs_bank;
    int cs_pin;
    char path[256];
};

mm_bool mm_spiflash_parse_spec(const char *spec, struct mm_spiflash_cfg *out);
mm_bool mm_spiflash_register_cfg(const struct mm_spiflash_cfg *cfg);
void mm_spiflash_reset_all(void);
void mm_spiflash_shutdown_all(void);
void mm_spiflash_register_mmap_regions(struct mmio_bus *bus);
void mm_spiflash_register_prot_regions(struct mm_prot_ctx *prot);
size_t mm_spiflash_count(void);
mm_bool mm_spiflash_get_info(size_t index, struct mm_spiflash_info *out);
mm_bool mm_spiflash_get_storage(size_t index, mm_u8 **data_out, size_t *size_out);

struct mm_spiflash;
struct mm_spiflash *mm_spiflash_get_for_bus(int bus);
mm_u8 mm_spiflash_xfer(struct mm_spiflash *flash, mm_u8 out);
void mm_spiflash_cs_deassert(struct mm_spiflash *flash);
void mm_spiflash_set_cs(struct mm_spiflash *flash, mm_u8 level);
mm_bool mm_spiflash_is_locked(const struct mm_spiflash *flash);

/*
 * Optional decrypt hook for OTFDEC / XIP decryption.
 * When registered, spiflash_mmio_read calls fn(opaque, byte_addr, block16)
 * for each 16-byte aligned block before serving bytes.  fn must:
 *   - fill block16[0..15] with decrypted bytes if the address is covered
 *     by an enabled region, returning MM_TRUE.
 *   - return MM_FALSE if the address is not covered (raw bytes are served).
 * Only one hook may be registered at a time (last write wins).
 */
typedef mm_bool (*mm_spiflash_decrypt_fn)(void *opaque, mm_u32 addr,
                                          mm_u8 *block16);
mm_bool mm_spiflash_set_decrypt_hook(mm_spiflash_decrypt_fn fn, void *opaque);

#endif /* M33MU_SPIFLASH_H */
