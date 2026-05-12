/* m33mu -- an ARMv8-M Emulator
 *
 * Copyright (C) 2025  Daniele Lacamera <root@danielinux.net>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * STM32 OTFDEC (On-The-Fly Decryption) peripheral model.
 * Shared across STM32H5 (H533, H563) and STM32U585.
 * OTFDEC NS base: 0x420C5000  S base: 0x520C5000  size: 0x400
 */

#ifndef M33MU_OTFDEC_H
#define M33MU_OTFDEC_H

#include "m33mu/types.h"

struct mm_otfdec; /* opaque */

struct mm_otfdec *mm_otfdec_new(void);
void mm_otfdec_reset(struct mm_otfdec *od);
void mm_otfdec_free(struct mm_otfdec *od);

mm_bool mm_otfdec_read(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                       mm_u32 *value_out);
mm_bool mm_otfdec_write(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                        mm_u32 value);

/*
 * Spiflash decrypt hook.
 * Called by the spiflash mmap read path for each 16-byte aligned block.
 *   opaque  -- pointer to struct mm_otfdec
 *   addr    -- absolute (mmap) byte address of the block (aligned to 16)
 *   block16 -- on entry: 16 raw (ciphertext) bytes from flash;
 *              on exit : 16 plaintext bytes (if decryption was applied)
 * Returns MM_TRUE if a region matched and block16 was decrypted.
 * Returns MM_FALSE if no region covers addr (caller serves raw bytes).
 */
mm_bool mm_otfdec_decrypt_block(void *opaque, mm_u32 addr, mm_u8 *block16);

#endif /* M33MU_OTFDEC_H */
