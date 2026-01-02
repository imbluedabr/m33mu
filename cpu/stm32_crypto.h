#ifndef M33MU_STM32_CRYPTO_H
#define M33MU_STM32_CRYPTO_H

#include "m33mu/types.h"

mm_bool hash_read(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                  mm_u32 *value_out);
mm_bool hash_write(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                   mm_u32 value);
mm_bool aes_read(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                 mm_u32 *value_out);
mm_bool aes_write(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                  mm_u32 value);
mm_bool pka_read(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                 mm_u32 *value_out);
mm_bool pka_write(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                  mm_u32 value);

#endif /* M33MU_STM32_CRYPTO_H */
