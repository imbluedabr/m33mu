/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef M33MU_RW612_SECURE_H
#define M33MU_RW612_SECURE_H

#include "m33mu/types.h"

struct mmio_bus;

/*
 * RW612 secure subsystem stubs.
 *   ELS  EdgeLock Secure Subsystem  – AES, SHA-256, HMAC, RNG, ECDSA-P256
 *   PKA  Public Key Accelerator     – ModExp + (small subset of) ECC
 *
 * Crypto operations are dispatched to wolfcrypt when M33MU_HAS_WOLFSSL is
 * defined; otherwise a deterministic fallback is used so tests still link.
 */

void mm_rw612_secure_reset(void);
mm_bool mm_rw612_secure_register_mmio(struct mmio_bus *bus);
void mm_rw612_secure_rng_fill(mm_u8 *out, mm_u32 len);

#endif /* M33MU_RW612_SECURE_H */
