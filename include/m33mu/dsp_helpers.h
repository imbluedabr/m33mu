/* m33mu -- an ARMv8-M Emulator
 *
 * Copyright (C) 2025  Daniele Lacamera <root@danielinux.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 */

#ifndef M33MU_DSP_HELPERS_H
#define M33MU_DSP_HELPERS_H

#include "m33mu/types.h"

/* Saturate a signed 64-bit value to N-bit signed range.
 * If saturation occurs, set *q_flag to MM_TRUE.
 * Returns saturated value as 32-bit signed.
 */
static inline mm_i32 mm_sat_s32(mm_i64 val, mm_u32 n, mm_bool *q_flag)
{
    mm_i64 max = (1LL << (n - 1)) - 1;
    mm_i64 min = -(1LL << (n - 1));
    
    if (val > max) {
        *q_flag = MM_TRUE;
        return (mm_i32)max;
    }
    if (val < min) {
        *q_flag = MM_TRUE;
        return (mm_i32)min;
    }
    return (mm_i32)val;
}

/* Saturate a signed 64-bit value to N-bit unsigned range.
 * If saturation occurs, set *q_flag to MM_TRUE.
 * Returns saturated value as 32-bit unsigned.
 */
static inline mm_u32 mm_sat_u32(mm_i64 val, mm_u32 n, mm_bool *q_flag)
{
    mm_i64 max = (1LL << n) - 1;
    
    if (val > max) {
        *q_flag = MM_TRUE;
        return (mm_u32)max;
    }
    if (val < 0) {
        *q_flag = MM_TRUE;
        return 0;
    }
    return (mm_u32)val;
}

/* Saturating 32-bit signed add: Rd = sat(Rn + Rm) */
static inline mm_u32 mm_qadd(mm_u32 rn, mm_u32 rm, mm_bool *q_flag)
{
    mm_i64 a = (mm_i32)rn;
    mm_i64 b = (mm_i32)rm;
    mm_i64 result = a + b;
    return (mm_u32)mm_sat_s32(result, 32, q_flag);
}

/* Saturating 32-bit signed subtract: Rd = sat(Rn - Rm) */
static inline mm_u32 mm_qsub(mm_u32 rn, mm_u32 rm, mm_bool *q_flag)
{
    mm_i64 a = (mm_i32)rn;
    mm_i64 b = (mm_i32)rm;
    mm_i64 result = a - b;
    return (mm_u32)mm_sat_s32(result, 32, q_flag);
}

/* Saturating double and add: Rd = sat(Rn + sat(Rm * 2)) */
static inline mm_u32 mm_qdadd(mm_u32 rn, mm_u32 rm, mm_bool *q_flag)
{
    mm_i64 m = (mm_i32)rm;
    mm_i64 doubled = m * 2;
    mm_i32 sat_doubled = mm_sat_s32(doubled, 32, q_flag);
    
    mm_i64 a = (mm_i32)rn;
    mm_i64 result = a + sat_doubled;
    return (mm_u32)mm_sat_s32(result, 32, q_flag);
}

/* Saturating double and subtract: Rd = sat(Rn - sat(Rm * 2)) */
static inline mm_u32 mm_qdsub(mm_u32 rn, mm_u32 rm, mm_bool *q_flag)
{
    mm_i64 m = (mm_i32)rm;
    mm_i64 doubled = m * 2;
    mm_i32 sat_doubled = mm_sat_s32(doubled, 32, q_flag);
    
    mm_i64 a = (mm_i32)rn;
    mm_i64 result = a - sat_doubled;
    return (mm_u32)mm_sat_s32(result, 32, q_flag);
}

/* --- Byte/halfword saturation primitives (used by Q*, SSAT16, USAT16) ----- */

static inline mm_i8 mm_sat_s8_simple(mm_i32 v)
{
    if (v > 127) return 127;
    if (v < -128) return -128;
    return (mm_i8)v;
}

static inline mm_u8 mm_sat_u8_simple(mm_i32 v)
{
    if (v > 255) return 255;
    if (v < 0) return 0;
    return (mm_u8)v;
}

static inline mm_i16 mm_sat_s16_simple(mm_i32 v)
{
    if (v > 32767) return 32767;
    if (v < -32768) return -32768;
    return (mm_i16)v;
}

static inline mm_u16 mm_sat_u16_simple(mm_i32 v)
{
    if (v > 65535) return 65535;
    if (v < 0) return 0;
    return (mm_u16)v;
}

/* --- Lane extractors ------------------------------------------------------ */

static inline mm_i8 mm_lane_s8(mm_u32 w, int i) { return (mm_i8)((w >> (i * 8)) & 0xffu); }
static inline mm_u8 mm_lane_u8(mm_u32 w, int i) { return (mm_u8)((w >> (i * 8)) & 0xffu); }
static inline mm_i16 mm_lane_s16(mm_u32 w, int i) { return (mm_i16)((w >> (i * 16)) & 0xffffu); }
static inline mm_u16 mm_lane_u16(mm_u32 w, int i) { return (mm_u16)((w >> (i * 16)) & 0xffffu); }

/* Pack 4 byte lanes into a word. */
static inline mm_u32 mm_pack_bytes(mm_u8 b0, mm_u8 b1, mm_u8 b2, mm_u8 b3)
{
    return ((mm_u32)b0) | ((mm_u32)b1 << 8) | ((mm_u32)b2 << 16) | ((mm_u32)b3 << 24);
}

/* Pack 2 halfword lanes into a word. */
static inline mm_u32 mm_pack_halves(mm_u16 h0, mm_u16 h1)
{
    return ((mm_u32)h0) | ((mm_u32)h1 << 16);
}

#endif /* M33MU_DSP_HELPERS_H */
