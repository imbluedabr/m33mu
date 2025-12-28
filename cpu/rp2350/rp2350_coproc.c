/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include <string.h>
#include <math.h>
#include <limits.h>
#include "rp2350/rp2350_coproc.h"
#include "rp2350/rp2350_mmio.h"

enum dcp_conv_src {
    DCP_CONV_NONE = 0,
    DCP_CONV_INT,
    DCP_CONV_UINT,
    DCP_CONV_FLOAT,
    DCP_CONV_DOUBLE
};

struct rp2350_dcp_state {
    mm_u64 raw_xm;
    mm_u64 raw_ym;
    mm_u64 raw_ef;
    mm_u64 x_d_bits;
    mm_u64 y_d_bits;
    mm_u32 x_f_bits;
    mm_u32 y_f_bits;
    mm_u64 conv_d_bits;
    mm_u32 conv_f_bits;
    mm_u32 conv_u;
    mm_i32 conv_i;
    mm_u8 conv_src;
    mm_u8 round_mode;
    mm_u8 cmp_mode;
};

static struct rp2350_dcp_state dcp_state;

static double u64_to_double(mm_u64 v)
{
    double out;
    memcpy(&out, &v, sizeof(out));
    return out;
}

static mm_u64 double_to_u64(double v)
{
    mm_u64 out;
    memcpy(&out, &v, sizeof(out));
    return out;
}

static float u32_to_float(mm_u32 v)
{
    float out;
    memcpy(&out, &v, sizeof(out));
    return out;
}

static mm_u32 float_to_u32(float v)
{
    mm_u32 out;
    memcpy(&out, &v, sizeof(out));
    return out;
}

static mm_u32 dcp_round_float_to_u32(float v, mm_bool round_nearest, mm_bool signed_out)
{
    double dv = (double)v;
    double out = round_nearest ? nearbyint(dv) : trunc(dv);
    if (isnan(out)) return 0u;
    if (signed_out) {
        if (out > (double)INT32_MAX) return (mm_u32)INT32_MAX;
        if (out < (double)INT32_MIN) return (mm_u32)INT32_MIN;
        return (mm_u32)(mm_i32)out;
    }
    if (out < 0.0) return 0u;
    if (out > (double)UINT32_MAX) return 0xffffffffu;
    return (mm_u32)(mm_u64)out;
}

static mm_u32 dcp_round_double_to_u32(double v, mm_bool round_nearest, mm_bool signed_out)
{
    double out = round_nearest ? nearbyint(v) : trunc(v);
    if (isnan(out)) return 0u;
    if (signed_out) {
        if (out > (double)INT32_MAX) return (mm_u32)INT32_MAX;
        if (out < (double)INT32_MIN) return (mm_u32)INT32_MIN;
        return (mm_u32)(mm_i32)out;
    }
    if (out < 0.0) return 0u;
    if (out > (double)UINT32_MAX) return 0xffffffffu;
    return (mm_u32)(mm_u64)out;
}

static mm_u32 dcp_cmp_flags_double(double a, double b)
{
    mm_u32 flags = 0u;
    if (isnan(a) || isnan(b)) {
        flags |= (1u << 29); /* C */
        flags |= (1u << 28); /* V */
        return flags;
    }
    if (a == b) {
        flags |= (1u << 30); /* Z */
        flags |= (1u << 29); /* C */
        return flags;
    }
    if (a < b) {
        flags |= (1u << 31); /* N */
        return flags;
    }
    flags |= (1u << 29); /* C */
    return flags;
}

static mm_u32 dcp_cmp_flags_float(float a, float b)
{
    return dcp_cmp_flags_double((double)a, (double)b);
}

void mm_rp2350_coproc_reset(void)
{
    memset(&dcp_state, 0, sizeof(dcp_state));
}

mm_bool mm_rp2350_dcp_mcrr(mm_u8 op1, mm_u8 crm, mm_u32 lo, mm_u32 hi)
{
    if (!mm_rp2350_active()) {
        return MM_FALSE;
    }
    switch (op1) {
    case 0u:
        if (crm == 0u) dcp_state.raw_xm = ((mm_u64)hi << 32) | lo;
        if (crm == 1u) dcp_state.raw_ym = ((mm_u64)hi << 32) | lo;
        if (crm == 2u) dcp_state.raw_ef = ((mm_u64)hi << 32) | lo;
        break;
    case 1u:
        if (crm == 0u) {
            dcp_state.x_d_bits = ((mm_u64)hi << 32) | lo;
            dcp_state.cmp_mode = 2u;
        }
        if (crm == 1u) {
            dcp_state.y_d_bits = ((mm_u64)hi << 32) | lo;
            dcp_state.cmp_mode = 2u;
        }
        if (crm == 2u) {
            dcp_state.x_f_bits = lo;
            dcp_state.y_f_bits = hi;
            dcp_state.cmp_mode = 1u;
        }
        break;
    case 6u:
        if (crm == 0u) {
            dcp_state.conv_u = lo;
            dcp_state.conv_src = DCP_CONV_UINT;
        }
        break;
    case 7u:
        if (crm == 0u) {
            dcp_state.conv_i = (mm_i32)lo;
            dcp_state.conv_src = DCP_CONV_INT;
        }
        break;
    case 8u:
        if (crm == 0u) {
            dcp_state.conv_d_bits = ((mm_u64)hi << 32) | lo;
            dcp_state.conv_src = DCP_CONV_DOUBLE;
        }
        break;
    case 9u:
        if (crm == 2u) {
            dcp_state.conv_f_bits = lo;
            dcp_state.conv_src = DCP_CONV_FLOAT;
        }
        break;
    default:
        break;
    }
    return MM_TRUE;
}

mm_bool mm_rp2350_dcp_mrrc(mm_u8 op1, mm_u8 crm, mm_u32 *lo_out, mm_u32 *hi_out)
{
    if (!mm_rp2350_active() || lo_out == 0 || hi_out == 0) {
        return MM_FALSE;
    }
    if (op1 == 0u) {
        mm_u64 v = 0u;
        if (crm == 8u) v = dcp_state.raw_xm;
        else if (crm == 9u) v = dcp_state.raw_ym;
        else if (crm == 10u) v = dcp_state.raw_ef;
        *lo_out = (mm_u32)(v & 0xffffffffu);
        *hi_out = (mm_u32)(v >> 32);
        return MM_TRUE;
    }
    if (crm == 0u) {
        double xd = u64_to_double(dcp_state.x_d_bits);
        double yd = u64_to_double(dcp_state.y_d_bits);
        double res = 0.0;
        switch (op1) {
        case 1u: res = xd + yd; break;
        case 3u:
            if (dcp_state.conv_src == DCP_CONV_INT) res = (double)dcp_state.conv_i;
            else if (dcp_state.conv_src == DCP_CONV_UINT) res = (double)dcp_state.conv_u;
            else res = xd - yd;
            break;
        case 5u: res = xd * yd; break;
        case 7u: res = xd / yd; break;
        case 9u: res = sqrt(xd); break;
        case 11u: res = (double)u32_to_float(dcp_state.x_f_bits); break;
        default: res = 0.0; break;
        }
        {
            mm_u64 v = double_to_u64(res);
            *lo_out = (mm_u32)(v & 0xffffffffu);
            *hi_out = (mm_u32)(v >> 32);
        }
        dcp_state.conv_src = DCP_CONV_NONE;
        return MM_TRUE;
    }
    *lo_out = 0u;
    *hi_out = 0u;
    return MM_TRUE;
}

mm_bool mm_rp2350_dcp_mrc(mm_u8 op1, mm_u8 crn, mm_u8 crm, mm_u8 op2, mm_bool peek, mm_u32 *value_out)
{
    float xf;
    float yf;
    double xd;
    double yd;
    mm_u32 out = 0u;
    if (!mm_rp2350_active() || value_out == 0) {
        return MM_FALSE;
    }
    if (op1 != 0u || (crn & 0x0fu) != 0u) {
        return MM_FALSE;
    }
    xf = u32_to_float(dcp_state.x_f_bits);
    yf = u32_to_float(dcp_state.y_f_bits);
    xd = u64_to_double(dcp_state.x_d_bits);
    yd = u64_to_double(dcp_state.y_d_bits);
    if (crm == 0u && op2 == 0u) {
        out = 0u;
    } else if (crm == 0u && op2 == 1u) {
        if (peek) {
            out = 0u;
        } else {
            if (dcp_state.cmp_mode == 2u) {
                out = dcp_cmp_flags_double(xd, yd);
            } else {
                out = dcp_cmp_flags_float(xf, yf);
            }
        }
    } else if (crm == 2u) {
        float fres = 0.0f;
        switch (op2) {
        case 0u: fres = xf + yf; break;
        case 1u:
            if (dcp_state.conv_src == DCP_CONV_INT) fres = (float)dcp_state.conv_i;
            else if (dcp_state.conv_src == DCP_CONV_UINT) fres = (float)dcp_state.conv_u;
            else fres = xf - yf;
            break;
        case 2u: fres = xf * yf; break;
        case 3u: fres = xf / yf; break;
        case 4u: fres = sqrtf(xf); break;
        case 5u: fres = (float)u64_to_double(dcp_state.x_d_bits); break;
        default: fres = 0.0f; break;
        }
        out = float_to_u32(fres);
        dcp_state.conv_src = DCP_CONV_NONE;
    } else if (crm == 3u) {
        mm_bool round_nearest = (dcp_state.round_mode != 0u);
        if (op2 == 0u) {
            if (dcp_state.conv_src == DCP_CONV_DOUBLE) {
                out = dcp_round_double_to_u32(u64_to_double(dcp_state.conv_d_bits), round_nearest, MM_TRUE);
            } else {
                out = dcp_round_float_to_u32(u32_to_float(dcp_state.conv_f_bits), round_nearest, MM_TRUE);
            }
        } else if (op2 == 1u) {
            if (dcp_state.conv_src == DCP_CONV_DOUBLE) {
                out = dcp_round_double_to_u32(u64_to_double(dcp_state.conv_d_bits), round_nearest, MM_FALSE);
            } else {
                out = dcp_round_float_to_u32(u32_to_float(dcp_state.conv_f_bits), round_nearest, MM_FALSE);
            }
        }
        dcp_state.conv_src = DCP_CONV_NONE;
    }
    *value_out = out;
    return MM_TRUE;
}

mm_bool mm_rp2350_dcp_cdp(mm_u8 op1, mm_u8 op2, mm_u8 crd, mm_u8 crn, mm_u8 crm)
{
    (void)crd;
    (void)crn;
    (void)crm;
    if (!mm_rp2350_active()) {
        return MM_FALSE;
    }
    if (op1 == 8u && crn == 0u && crm == 0u) {
        if (op2 == 2u) dcp_state.round_mode = 0u;
        if (op2 == 3u) dcp_state.round_mode = 1u;
    }
    return MM_TRUE;
}
